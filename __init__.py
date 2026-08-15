"""
SSH Pilot Plugin: VNC Protocol Backend
"""

from __future__ import annotations

import functools
import logging
import os
import shutil
import subprocess
import tempfile
import atexit
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sshpilot.plugins.api import (
    FieldSpec,
    PluginContext,
    ProtocolBackend,
    ProtocolError,
    SpawnSpec,
    SshPilotPlugin,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Client definitions
# ---------------------------------------------------------------------------

KNOWN_CLIENTS: dict[str, dict] = {
    "tigervnc": {
        "binaries": ["vncviewer", "xtigervncviewer"],
        "version_markers": ["TigerVNC"],
        "version_flags": ["-version", "--version"],
        "preferred": True,
    },
    "turbovnc": {
        "binaries": ["vncviewer", "tvncviewer"],
        "version_markers": ["TurboVNC"],
        "version_flags": ["-version", "--version"],
        "preferred": True,
    },
    "tightvnc": {
        "binaries": ["vncviewer", "xtightvncviewer"],
        "version_markers": ["TightVNC"],
        "version_flags": ["-version", "--version", "-help"],
        "preferred": False,
    },
    "realvnc": {
        "binaries": ["vncviewer"],
        "version_markers": ["RealVNC"],
        "version_flags": ["-version", "--version"],
        "preferred": False,
    },
    "remmina": {
        "binaries": ["remmina"],
        "version_markers": ["Remmina"],
        "version_flags": ["--version"],
        "preferred": False,
    },
    "krdc": {
        "binaries": ["krdc"],
        "version_markers": ["krdc"],
        "version_flags": ["--version"],
        "preferred": False,
    },
    "vinagre": {
        "binaries": ["vinagre"],
        "version_markers": ["vinagre"],
        "version_flags": ["--version", "-v"],
        "preferred": False,
    },
    "gvncviewer": {
        "binaries": ["gvncviewer"],
        "version_markers": ["gvncviewer"],
        "version_flags": ["--version"],
        "preferred": False,
    },
}

# Ordered by preference for auto-detection
_CLIENT_ORDER = [
    "tigervnc", "turbovnc", "tightvnc", "realvnc",
    "remmina", "krdc", "vinagre", "gvncviewer",
]

# ---------------------------------------------------------------------------
# Field choices (immutable)
# ---------------------------------------------------------------------------

_QUALITY = (
    ("", "Auto"),
    ("0", "0 - Lowest / smallest"),
    ("1", "1"),
    ("2", "2"),
    ("3", "3"),
    ("4", "4"),
    ("5", "5 - Medium"),
    ("6", "6"),
    ("7", "7"),
    ("8", "8"),
    ("9", "9 - Highest / largest"),
)

_COMPRESS = (
    ("", "Auto"),
    ("0", "0 - No compression"),
    ("1", "1"),
    ("2", "2"),
    ("3", "3"),
    ("4", "4"),
    ("5", "5 - Medium"),
    ("6", "6"),
    ("7", "7"),
    ("8", "8"),
    ("9", "9 - Maximum"),
)

_ENCODING = (
    ("", "Auto"),
    ("Tight", "Tight"),
    ("ZRLE", "ZRLE"),
    ("Hextile", "Hextile"),
    ("Raw", "Raw"),
    ("CoRRE", "CoRRE"),
    ("Raw", "Raw"),
)

_COLOR_DEPTH = (
    ("", "Auto"),
    ("8", "8-bit (256 colors)"),
    ("16", "16-bit (65K colors)"),
    ("24", "24-bit (16M colors)"),
    ("32", "32-bit (16M+ colors)"),
)

# ---------------------------------------------------------------------------
# Helpers (adapted from rdp-pilot)
# ---------------------------------------------------------------------------


def _parse_port(value: Any, default: int = 5900) -> int | None:
    """Strictly parse a port value.

    Returns ``default`` when unset, ``None`` for anything that is not a valid
    port number. Never silently coerces bools, floats or junk strings.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 65536 else None
    if isinstance(value, str):
        digits = value.strip()
        if not digits:
            return default
        if digits.isdigit():
            parsed = int(digits)
            if 0 < parsed < 65536:
                return parsed
    return None


def _split_host_port(host: str) -> tuple[str, int | None]:
    """Split an optional ``:port`` suffix off a host, IPv6-aware."""
    host = (host or "").strip()
    if not host:
        return host, None
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            inner = host[1:end]
            rest = host[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return inner, int(rest[1:])
            return inner, None
    if host.count(":") == 1:
        head, _, tail = host.partition(":")
        if tail.isdigit():
            return head, int(tail)
    return host, None


def _format_host(host: str) -> str:
    """Return the host ready for use, wrapping IPv6 literals in brackets."""
    if host.startswith("["):
        return host
    if host.count(":") >= 2:
        return f"[{host}]"
    return host


def _get_host(data: dict, connection: Any = None) -> str:
    """Resolve the connection host from plugin data or the connection object."""
    host = data.get("host") or data.get("hostname") or ""
    if host:
        return str(host)
    if connection is not None:
        return str(getattr(connection, "hostname", "") or getattr(connection, "host", "") or "")
    return ""


def _flatpak_prefix() -> tuple[str, ...]:
    """Return flatpak-spawn prefix if running inside a Flatpak sandbox."""
    if os.path.exists("/.flatpak-info"):
        flatpak = shutil.which("flatpak-spawn")
        if flatpak:
            return (flatpak, "--host")
        return ("flatpak-spawn", "--host")
    return ()


# ---------------------------------------------------------------------------
# VNC client discovery
# ---------------------------------------------------------------------------


@dataclass
class VncClientInfo:
    """A discovered VNC client: its id, resolved binary path, and display name."""
    client_id: str
    binary: str
    display_name: str
    argv_prefix: tuple[str, ...]


def _run_version_command(path: str, flags: list[str]) -> str:
    """Run the binary with version flags and return stdout+stderr text."""
    for flag in flags:
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=2,
            )
            output = (result.stdout or "") + (result.stderr or "")
            if output.strip():
                return output
        except (subprocess.TimeoutExpired, OSError):
            continue
    return ""


@functools.lru_cache(maxsize=8)
def _discover_vnc_clients() -> tuple[VncClientInfo, ...]:
    """Discover installed VNC clients by scanning PATH and matching version output.

    Resolution order:
    1. ``VNC_PILOT_BIN`` env override — user-specified binary, client set to 'custom'.
    2. ``VNC_PILOT_CLIENT`` env override — force a specific known client by id.
    3. Auto-scan: for each known client, check all its candidate binaries via
       ``shutil.which`` and fingerprint with ``--version``/``-version``.
    """
    flatpak = _flatpak_prefix()
    results: list[VncClientInfo] = []

    override_bin = os.environ.get("VNC_PILOT_BIN", "").strip()
    override_client = os.environ.get("VNC_PILOT_CLIENT", "").strip()

    if override_bin:
        results.append(VncClientInfo(
            client_id="custom" if not override_client else override_client,
            binary=override_bin,
            display_name=os.path.basename(override_bin) or "custom",
            argv_prefix=flatpak + (override_bin,),
        ))
        return tuple(results)

    # Scan for each known client
    for client_id in _CLIENT_ORDER:
        spec = KNOWN_CLIENTS[client_id]
        for binary_name in spec["binaries"]:
            path = shutil.which(binary_name)
            if path is None:
                continue
            # Fingerprint: run version and check markers
            version_output = _run_version_command(path, spec["version_flags"])
            matched = False
            if version_output:
                for marker in spec["version_markers"]:
                    if marker.lower() in version_output.lower():
                        matched = True
                        break
            else:
                # If we can't get version output, accept the binary as a fallback
                # (e.g., remmina --version may not output "Remmina" on some builds)
                matched = True
            if matched:
                display = client_id.capitalize() if client_id != "realvnc" else "RealVNC"
                if client_id == "tightvnc":
                    display = "TightVNC"
                if client_id == "turbovnc":
                    display = "TurboVNC"
                if client_id == "tigervnc":
                    display = "TigerVNC"
                if client_id == "gvncviewer":
                    display = "gvncviewer (gtk-vnc)"
                if client_id == "krdc":
                    display = "KRDC (KDE)"
                if client_id == "vinagre":
                    display = "Vinagre (GNOME)"
                results.append(VncClientInfo(
                    client_id=client_id,
                    binary=path,
                    display_name=display,
                    argv_prefix=flatpak + (path,),
                ))
                # Don't break for the same client_id — first match wins per client
                break

    if override_client and not any(c.client_id == override_client for c in results):
        logger.warning(
            "VNC_PILOT_CLIENT set to '%s' but that client was not found on PATH",
            override_client,
        )

    return tuple(results)


def _resolve_client(
    data: dict, ctx: PluginContext
) -> VncClientInfo:
    """Pick the VNC client to use for a connection.

    Preference: explicit selection in data > VNC_PILOT_CLIENT > first discovered.
    """
    selected = data.get("vnc_client") or ""
    discovered = _discover_vnc_clients()

    if selected:
        for c in discovered:
            if c.client_id == selected:
                return c
        # User selected a client not in our discovered list; check env override path
        if selected == "custom":
            bin_path = os.environ.get("VNC_PILOT_BIN", "").strip()
            if bin_path:
                flatpak = _flatpak_prefix()
                return VncClientInfo(
                    client_id="custom",
                    binary=bin_path,
                    display_name=os.path.basename(bin_path) or "custom",
                    argv_prefix=flatpak + (bin_path,),
                )
        raise ProtocolError(
            f"VNC client '{selected}' is selected but not found on this system. "
            "Install it or choose a different client, or unset VNC_PILOT_BIN."
        )

    if discovered:
        # Prefer preferred clients, then fall back to first found
        preferred = [c for c in discovered if c.client_id in ("tigervnc", "turbovnc")]
        if preferred:
            return preferred[0]
        return discovered[0]

    raise ProtocolError(
        "No VNC client found on PATH. Install one of: "
        "TigerVNC, TurboVNC, TightVNC, RealVNC, Remmina, KRDC, Vinagre, or gvncviewer. "
        "Alternatively, set VNC_PILOT_BIN to point at a custom binary."
    )


# ---------------------------------------------------------------------------
# Password handling
# ---------------------------------------------------------------------------


def _secret_key(connection: Any) -> str:
    return f"vnc_password_{connection.nickname}"


def _resolve_password(connection: Any, data: dict, ctx: PluginContext) -> str:
    """Password from the SSH Pilot keyring (primary storage).

    Legacy plaintext passwords previously stored in ``connection.data``
    under the ``credential`` key are migrated into the keyring on first
    use and removed from the config, so the password is never persisted
    in the connection data.
    """
    secret_key = _secret_key(connection)
    try:
        stored = ctx.secrets.get(secret_key) or ""
    except Exception:
        logger.exception("Failed to read password from the SSH Pilot keyring")
        stored = ""
    if stored:
        return stored
    legacy = data.get("credential") or ""
    if not legacy:
        return ""
    try:
        ctx.secrets.set(secret_key, legacy)
    except Exception:
        logger.exception(
            "Failed to store the password in the SSH Pilot keyring; "
            "keeping the legacy value in the connection config")
        return legacy
    data.pop("credential", None)
    return legacy


def _create_passwd_file(password: str) -> Optional[str]:
    """Create a temporary VNC password file.

    Writes the password to a temp file with mode 0o600. The file is
    removed via atexit. Some VNC viewers accept plain-text passwords in
    the passwd file; for viewers that require the VNC-encrypted format,
    we attempt to use ``vncpasswd -f`` if it is on PATH; otherwise the
    plain text file is passed and the viewer handles (or prompts for)
    the password.
    """
    if not password:
        return None

    fd, path = tempfile.mkstemp(prefix="vnc-pass-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(password)
        os.chmod(path, 0o600)
    except OSError:
        return None

    # Try to convert to proper VNC passwd format using vncpasswd
    vncpasswd = shutil.which("vncpasswd")
    if vncpasswd:
        try:
            result = subprocess.run(
                [vncpasswd, "-f"],
                input=password,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stdout:
                with open(path, "wb") as f:
                    f.write(result.stdout.encode())
        except (subprocess.TimeoutExpired, OSError, ValueError):
            # If conversion fails, the plain-text file is our fallback
            pass

    atexit.register(lambda: _safe_remove(path))
    return path


def _safe_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


def _resolve_target(data: dict, host: str) -> str:
    """Build the VNC target string (host:display or host::port).

    VNC display numbering: display N maps to port 5900+N. If an explicit
    port is given, use ``host::port``. If a display number is given,
    use ``host:display``.
    """
    display = data.get("display")
    if display is not None:
        try:
            d = int(display)
            if d >= 0:
                return f"{_format_host(host)}:{d}"
        except (TypeError, ValueError):
            pass

    port = _parse_port(data.get("port"), 5900)
    if port is None:
        port = 5900

    embedded_port = None
    bare_host = host
    if ":" in host and not host.startswith("["):
        bare_host, embedded_port = _split_host_port(host)
    if embedded_port:
        return f"{_format_host(bare_host)}::{embedded_port}"

    return f"{_format_host(host)}::{port}"


# ---------------------------------------------------------------------------
# Per-client argv builders
# ---------------------------------------------------------------------------


def _build_tiger_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for TigerVNC / TurboVNC (compatible CLIs).

    Both use ``-flag value`` or ``-flag`` boolean style. Key flags:
    -FullScreen, -ViewOnly, -Shared, -PreferredEncoding, -QualityLevel,
    -CompressLevel, -geometry, -passwd, -via
    """
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-ViewOnly")
    if data.get("fullscreen"):
        argv.append("-FullScreen")
    if data.get("shared", True):  # shared is on by default in VNC
        argv.append("-Shared")
    else:
        argv.append("-NOShared")

    encoding = data.get("encoding", "")
    if encoding:
        argv.append(f"-PreferredEncoding")
        argv.append(encoding)

    quality = data.get("quality", "")
    if quality:
        argv.append(f"-QualityLevel")
        argv.append(quality)

    compress = data.get("compress", "")
    if compress:
        argv.append(f"-CompressLevel")
        argv.append(compress)

    color_depth = data.get("color_depth", "")
    if color_depth:
        argv.append(f"-colorDepth")
        argv.append(color_depth)

    geometry = data.get("tigervnc_geometry") or data.get("turbovnc_geometry")
    if geometry:
        argv.append(f"-geometry")
        argv.append(geometry)

    via = data.get("tigervnc_via") or data.get("turbovnc_via")
    if via:
        argv.append(f"-via")
        argv.append(via)

    if not data.get("tigervnc_accept_clipboard", True):
        argv.append("-AcceptClipboard")
        argv.append("0")
    if not data.get("tigervnc_send_clipboard", True):
        argv.append("-SendClipboard")
        argv.append("0")

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)

    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-passwd")
            argv.append(passwd_file)

    return argv, env


def _build_tightvnc_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for TightVNC.

    TightVNC shares many flags with TigerVNC but uses slightly different
    flag names in some cases.
    """
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-viewonly")
    if data.get("fullscreen"):
        argv.append("-fullscreen")
    if data.get("shared", True):
        argv.append("-shared")
    else:
        argv.append("-noshared")

    encoding = data.get("encoding", "")
    if encoding:
        argv.append(f"-encodings")
        argv.append(encoding)

    quality = data.get("quality", "")
    if quality:
        argv.append(f"-quality")
        argv.append(quality)

    compress = data.get("compress", "")
    if compress:
        argv.append(f"-compresslevel")
        argv.append(compress)

    color_depth = data.get("color_depth", "")
    if color_depth:
        argv.append(f"-bcolors")
        argv.append(color_depth)

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)

    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-passwd")
            argv.append(passwd_file)

    return argv, env


def _build_realvnc_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for RealVNC.

    RealVNC uses similar flags to TigerVNC but some differ.
    """
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-ViewOnly")
    if data.get("fullscreen"):
        argv.append("-FullScreen")
    if data.get("shared", True):
        argv.append("-Shared")

    encoding = data.get("encoding", "")
    if encoding:
        argv.append(f"-PreferredEncoding")
        argv.append(encoding)

    quality = data.get("quality", "")
    if quality:
        argv.append(f"-QualityLevel")
        argv.append(quality)

    compress = data.get("compress", "")
    if compress:
        argv.append(f"-CompressLevel")
        argv.append(compress)

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)

    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-passwd")
            argv.append(passwd_file)

    return argv, env


def _build_remmina_argv(
    client: VncClientInfo,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for Remmina.

    Remmina is a GUI multi-protocol client. It can be launched with a
    VNC URI: ``remmina -c vnc://[user@]host:port``. Most settings live
    in a profile file; we generate a temporary .remmina file for full
    control.
    """
    host = _get_host(data)
    port = _parse_port(data.get("port"), 5900) or 5900
    display = data.get("display")
    if display is not None:
        try:
            d = int(display)
            if d >= 0:
                port = 5900 + d
        except (TypeError, ValueError):
            pass

    username = data.get("username") or ""

    # Build a .remmina profile file
    profile_content = "[remmina]\n"
    profile_content += "name=VNC Pilot\n"
    profile_content += "protocol=VNC\n"
    profile_content += f"server={_format_host(host)}\n"
    profile_content += f"port={port}\n"

    if username:
        profile_content += f"username={username}\n"
    if password:
        profile_content += f"password={password}\n"

    profile_content += "view_only=" + ("yes" if data.get("view_only") else "no") + "\n"
    profile_content += "fullscreen=" + ("yes" if data.get("fullscreen") else "no") + "\n"
    profile_content += "shared=" + ("yes" if data.get("shared", True) else "no") + "\n"

    quality = data.get("quality", "")
    if quality:
        profile_content += f"quality={quality}\n"

    # Write profile to a temp file
    fd, profile_path = tempfile.mkstemp(prefix="remmina-vnc-", suffix=".remmina")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(profile_content)
        os.chmod(profile_path, 0o600)
    except OSError:
        _safe_remove(profile_path)
        # Fall back to URI mode
        pass

    atexit.register(lambda: _safe_remove(profile_path))

    argv = list(client.argv_prefix)
    if profile_path and os.path.exists(profile_path):
        argv += ["--connect", profile_path]
    else:
        # URI fallback
        uri = "vnc://"
        if username:
            uri += f"{username}@"
        uri += f"{_format_host(host)}:{port}"
        argv += ["-c", uri]

    env = dict(os.environ)
    return argv, env


def _build_krdc_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for KRDC (KDE Remote Desktop Client)."""
    argv = list(client.argv_prefix)
    argv.append(f"vnc://{target}")

    if data.get("fullscreen"):
        argv.append("-f")

    # KRDC ignores most CLI args; settings come from profiles
    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)
    if password:
        env["VNC_PASSWORD"] = password

    return argv, env


def _build_vinagre_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for Vinagre (GNOME)."""
    # Vinagre uses vnc:// URIs
    host_part = target
    argv = list(client.argv_prefix)
    argv.append(f"vnc://{host_part}")

    if data.get("fullscreen"):
        argv.append("--fullscreen")

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)
    if password:
        env["VNC_PASSWORD"] = password

    return argv, env


def _build_gvncviewer_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for gvncviewer (gtk-vnc)."""
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-v")
    if data.get("fullscreen"):
        argv.append("-f")
    if data.get("shared", True):
        argv.append("-s")

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-p")
            argv.append(passwd_file)

    return argv, env


def _build_custom_argv(
    client: VncClientInfo,
    target: str,
    data: dict,
    password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for a user-specified custom VNC client.

    Just appends ``host:port`` (or ``host::port``), password via temp
    file (if the client is known to accept ``-passwd``), and raw
    ``extra_args`` from the user.
    """
    argv = list(client.argv_prefix)
    argv.append(target)

    extra = data.get("extra_args", "").strip()
    if extra:
        argv.extend(extra.split())

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-passwd")
            argv.append(passwd_file)

    return argv, env


# Dispatch table
_BUILDERS = {
    "tigervnc": _build_tiger_argv,
    "turbovnc": _build_tiger_argv,  # same CLI as TigerVNC
    "tightvnc": _build_tightvnc_argv,
    "realvnc": _build_realvnc_argv,
    "remmina": _build_remmina_argv,
    "krdc": _build_krdc_argv,
    "vinagre": _build_vinagre_argv,
    "gvncviewer": _build_gvncviewer_argv,
    "custom": _build_custom_argv,
}


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class VncBackend(ProtocolBackend):
    protocol_id = "vnc"
    display_name = "VNC"
    default_port = 5900

    def capabilities(self) -> frozenset:
        return frozenset()

    def connection_fields(self) -> List[FieldSpec]:
        fields: List[FieldSpec] = []

        # --- General ---
        fields.append(FieldSpec(
            key="host", label="IP / HOSTNAME", kind="text", required=True,
            placeholder="hostname or IP address"))
        fields.append(FieldSpec(
            key="port", label="Port", kind="int", default=5900,
            placeholder="5900"))
        fields.append(FieldSpec(
            key="display", label="Display", kind="int",
            placeholder="e.g. 1 (implies host:1 → port 5901)"))
        fields.append(FieldSpec(
            key="username", label="Username", kind="text",
            placeholder="username (optional for most VNC servers)"))
        fields.append(FieldSpec(
            key="credential", label="Password", kind="password",
            placeholder="password (stored in system keyring)"))

        # Build dynamic choices from discovered clients
        choices = self._vnc_client_choices()
        fields.append(FieldSpec(
            key="vnc_client", label="VNC Client", kind="choice",
            default=choices[0][0] if choices else "", choices=choices,
            placeholder="Select a VNC client"))

        # --- Display ---
        fields.append(FieldSpec(
            key="view_only", label="View only", kind="switch",
            default=False, group="Display"))
        fields.append(FieldSpec(
            key="fullscreen", label="Fullscreen", kind="switch",
            default=False, group="Display"))
        fields.append(FieldSpec(
            key="shared", label="Shared session", kind="switch",
            default=True, group="Display"))
        fields.append(FieldSpec(
            key="quality", label="Quality / JPEG level", kind="choice",
            default="", choices=_QUALITY, group="Display"))
        fields.append(FieldSpec(
            key="compress", label="Compression level", kind="choice",
            default="", choices=_COMPRESS, group="Display"))
        fields.append(FieldSpec(
            key="encoding", label="Preferred encoding", kind="choice",
            default="", choices=_ENCODING, group="Display"))
        fields.append(FieldSpec(
            key="color_depth", label="Color depth", kind="choice",
            default="", choices=_COLOR_DEPTH, group="Display"))
        fields.append(FieldSpec(
            key="extra_args", label="Extra CLI arguments", kind="text",
            placeholder="-via gateway.example.com (raw string, appended to argv)"))

        # --- TigerVNC / TurboVNC (shared CLI) ---
        fields.append(FieldSpec(
            key="tigervnc_geometry", label="Geometry", kind="text",
            placeholder="e.g. 1280x720", group="TigerVNC"))
        fields.append(FieldSpec(
            key="tigervnc_via", label="SSH tunnel via", kind="text",
            placeholder="e.g. user@gateway", group="TigerVNC"))
        fields.append(FieldSpec(
            key="tigervnc_accept_clipboard", label="Accept clipboard",
            kind="switch", default=True, group="TigerVNC"))
        fields.append(FieldSpec(
            key="tigervnc_send_clipboard", label="Send clipboard",
            kind="switch", default=True, group="TigerVNC"))

        # --- TurboVNC ---
        fields.append(FieldSpec(
            key="turbovnc_jpeg", label="Force JPEG compression",
            kind="switch", default=False, group="TurboVNC"))
        fields.append(FieldSpec(
            key="turbovnc_local", label="Local cursor feedback",
            kind="switch", default=True, group="TurboVNC"))

        # --- Remmina ---
        fields.append(FieldSpec(
            key="remmina_sftp", label="Enable SFTP",
            kind="switch", default=False, group="Remmina"))

        # --- Custom ---
        fields.append(FieldSpec(
            key="custom_binary", label="Custom binary path", kind="text",
            placeholder="/path/to/vncviewer", group="Custom"))

        return fields

    def _vnc_client_choices(self) -> list[tuple[str, str]]:
        """Build the vnc_client choice list from discovered clients.

        Falls back to 'auto' if no clients are found yet.
        """
        discovered = _discover_vnc_clients()
        choices: list[tuple[str, str]] = []
        for c in discovered:
            choices.append((c.client_id, c.display_name))
        if not choices:
            choices.append(("auto", "Auto-detect (no client found)"))
        else:
            choices.insert(0, ("auto", "Auto-detect"))
        return choices

    def validate(self, data: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not _get_host(data):
            errors.append("Host is required.")
        port = _parse_port(data.get("port"), self.default_port)
        if port is None:
            errors.append("Port must be an integer between 1 and 65535.")
        display = data.get("display")
        if display:
            try:
                d = int(display)
                if d < 0:
                    errors.append("Display number must be non-negative.")
            except (TypeError, ValueError):
                errors.append("Display must be a number.")
        return errors

    def build_spawn(self, connection: Any, ctx: PluginContext) -> SpawnSpec:
        data = getattr(connection, "data", None) or {}
        host = _get_host(data, connection)
        if not host:
            raise ProtocolError("No host configured for this connection.")

        client = _resolve_client(data, ctx)

        target = _resolve_target(data, host)
        password = _resolve_password(connection, data, ctx)

        builder = _BUILDERS.get(client.client_id, _build_custom_argv)
        if client.client_id == "remmina":
            argv, env = builder(client, data, password)
        else:
            argv, env = builder(client, target, data, password)

        return SpawnSpec(argv=argv, env=env)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class Plugin(SshPilotPlugin):
    _PATCHED = False

    def activate(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        ctx.register_protocol(VncBackend())
        self._patch_connection_dialog()

    def _patch_connection_dialog(self) -> None:
        if Plugin._PATCHED:
            return
        try:
            from sshpilot.connection_dialog import ConnectionDialog

            _orig_apply = ConnectionDialog._apply_protocol_to_ui

            def _patched_apply(self_obj):
                _orig_apply(self_obj)
                pid = (self_obj._selected_protocol_id()
                       if hasattr(self_obj, "_selected_protocol_id") else "ssh")
                if pid != "ssh":
                    for k in ("hostname", "username", "port"):
                        self_obj.validation_results.pop(k, None)
                    if hasattr(self_obj, "_update_save_buttons"):
                        self_obj._update_save_buttons()

            ConnectionDialog._apply_protocol_to_ui = _patched_apply

            _orig_validate = ConnectionDialog._run_initial_validation

            def _patched_validate(self_obj):
                try:
                    for field_name, attr_name in [
                        ("name", "nickname_row"),
                        ("hostname", "hostname_row"),
                        ("username", "username_row"),
                        ("port", "port_row"),
                    ]:
                        row = getattr(self_obj, attr_name, None)
                        if row is not None and row.get_visible():
                            self_obj._validate_field_row(field_name, row)
                    if hasattr(self_obj, "_update_save_buttons"):
                        self_obj._update_save_buttons()
                except Exception:
                    logger.exception(
                        "Failed to run initial connection dialog validation")

            ConnectionDialog._run_initial_validation = _patched_validate

            Plugin._PATCHED = True
        except Exception:
            logger.exception("Failed to patch ConnectionDialog")

    def deactivate(self) -> None:
        pass
