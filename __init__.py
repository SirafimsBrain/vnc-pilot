"""
SSH Pilot Plugin: VNC Protocol Backend
"""

from __future__ import annotations

import atexit
import functools
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time
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

# The VNC protocol's challenge/response authentication derives its DES key
# from the first 8 characters of the password; longer passwords are silently
# truncated by every client, so we mirror that behaviour consistently.
VNC_PASSWORD_MAX = 8

# How long a client-discovery result is considered fresh. Long enough that
# opening the connection dialog stays fast, short enough that a client
# installed while SSH Pilot is running is picked up on the next dialog open.
_DISCOVERY_TTL_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Client definitions
# ---------------------------------------------------------------------------

KNOWN_CLIENTS: dict[str, dict] = {
    "tigervnc": {
        "binaries": ["vncviewer", "xtigervncviewer"],
        "version_markers": ["TigerVNC"],
        "preferred": True,
    },
    "turbovnc": {
        "binaries": ["vncviewer", "tvncviewer"],
        "version_markers": ["TurboVNC"],
        "preferred": True,
    },
    "tightvnc": {
        "binaries": ["vncviewer", "xtightvncviewer"],
        "version_markers": ["TightVNC"],
        "preferred": False,
    },
    "realvnc": {
        "binaries": ["vncviewer"],
        "version_markers": ["RealVNC"],
        "preferred": False,
    },
    "remmina": {
        "binaries": ["remmina"],
        "version_markers": ["Remmina"],
        "preferred": False,
    },
    "krdc": {
        "binaries": ["krdc"],
        "version_markers": ["krdc"],
        "preferred": False,
    },
    "vinagre": {
        "binaries": ["vinagre"],
        "version_markers": ["vinagre"],
        "preferred": False,
    },
    "gvncviewer": {
        "binaries": ["gvncviewer"],
        "version_markers": ["gvncviewer"],
        "preferred": False,
    },
}

# Ordered by preference for auto-detection.
_CLIENT_ORDER = [
    "tigervnc", "turbovnc", "tightvnc", "realvnc",
    "remmina", "krdc", "vinagre", "gvncviewer",
]

# The plain ``vncviewer`` name is shared by TigerVNC, TurboVNC, TightVNC and
# RealVNC. A binary with this name MUST be identified by its version output;
# without it we refuse to guess, because the wrong client would receive the
# wrong flags.
_SHARED_BINARY_NAMES = frozenset({"vncviewer"})

_DISPLAY_NAMES = {
    "tigervnc": "TigerVNC",
    "turbovnc": "TurboVNC",
    "tightvnc": "TightVNC",
    "realvnc": "RealVNC",
    "remmina": "Remmina",
    "krdc": "KRDC (KDE)",
    "vinagre": "Vinagre (GNOME)",
    "gvncviewer": "gvncviewer (gtk-vnc)",
}

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
)

_COLOR_DEPTH = (
    ("", "Auto"),
    ("8", "8-bit (256 colors)"),
    ("16", "16-bit (65K colors)"),
    ("24", "24-bit (16M colors)"),
    ("32", "32-bit (16M+ colors)"),
)

# Remmina's quality key only distinguishes 0/1/2/9; everything else falls
# back to its internal default. Map our 0-9 choices onto those values.
_REMMINA_QUALITY = {"0": 0, "1": 1, "2": 2, "9": 9}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_port(value: Any, default: int = 5900) -> Optional[int]:
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


def _split_host_port(host: str) -> tuple[str, Optional[int]]:
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


def _validate_host(host: str) -> Optional[str]:
    """Return an error message for an unusable host, or ``None``."""
    host = (host or "").strip()
    if not host:
        return "Host is required."
    if host.startswith("-"):
        return "Host must not start with '-' (it would be parsed as an option)."
    if any(ch.isspace() for ch in host):
        return "Host must not contain whitespace."
    return None


def _flatpak_prefix() -> tuple[str, ...]:
    """Return ``('flatpak-spawn', '--host')`` when running inside Flatpak."""
    if not os.path.exists("/.flatpak-info"):
        return ()
    flatpak = shutil.which("flatpak-spawn")
    if flatpak:
        return (flatpak, "--host")
    logger.warning(
        "Running inside Flatpak but 'flatpak-spawn' was not found on PATH; "
        "host VNC clients will not be reachable. Install flatpak-spawn or "
        "run SSH Pilot outside Flatpak.")
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


@functools.lru_cache(maxsize=32)
def _version_output_for(path: str) -> str:
    """Run ``--version``-style flags once per binary and cache the output.

    The same ``vncviewer`` binary is probed by several candidate clients
    during discovery; caching by path keeps that to a single short subprocess
    run instead of a storm of them.
    """
    for flag in ("--version", "-version", "-help", "-v"):
        try:
            result = subprocess.run(
                [path, flag], capture_output=True, text=True, timeout=1)
        except (subprocess.TimeoutExpired, OSError):
            continue
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            return output
    return ""


def _binary_matches(path: str, binary_name: str, spec: dict) -> bool:
    """Decide whether a found binary really is the client described by spec.

    Version output is authoritative. When a binary produces no version output,
    we only accept it if its name uniquely identifies the client: a shared
    ``vncviewer`` that cannot be fingerprinted must not be silently matched
    against TigerVNC / TurboVNC / TightVNC / RealVNC, because it would then
    be launched with the wrong flags.
    """
    output = _version_output_for(path)
    if output.strip():
        lowered = output.lower()
        return any(marker.lower() in lowered for marker in spec["version_markers"])
    return binary_name not in _SHARED_BINARY_NAMES


def _display_name(client_id: str) -> str:
    return _DISPLAY_NAMES.get(client_id, client_id.capitalize())


_discovery_cache: Optional[tuple[float, tuple[VncClientInfo, ...]]] = None


def _discover_vnc_clients() -> tuple[VncClientInfo, ...]:
    """Discover installed VNC clients by scanning PATH and fingerprinting
    their version output.

    Results are cached for a short TTL so the connection dialog opens fast;
    re-discovery after the TTL picks up clients installed while SSH Pilot is
    running. There is deliberately no environment-variable override: the
    client is chosen explicitly per connection (``vnc_client`` choice or
    ``custom_binary`` path).
    """
    global _discovery_cache
    now = time.monotonic()
    if _discovery_cache is not None:
        ts, cached = _discovery_cache
        if now - ts < _DISCOVERY_TTL_SECONDS:
            return cached

    flatpak = _flatpak_prefix()
    results: list[VncClientInfo] = []
    for client_id in _CLIENT_ORDER:
        spec = KNOWN_CLIENTS[client_id]
        for binary_name in spec["binaries"]:
            path = shutil.which(binary_name)
            if path is None:
                continue
            if not _binary_matches(path, binary_name, spec):
                continue
            results.append(VncClientInfo(
                client_id=client_id,
                binary=path,
                display_name=_display_name(client_id),
                argv_prefix=flatpak + (path,),
            ))
            break

    result = tuple(results)
    _discovery_cache = (now, result)
    return result


def _discovery_cache_clear() -> None:
    """Drop the cached discovery result (used by tests and after installs)."""
    global _discovery_cache
    _discovery_cache = None


def _resolve_custom_binary(value: str) -> str:
    """Resolve a per-connection custom VNC client path or name on PATH."""
    value = (value or "").strip()
    if not value:
        raise ProtocolError("No custom VNC client path provided.")
    if os.sep in value:
        if not os.path.isfile(value) or not os.access(value, os.X_OK):
            raise ProtocolError(
                f"Custom VNC client '{value}' does not exist or is not executable.")
        return value
    path = shutil.which(value)
    if path is None:
        raise ProtocolError(
            f"Custom VNC client '{value}' was not found on PATH.")
    return path


def _resolve_client(data: dict) -> VncClientInfo:
    """Pick the VNC client for a connection.

    Priority: per-connection ``custom_binary`` path > explicit ``vnc_client``
    selection > first preferred installed client.

    There is deliberately no implicit "auto" mode: the user either picks an
    installed client or a custom binary, or gets a clear error.
    """
    custom = (data.get("custom_binary") or "").strip()
    if custom:
        path = _resolve_custom_binary(custom)
        return VncClientInfo(
            client_id="custom",
            binary=path,
            display_name=os.path.basename(path) or "custom",
            argv_prefix=_flatpak_prefix() + (path,),
        )

    selected = (data.get("vnc_client") or "").strip()
    discovered = _discover_vnc_clients()
    if selected:
        for client in discovered:
            if client.client_id == selected:
                return client
        raise ProtocolError(
            f"VNC client '{selected}' is not installed on this system. "
            "Install it, choose another client, or set a custom binary path "
            "for this connection.")

    if discovered:
        # Only reachable for connections saved before the client field had a
        # default; pick deterministically but log so the choice is visible.
        logger.warning(
            "No VNC client was selected for this connection; using %s.",
            discovered[0].display_name)
        return discovered[0]

    raise ProtocolError(
        "No VNC client was found on this system. Install one of: "
        "TigerVNC, TurboVNC, TightVNC, RealVNC, Remmina, KRDC, Vinagre, "
        "gvncviewer — or set a custom binary path for this connection.")


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


_TEMP_FILES: List[str] = []
_TEMP_FILES_REGISTERED = False


def _track_temp_file(path: str) -> None:
    """Register a temp file for cleanup at interpreter exit / deactivate."""
    global _TEMP_FILES_REGISTERED
    _TEMP_FILES.append(path)
    if not _TEMP_FILES_REGISTERED:
        _TEMP_FILES_REGISTERED = True
        atexit.register(_cleanup_temp_files)


def _cleanup_temp_files() -> None:
    for path in _TEMP_FILES:
        _safe_remove(path)
    _TEMP_FILES.clear()


def _safe_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _create_passwd_file(password: str) -> Optional[str]:
    """Create a temporary VNC password file (mode 0o600).

    The password is converted with ``vncpasswd -f`` when available, producing
    the DES-encrypted format that every CLI viewer expects. When conversion
    is not possible we log a warning and fall back to a plain-text file:
    a handful of viewers accept it, but the standard clients (TigerVNC,
    TurboVNC, TightVNC, RealVNC) will fail authentication without the
    encrypted format.

    VNC passwords are limited to 8 characters by the protocol; longer
    passwords are truncated with a warning, mirroring ``vncpasswd``.
    """
    if not password:
        return None
    if len(password) > VNC_PASSWORD_MAX:
        logger.warning(
            "VNC passwords are limited to %d characters; the password was "
            "truncated to match. Check the password set on the VNC server.",
            VNC_PASSWORD_MAX)
        password = password[:VNC_PASSWORD_MAX]

    fd, path = tempfile.mkstemp(prefix="vnc-pass-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(password)
        os.chmod(path, 0o600)
    except OSError:
        logger.exception("Failed to write the temporary VNC password file")
        return None

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
            else:
                logger.warning(
                    "vncpasswd produced no output; passing a plain-text "
                    "password file, which standard viewers will reject.")
        except (subprocess.TimeoutExpired, OSError, ValueError):
            logger.warning(
                "Failed to convert the password to VNC format with "
                "vncpasswd; passing a plain-text password file instead.")
    else:
        logger.warning(
            "vncpasswd was not found on PATH; passing a plain-text password "
            "file, which standard viewers will reject. Install the VNC "
            "client tools (vncpasswd) for reliable password authentication.")

    _track_temp_file(path)
    return path


# ---------------------------------------------------------------------------
# Target / URI resolution
# ---------------------------------------------------------------------------


def _vnc_port(data: dict, host: str, default: int = 5900) -> int:
    """Resolve the effective VNC port.

    Priority: display number N (port 5900+N) > ``host:port`` suffix inside
    the host field > the ``port`` field.
    """
    display = data.get("display")
    if display is not None and str(display).strip() != "":
        try:
            d = int(display)
            if d >= 0:
                return 5900 + d
        except (TypeError, ValueError):
            pass
    _, embedded = _split_host_port(host)
    if embedded:
        return embedded
    port = _parse_port(data.get("port"), default)
    return port if port is not None else default


def _resolve_target(data: dict, host: str) -> str:
    """Build the VNC target string: ``host:display`` or ``host::port``."""
    host = (host or "").strip()
    if not host:
        return ""
    display = data.get("display")
    if display is not None and str(display).strip() != "":
        try:
            d = int(display)
            if d >= 0:
                return f"{_format_host(host)}:{d}"
        except (TypeError, ValueError):
            pass
    port = _vnc_port(data, host)
    return f"{_format_host(host)}::{port}"


def _vnc_uri(data: dict, host: str) -> str:
    """Build a ``vnc://host:port`` URI for GUI clients (KRDC, Vinagre)."""
    host = (host or "").strip()
    if not host:
        return ""
    bare, _ = _split_host_port(host)
    port = _vnc_port(data, host)
    return f"vnc://{_format_host(bare)}:{port}"


def _extra_args_list(data: dict) -> List[str]:
    """Split the raw ``extra_args`` field into argv tokens.

    Unlike a plain ``str.split()``, this respects quotes so values like
    ``-via "user@gateway"`` survive intact.
    """
    extra = (data.get("extra_args") or "").strip()
    if not extra:
        return []
    try:
        return shlex.split(extra)
    except ValueError:
        logger.warning(
            "extra_args contains unbalanced quotes; falling back to plain "
            "whitespace splitting.")
        return extra.split()


# ---------------------------------------------------------------------------
# Per-client argv builders (uniform signature: (client, data, password))
# ---------------------------------------------------------------------------


def _build_tiger_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for TigerVNC (and its TurboVNC derivative).

    TigerVNC and TurboVNC share a common heritage but their parameter sets
    diverged; both are handled here, with TurboVNC's specific names used
    where they differ (Encoding, Quality 1-100, DesktopSize, RecvClipboard,
    SendClipboard, LocalCursor, JPEG, Colors).
    """
    host = _get_host(data)
    target = _resolve_target(data, host)
    argv = list(client.argv_prefix)
    argv.append(target)
    is_turbo = client.client_id == "turbovnc"

    if data.get("view_only"):
        argv.append("-ViewOnly")
    if data.get("fullscreen"):
        argv.append("-FullScreen")
    # Both viewers use the -Shared / -Shared=0 boolean syntax.
    argv.append("-Shared" if data.get("shared", True) else "-Shared=0")

    encoding = data.get("encoding")
    if encoding:
        argv += (["-Encoding", str(encoding)] if is_turbo
                 else ["-PreferredEncoding", str(encoding)])

    quality = data.get("quality")
    if quality:
        if is_turbo:
            # TurboVNC's JPEG quality is 1-100; map our 0-9 choices onto it.
            level = max(1, min(100, int(quality) * 10 + 5))
            argv += ["-Quality", str(level)]
        else:
            argv += ["-QualityLevel", str(quality)]

    compress = data.get("compress")
    if compress:
        argv += ["-CompressLevel", str(compress)]

    color_depth = data.get("color_depth")
    if color_depth:
        if is_turbo:
            colors = {
                "8": "256", "16": "65536",
                "24": "16777216", "32": "16777216",
            }.get(str(color_depth))
            if colors:
                argv += ["-Colors", colors]
        elif str(color_depth) == "8":
            # TigerVNC has no -colorDepth; 8-bit (256 colors) is the highest
            # reduced color level it can force.
            argv += ["-LowColorLevel", "2"]
        elif str(color_depth) in ("24", "32"):
            argv += ["-FullColor"]
        # 16-bit has no TigerVNC equivalent; leave AutoSelect to decide.

    geometry = data.get("tigervnc_geometry") or data.get("turbovnc_geometry")
    if geometry:
        argv += (["-DesktopSize", str(geometry)] if is_turbo
                 else ["-geometry", str(geometry)])

    via = data.get("tigervnc_via") or data.get("turbovnc_via")
    if via:
        argv += ["-via", str(via)]

    if not data.get("tigervnc_accept_clipboard", True):
        argv.append("-RecvClipboard=0" if is_turbo else "-AcceptClipboard=0")
    if not data.get("tigervnc_send_clipboard", True):
        argv.append("-SendClipboard=0" if is_turbo else "-SendClipboard=0")

    if is_turbo:
        # TurboVNC's JPEG is on by default; only force it explicitly on.
        if data.get("turbovnc_jpeg"):
            argv.append("-JPEG=1")
        argv.append("-LocalCursor=1" if data.get("turbovnc_local", True) else "-LocalCursor=0")

    argv += _extra_args_list(data)

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv.append("-passwd")
            argv.append(passwd_file)
    return argv, env


def _build_tightvnc_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for TightVNC (different flag names from TigerVNC)."""
    host = _get_host(data)
    target = _resolve_target(data, host)
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-viewonly")
    if data.get("fullscreen"):
        argv.append("-fullscreen")
    argv.append("-shared" if data.get("shared", True) else "-noshared")

    encoding = data.get("encoding")
    if encoding:
        argv += ["-encodings", str(encoding)]
    quality = data.get("quality")
    if quality:
        argv += ["-quality", str(quality)]
    compress = data.get("compress")
    if compress:
        argv += ["-compresslevel", str(compress)]

    color_depth = data.get("color_depth")
    if color_depth:
        # TightVNC has no -bcolors; it exposes 8-bit (-bgr233) vs 24-bit
        # (-truecolour) pixel formats.
        argv.append("-bgr233" if str(color_depth) == "8" else "-truecolour")

    argv += _extra_args_list(data)

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv += ["-passwd", passwd_file]
    return argv, env


def _build_realvnc_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for the RealVNC viewer.

    Only options documented in the RealVNC viewer manual are used;
    quality/compression levels are not exposed by RealVNC and are skipped.
    """
    host = _get_host(data)
    target = _resolve_target(data, host)
    argv = list(client.argv_prefix)
    argv.append(target)

    if data.get("view_only"):
        argv.append("-ViewOnly")
    if data.get("fullscreen"):
        argv.append("-FullScreen")
    if data.get("shared", True):
        argv.append("-Shared")

    encoding = data.get("encoding")
    # RealVNC only documents ZRLE / hextile / raw for -PreferredEncoding.
    if encoding and str(encoding) != "Tight":
        argv += ["-PreferredEncoding", str(encoding)]

    via = data.get("tigervnc_via") or data.get("turbovnc_via")
    if via:
        argv += ["-via", str(via)]

    argv += _extra_args_list(data)

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv += ["-passwd", passwd_file]
    return argv, env


def _profile_value(value: Any) -> str:
    """Sanitize a value for a GLib-style .remmina key file."""
    return str(value).replace("\n", " ").replace("\r", " ").strip()


def _write_temp_profile(lines: List[str]) -> Optional[str]:
    fd, path = tempfile.mkstemp(prefix="remmina-vnc-", suffix=".remmina")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
    except OSError:
        logger.exception("Failed to write the temporary Remmina profile")
        _safe_remove(path)
        return None
    _track_temp_file(path)
    return path


def _build_remmina_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for Remmina (>= 1.4) via a temporary .remmina profile.

    The profile is generated with the keys Remmina's VNC plugin reads:
    ``server=host:port`` (Remmina parses the port itself), ``username``,
    ``password``, ``viewonly``, ``quality``, ``colordepth`` and
    ``viewmode=2`` for fullscreen. ``extra_args`` has no equivalent in
    Remmina profiles and is intentionally not applied.
    """
    host = _get_host(data)
    if not host:
        raise ProtocolError("No host configured for this connection.")
    port = _vnc_port(data, host)
    username = data.get("username") or ""

    lines = [
        "[remmina]",
        f"name={_profile_value(data.get('_connection_name') or 'VNC Pilot')}",
        "protocol=VNC",
        f"server={_format_host(host)}:{port}",
        "viewonly=%d" % (1 if data.get("view_only") else 0),
        "disablepasswordstoring=0",
    ]
    if data.get("fullscreen"):
        lines.append("viewmode=2")
    quality = data.get("quality")
    if quality:
        lines.append("quality=%d" % _REMMINA_QUALITY.get(str(quality), 2))
    color_depth = data.get("color_depth")
    if color_depth and str(color_depth) in ("8", "16", "24", "32"):
        lines.append("colordepth=%d" % int(color_depth))
    if username:
        lines.append(f"username={_profile_value(username)}")
    if password:
        lines.append(f"password={_profile_value(password)}")

    profile_path = _write_temp_profile(lines)

    argv = list(client.argv_prefix)
    if profile_path:
        argv += ["--connect", profile_path]
    else:
        argv += ["-c", _vnc_uri(data, host)]
    return argv, dict(os.environ)


def _build_krdc_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for KRDC (KDE).

    KRDC accepts ``vnc://host:port`` URIs and ignores a password on the
    command line entirely, so it is left to prompt the user.
    """
    host = _get_host(data)
    uri = _vnc_uri(data, host)
    argv = list(client.argv_prefix)
    argv.append(uri)

    if data.get("fullscreen"):
        argv.append("-f")

    argv += _extra_args_list(data)
    return argv, dict(os.environ)


def _build_vinagre_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for Vinagre (GNOME).

    Vinagre accepts ``vnc://host:port`` URIs and cannot take a password on
    the command line, so it is left to prompt the user.
    """
    host = _get_host(data)
    uri = _vnc_uri(data, host)
    argv = list(client.argv_prefix)
    argv.append(uri)

    if data.get("fullscreen"):
        argv.append("--fullscreen")

    argv += _extra_args_list(data)
    return argv, dict(os.environ)


def _build_gvncviewer_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for gvncviewer (gtk-vnc).

    gvncviewer exposes no command-line options at all (no fullscreen,
    view-only, color depth or password file), so it is launched with a
    ``host::port`` target and prompts for the password itself. Any
    client-specific flags must be passed via ``extra_args``.
    """
    host = _get_host(data)
    target = _resolve_target(data, host)
    argv = list(client.argv_prefix)
    argv.append(target)

    argv += _extra_args_list(data)
    return argv, dict(os.environ)


def _build_custom_argv(
    client: VncClientInfo, data: dict, password: str,
) -> Tuple[List[str], Dict[str, str]]:
    """Build argv for a user-specified custom VNC client.

    This is a best-effort passthrough: ``host::port`` target plus raw
    ``extra_args``. The ``-passwd`` option is assumed to be TigerVNC-style,
    which is the most common convention; if the custom client uses different
    flags, pass them via ``extra_args``.
    """
    host = _get_host(data)
    target = _resolve_target(data, host)
    argv = list(client.argv_prefix)
    argv.append(target)

    argv += _extra_args_list(data)

    env = dict(os.environ)
    if password:
        passwd_file = _create_passwd_file(password)
        if passwd_file:
            argv += ["-passwd", passwd_file]
    return argv, env


_BUILDERS = {
    "tigervnc": _build_tiger_argv,
    "turbovnc": _build_tiger_argv,
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
            placeholder="password (stored in system keyring; max 8 chars)"))

        # The client is always chosen explicitly: either from the installed
        # clients discovered on this system, or 'custom' with a binary path.
        choices = self._vnc_client_choices()
        first = choices[0][0] if choices else ""
        fields.append(FieldSpec(
            key="vnc_client", label="VNC Client", kind="choice",
            # With no client installed only 'custom' is offered: leave the
            # selection empty so validate() shows the install-a-client
            # warning instead of silently defaulting to Custom.
            default="" if first == "custom" else first,
            choices=choices,
            placeholder="Select a VNC client installed on this system"))

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
            # 24-bit truecolor is more than enough for comfortable work and
            # cuts network traffic substantially vs 32-bit; users can still
            # pick another depth or Auto per connection.
            default="24", choices=_COLOR_DEPTH, group="Display"))
        fields.append(FieldSpec(
            key="extra_args", label="Extra CLI arguments", kind="text",
            placeholder="-via user@gateway (quotes supported, appended to argv)"))

        # --- TigerVNC ---
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
            key="turbovnc_geometry", label="Geometry (DesktopSize)",
            kind="text", placeholder="e.g. 1280x720", group="TurboVNC"))
        fields.append(FieldSpec(
            key="turbovnc_via", label="SSH tunnel via", kind="text",
            placeholder="e.g. user@gateway", group="TurboVNC"))
        fields.append(FieldSpec(
            key="turbovnc_jpeg", label="Force JPEG compression",
            kind="switch", default=False, group="TurboVNC"))
        fields.append(FieldSpec(
            key="turbovnc_local", label="Local cursor",
            kind="switch", default=True, group="TurboVNC"))

        # --- Custom ---
        fields.append(FieldSpec(
            key="custom_binary", label="Custom binary path", kind="text",
            placeholder="/path/to/vncviewer or a name on PATH",
            group="Custom"))

        return fields

    def _vnc_client_choices(self) -> List[tuple[str, str]]:
        """Build the vnc_client choice list.

        Contains every client installed on this system, plus an explicit
        'custom' entry. There is intentionally no 'auto' option: selection
        must be unambiguous. With no clients installed the list still offers
        'custom', and validate() reports the missing-client warning.
        """
        choices: List[tuple[str, str]] = []
        for client in _discover_vnc_clients():
            choices.append((client.client_id, client.display_name))
        choices.append(("custom", "Custom (binary path below)"))
        return choices

    def validate(self, data: dict[str, Any]) -> List[str]:
        errors: List[str] = []
        host_error = _validate_host(_get_host(data))
        if host_error:
            errors.append(host_error)
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
        errors.extend(self._validate_client(data))
        return errors

    def _validate_client(self, data: dict[str, Any]) -> List[str]:
        custom = (data.get("custom_binary") or "").strip()
        if custom:
            try:
                _resolve_custom_binary(custom)
                return []
            except ProtocolError as exc:
                return [str(exc)]
        selected = (data.get("vnc_client") or "").strip()
        discovered = _discover_vnc_clients()
        if selected == "custom":
            return ["Custom binary path is required when 'Custom' is selected."]
        if selected:
            if any(c.client_id == selected for c in discovered):
                return []
            return [
                f"VNC client '{selected}' is not installed on this system. "
                "Install it or pick another client."]
        if not discovered:
            return [
                "No VNC client was found on this system. Install one of: "
                "TigerVNC, TurboVNC, TightVNC, RealVNC, Remmina, KRDC, "
                "Vinagre, gvncviewer — or set a custom binary path."]
        return ["Select a VNC client."]

    def build_spawn(self, connection: Any, ctx: PluginContext) -> SpawnSpec:
        raw_data = getattr(connection, "data", None) or {}
        data = dict(raw_data)
        data.setdefault(
            "_connection_name",
            (getattr(connection, "nickname", "") or "").strip())

        host = _get_host(data, connection)
        if not host:
            raise ProtocolError("No host configured for this connection.")

        client = _resolve_client(data)
        password = _resolve_password(connection, raw_data, ctx)

        builder = _BUILDERS.get(client.client_id, _build_custom_argv)
        argv, env = builder(client, data, password)

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
        # Remove any leftover temporary password/profile files. atexit covers
        # interpreter exit; this covers plugin disable within a running app.
        _cleanup_temp_files()
