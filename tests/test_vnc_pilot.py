"""Tests for the VNC Pilot SSH Pilot plugin (run without the SSH Pilot SDK)."""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"


def _install_fake_sdk() -> None:
    """Install a minimal fake 'sshpilot.plugins.api' so the plugin imports."""
    if "sshpilot.plugins.api" in sys.modules:
        return

    class ProtocolError(Exception):
        pass

    class FieldSpec:
        def __init__(self, **kwargs):
            defaults = {
                "kind": "text",
                "default": None,
                "choices": None,
                "placeholder": "",
                "required": False,
                "group": "general",
            }
            defaults.update(kwargs)
            self.__dict__.update(defaults)

    class ProtocolBackend:
        protocol_id = None
        display_name = None
        default_port = None

    class SshPilotPlugin:
        pass

    class SpawnSpec:
        def __init__(self, argv=None, env=None, working_directory=None, extras=None):
            self.argv = argv or []
            self.env = env or {}
            self.working_directory = working_directory
            self.extras = extras or {}

    class PluginContext:
        pass

    api = types.ModuleType("sshpilot.plugins.api")
    api.ProtocolError = ProtocolError
    api.FieldSpec = FieldSpec
    api.ProtocolBackend = ProtocolBackend
    api.SshPilotPlugin = SshPilotPlugin
    api.SpawnSpec = SpawnSpec
    api.PluginContext = PluginContext

    plugins = types.ModuleType("sshpilot.plugins")
    plugins.api = api
    pkg = types.ModuleType("sshpilot")
    pkg.plugins = plugins
    sys.modules["sshpilot"] = pkg
    sys.modules["sshpilot.plugins"] = plugins
    sys.modules["sshpilot.plugins.api"] = api


_install_fake_sdk()

_spec = importlib.util.spec_from_file_location("vnc_pilot", str(PLUGIN_PATH))
_module = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["vnc_pilot"] = _module
_spec.loader.exec_module(_module)
vnc = _module


class _FakeConnection:
    def __init__(self, data=None, nickname="test"):
        self.data = data or {}
        self.nickname = nickname


def make_ctx(secrets_get=None):
    class Secrets:
        def __init__(self):
            self.calls = []
            self._get = secrets_get or (lambda key: None)

        def get(self, key):
            return self._get(key)

        def set(self, key, value):
            self.calls.append(("set", key, value))

        def delete(self, key):
            self.calls.append(("delete", key))
            return True

    secrets = Secrets()
    return SimpleNamespace(secrets=secrets), secrets


@pytest.fixture(autouse=True)
def clear_caches(monkeypatch):
    vnc._discover_vnc_clients.cache_clear()
    yield
    vnc._discover_vnc_clients.cache_clear()


@pytest.fixture
def backend():
    return vnc.VncBackend()


@pytest.fixture(autouse=True)
def mock_version_subprocess(monkeypatch):
    """By default, fake subprocess.run so version detection doesn't hit the system."""
    def fake_run(args, **kwargs):
        class Result:
            returncode = 0
            stdout = ""
            stderr = ""
        return Result()
    monkeypatch.setattr(vnc.subprocess, "run", fake_run)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_split_host_port():
    assert vnc._split_host_port("host") == ("host", None)
    assert vnc._split_host_port("host:5901") == ("host", 5901)
    assert vnc._split_host_port("192.168.1.5:5901") == ("192.168.1.5", 5901)
    assert vnc._split_host_port("::1") == ("::1", None)
    assert vnc._split_host_port("[::1]") == ("::1", None)
    assert vnc._split_host_port("[::1]:5901") == ("::1", 5901)
    assert vnc._split_host_port("  host  ") == ("host", None)
    assert vnc._split_host_port("") == ("", None)


def test_format_host():
    assert vnc._format_host("10.0.0.1") == "10.0.0.1"
    assert vnc._format_host("::1") == "[::1]"
    assert vnc._format_host("fe80::1") == "[fe80::1]"
    assert vnc._format_host("[::1]") == "[::1]"


def test_parse_port():
    assert vnc._parse_port(None) == 5900
    assert vnc._parse_port(5901) == 5901
    assert vnc._parse_port("5901") == 5901
    assert vnc._parse_port(" 5901 ") == 5901
    assert vnc._parse_port("") == 5900
    assert vnc._parse_port(True) is None
    assert vnc._parse_port(3.5) is None
    assert vnc._parse_port("abc") is None
    assert vnc._parse_port(0) is None
    assert vnc._parse_port(65536) is None


def test_get_host():
    assert vnc._get_host({"host": "10.0.0.1"}) == "10.0.0.1"
    assert vnc._get_host({"hostname": "example.com"}) == "example.com"
    assert vnc._get_host({}) == ""


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------

def test_validate_requires_host():
    assert "Host is required." in vnc.VncBackend().validate({})


def test_validate_port_range():
    backend = vnc.VncBackend()
    for bad in (70000, 0, -1, "abc", True, 3.5):
        errors = backend.validate({"host": "h", "port": bad})
        assert "Port must be an integer between 1 and 65535." in errors, bad


def test_validate_ok():
    backend = vnc.VncBackend()
    assert backend.validate({"host": "10.0.0.1"}) == []
    assert backend.validate({"host": "10.0.0.1", "port": 5901}) == []
    assert backend.validate({"host": "10.0.0.1", "port": ""}) == []


def test_validate_display():
    backend = vnc.VncBackend()
    assert backend.validate({"host": "h", "display": "abc"}) != []
    assert backend.validate({"host": "h", "display": 1}) == []


# ---------------------------------------------------------------------------
# Client discovery
# ---------------------------------------------------------------------------

def test_discover_clients_auto(monkeypatch):
    def which(name):
        mapping = {
            "vncviewer": "/usr/bin/vncviewer",
            "gvncviewer": "/usr/bin/gvncviewer",
        }
        return mapping.get(name)

    def fake_run(args, **kwargs):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        binary = os.path.basename(args[0])
        if binary == "vncviewer":
            R.stdout = "TigerVNC viewer version 1.14.0"
        elif binary == "gvncviewer":
            R.stdout = "gvncviewer version 1.2.0"
        return R()

    monkeypatch.setattr(vnc.shutil, "which", which)
    monkeypatch.setattr(vnc.subprocess, "run", fake_run)
    clients = vnc._discover_vnc_clients()
    ids = [c.client_id for c in clients]
    assert "tigervnc" in ids
    assert "gvncviewer" in ids


def test_discover_client_with_env_override():
    """ VNC_PILOT_BIN forces a custom client. """
    os_env = dict(__import__("os").environ)
    os_env["VNC_PILOT_BIN"] = "/custom/vncviewer"
    with mock.patch.dict("os.environ", os_env, clear=True):
        vnc._discover_vnc_clients.cache_clear()
        clients = vnc._discover_vnc_clients()
        assert len(clients) == 1
        assert clients[0].client_id == "custom"
        assert clients[0].binary == "/custom/vncviewer"
        vnc._discover_vnc_clients.cache_clear()


def test_discover_no_client_found(monkeypatch):
    monkeypatch.setattr(vnc.shutil, "which", lambda name: None)
    clients = vnc._discover_vnc_clients()
    assert len(clients) == 0


def test_discover_conflicting_vncviewer_resolved_by_version(monkeypatch):
    """The 'vncviewer' name is shared by multiple clients; version fingerprinting
    must distinguish them."""
    def which(name):
        if name == "vncviewer":
            return "/usr/bin/vncviewer"
        return None

    call_count = [0]

    def fake_run(args, **kwargs):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        call_count[0] += 1
        # Return output matching the first client in _CLIENT_ORDER (tigervnc)
        R.stdout = "TigerVNC viewer version 1.14.0"
        return R()

    monkeypatch.setattr(vnc.shutil, "which", which)
    monkeypatch.setattr(vnc.subprocess, "run", fake_run)
    clients = vnc._discover_vnc_clients()
    # Should resolve to tigervnc, not be duplicated
    tigervnc = [c for c in clients if c.client_id == "tigervnc"]
    assert len(tigervnc) == 1


# ---------------------------------------------------------------------------
# build_spawn() — TigerVNC
# ---------------------------------------------------------------------------

def make_backend_v3(monkeypatch):
    """Patch shutil.which to return TigerVNC for vncviewer."""
    monkeypatch.setattr(vnc.shutil, "which",
                        lambda name: f"/usr/bin/{name}" if name == "vncviewer" else None)

    def fake_run(args, **kwargs):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        if "vncviewer" in args[0]:
            R.stdout = "TigerVNC viewer version 1.14.0"
        return R()

    monkeypatch.setattr(vnc.subprocess, "run", fake_run)
    vnc._discover_vnc_clients.cache_clear()
    return vnc.VncBackend()


def test_build_spawn_tigervnc_basic(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/usr/bin/vncviewer"
    target = spawn.argv[1]
    assert "10.0.0.1" in target
    assert "::5900" in target  # default port


def test_build_spawn_tigervnc_viewonly(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1", "view_only": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-ViewOnly" in spawn.argv


def test_build_spawn_tigervnc_fullscreen(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1", "fullscreen": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-FullScreen" in spawn.argv


def test_build_spawn_tigervnc_shared(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1"})  # shared defaults to True
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-Shared" in spawn.argv


def test_build_spawn_tigervnc_not_shared(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1", "shared": False})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-NOShared" in spawn.argv


def test_build_spawn_tigervnc_display(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "10.0.0.1", "display": 5})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    # Display 5 → port 5905
    target = spawn.argv[1]
    assert ":5" in target


def test_build_spawn_tigervnc_encoding(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h", "encoding": "Hextile"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-PreferredEncoding" in spawn.argv
    idx = spawn.argv.index("-PreferredEncoding")
    assert spawn.argv[idx + 1] == "Hextile"


def test_build_spawn_tigervnc_quality(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h", "quality": "7"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-QualityLevel" in spawn.argv
    idx = spawn.argv.index("-QualityLevel")
    assert spawn.argv[idx + 1] == "7"


def test_build_spawn_tigervnc_extra_args(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h", "extra_args": "-Log *:debug"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-Log" in spawn.argv
    assert "*:debug" in spawn.argv


def test_build_spawn_ipv6(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "::1"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    target = spawn.argv[1]
    assert "[::1]" in target


def test_build_spawn_host_with_embedded_port(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "vnc.example.com:5901"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    target = spawn.argv[1]
    assert "::5901" in target


# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------

def test_password_from_keyring(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h"})
    ctx, _ = make_ctx(secrets_get=lambda key: "s3cret")
    spawn = backend.build_spawn(conn, ctx)
    assert "-passwd" in spawn.argv


def test_no_password_when_absent(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-passwd" not in spawn.argv


def test_password_uses_tmp_file_not_argv(monkeypatch):
    """Password must appear only in a temp passwd file, never in argv directly."""
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h"})
    ctx, _ = make_ctx(secrets_get=lambda key: "my secret pass")
    spawn = backend.build_spawn(conn, ctx)
    for arg in spawn.argv:
        assert "my secret pass" not in arg


def test_legacy_password_migrated_to_keyring(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h", "credential": "legacy-pass"})
    ctx, secrets = make_ctx()
    backend.build_spawn(conn, ctx)
    assert secrets.calls == [("set", "vnc_password_test", "legacy-pass")]
    assert "credential" not in conn.data


# ---------------------------------------------------------------------------
# Client selection
# ---------------------------------------------------------------------------

def test_build_spawn_explicit_tigervnc(monkeypatch):
    monkeypatch.setattr(vnc.shutil, "which",
                        lambda name: f"/usr/bin/{name}" if name == "vncviewer" else None)

    def fake_run(args, **kwargs):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        if "vncviewer" in args[0]:
            R.stdout = "TigerVNC viewer version 1.14.0"
        return R()

    monkeypatch.setattr(vnc.subprocess, "run", fake_run)
    vnc._discover_vnc_clients.cache_clear()

    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/usr/bin/vncviewer"


def test_build_spawn_client_not_found(monkeypatch):
    monkeypatch.setattr(vnc.shutil, "which", lambda name: None)
    vnc._discover_vnc_clients.cache_clear()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="not found"):
        backend.build_spawn(conn, ctx)


def test_build_spawn_no_client_found(monkeypatch):
    monkeypatch.setattr(vnc.shutil, "which", lambda name: None)
    vnc._discover_vnc_clients.cache_clear()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="No VNC client found"):
        backend.build_spawn(conn, ctx)


# ---------------------------------------------------------------------------
# connection_fields()
# ---------------------------------------------------------------------------

def test_connection_fields_present():
    backend = vnc.VncBackend()
    fields = backend.connection_fields()
    keys = [f.key for f in fields]
    for required in ("host", "port", "display", "username", "credential",
                     "vnc_client", "view_only", "fullscreen", "shared",
                     "quality", "compress", "encoding", "color_depth",
                     "extra_args"):
        assert required in keys, required


def test_connection_fields_groups():
    backend = vnc.VncBackend()
    fields = backend.connection_fields()
    groups = {f.key: f.group for f in fields}
    assert groups["host"] == "general"
    assert groups["vnc_client"] == "general"
    assert groups["view_only"] == "Display"
    assert groups["tigervnc_geometry"] == "TigerVNC"
    assert groups["turbovnc_jpeg"] == "TurboVNC"
    assert groups["remmina_sftp"] == "Remmina"
    assert groups["custom_binary"] == "Custom"


def test_connection_fields_required():
    backend = vnc.VncBackend()
    fields = {f.key: f for f in backend.connection_fields()}
    assert fields["host"].required is True
    assert fields["port"].default == 5900
    assert fields["shared"].default is True


# ---------------------------------------------------------------------------
# Per-client dispatch
# ---------------------------------------------------------------------------

def test_builder_dispatch_tigervnc(monkeypatch):
    backend = make_backend_v3(monkeypatch)
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc", "view_only": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-ViewOnly" in spawn.argv


def test_builder_dispatch_custom(monkeypatch):
    monkeypatch.setenv("VNC_PILOT_BIN", "/opt/vnc/custom-viewer")
    vnc._discover_vnc_clients.cache_clear()

    conn = _FakeConnection({"host": "h", "vnc_client": "custom"})
    ctx, _ = make_ctx()
    backend = vnc.VncBackend()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/opt/vnc/custom-viewer"
    assert "h" in spawn.argv[1] or "h::5900" in spawn.argv[1]


# ---------------------------------------------------------------------------
# Flatpak
# ---------------------------------------------------------------------------

def test_flatpak_prefix_no_flatpak(monkeypatch):
    monkeypatch.setattr(vnc.os.path, "exists", lambda p: False if p == "/.flatpak-info" else True)
    assert vnc._flatpak_prefix() == ()


def test_flatpak_prefix_with_flatpak(monkeypatch):
    def fake_exists(p):
        if p == "/.flatpak-info":
            return True
        if p == "/usr/bin/flatpak-spawn":
            return True
        return True
    monkeypatch.setattr(vnc.os.path, "exists", fake_exists)
    monkeypatch.setattr(vnc.shutil, "which",
                        lambda name: "/usr/bin/flatpak-spawn" if name == "flatpak-spawn" else "/usr/bin/vncviewer")
    prefix = vnc._flatpak_prefix()
    assert prefix == ("/usr/bin/flatpak-spawn", "--host")


# ---------------------------------------------------------------------------
# Resolve target
# ---------------------------------------------------------------------------

def test_resolve_target_default_port():
    assert "5900" in vnc._resolve_target({}, "10.0.0.1")


def test_resolve_target_with_port():
    target = vnc._resolve_target({"port": 5905}, "10.0.0.1")
    assert "5905" in target


def test_resolve_target_with_display():
    target = vnc._resolve_target({"display": 3}, "10.0.0.1")
    assert ":3" in target


def test_resolve_target_ipv6():
    target = vnc._resolve_target({}, "::1")
    assert "[::1]" in target


# ---------------------------------------------------------------------------
# ConnectionDialog patch
# ---------------------------------------------------------------------------

def test_patch_failure_is_logged(caplog, monkeypatch):
    vnc.Plugin._PATCHED = False
    plugin = vnc.Plugin()
    ctx = SimpleNamespace(register_protocol=lambda p: None)
    with caplog.at_level(logging.ERROR):
        plugin.activate(ctx)
    assert any("Failed to patch ConnectionDialog" in r.message for r in caplog.records)


def test_patched_validation_logs_failures(caplog, monkeypatch):
    class Row:
        def get_visible(self):
            raise RuntimeError("boom")

    class Dialog:
        nickname_row = Row()
        hostname_row = Row()
        username_row = Row()
        port_row = Row()

        @classmethod
        def _apply_protocol_to_ui(cls, self_obj):
            pass

        @classmethod
        def _run_initial_validation(cls, self_obj):
            pass

    dialog_module = types.ModuleType("sshpilot.connection_dialog")
    dialog_module.ConnectionDialog = Dialog
    monkeypatch.setitem(sys.modules, "sshpilot.connection_dialog", dialog_module)

    vnc.Plugin._PATCHED = False
    vnc.Plugin()._patch_connection_dialog()

    with caplog.at_level(logging.ERROR):
        Dialog._run_initial_validation(Dialog())
    assert any(
        "Failed to run initial connection dialog validation" in r.message
        for r in caplog.records
    )
