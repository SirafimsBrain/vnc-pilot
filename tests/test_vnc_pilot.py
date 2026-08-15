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
    vnc._discovery_cache_clear()
    vnc._version_output_for.cache_clear()
    vnc._cleanup_temp_files()
    yield
    vnc._discovery_cache_clear()
    vnc._version_output_for.cache_clear()
    vnc._cleanup_temp_files()


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


def _make_discovery(which_map, version_outputs=None):
    """Install fake shutil.which + version output for client discovery."""
    version_outputs = version_outputs or {}

    def fake_which(name):
        return which_map.get(name)

    def fake_run(args, **kwargs):
        class Result:
            returncode = 0
            stdout = ""
            stderr = ""
        binary = os.path.basename(args[0])
        if binary in version_outputs:
            Result.stdout = version_outputs[binary]
        return Result()

    vnc.shutil.which = fake_which
    vnc.subprocess.run = fake_run
    vnc._discovery_cache_clear()
    vnc._version_output_for.cache_clear()


def _make_tigervnc():
    """Install a TigerVNC viewable via /usr/bin/vncviewer."""
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "TigerVNC viewer version 1.14.0"})


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


def test_extra_args_respects_quotes():
    data = {"extra_args": '-via "user@gateway" -Log *:debug'}
    assert vnc._extra_args_list(data) == ["-via", "user@gateway", "-Log", "*:debug"]


def test_extra_args_plain_split_on_unbalanced_quotes(caplog):
    data = {"extra_args": 'unbalanced "quote'}
    with caplog.at_level(logging.WARNING):
        assert vnc._extra_args_list(data) == ["unbalanced", '"quote']


def test_validate_host():
    assert vnc._validate_host("") == "Host is required."
    assert vnc._validate_host("   ") == "Host is required."
    assert vnc._validate_host("-oProxy") is not None
    assert vnc._validate_host("has space") is not None
    assert vnc._validate_host("10.0.0.1") is None
    assert vnc._validate_host("[::1]") is None


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
    _make_tigervnc()
    backend = vnc.VncBackend()
    assert backend.validate({"host": "10.0.0.1", "vnc_client": "tigervnc"}) == []
    assert backend.validate({"host": "10.0.0.1", "port": 5901, "vnc_client": "tigervnc"}) == []


def test_validate_display():
    _make_tigervnc()
    backend = vnc.VncBackend()
    assert backend.validate({"host": "h", "display": "abc", "vnc_client": "tigervnc"}) != []
    assert backend.validate({"host": "h", "display": -1, "vnc_client": "tigervnc"}) != []
    assert backend.validate({"host": "h", "display": 1, "vnc_client": "tigervnc"}) == []


def test_validate_no_client_installed_warns():
    _make_discovery({})
    errors = vnc.VncBackend().validate({"host": "10.0.0.1"})
    assert any("No VNC client was found" in e for e in errors)


def test_validate_explicit_auto_is_an_error():
    """There is no 'auto' client: selecting it must be a clear error, not silence."""
    _make_tigervnc()
    errors = vnc.VncBackend().validate({"host": "h", "vnc_client": "auto"})
    assert any("'auto' is not installed" in e for e in errors)


def test_validate_custom_requires_path():
    _make_tigervnc()
    errors = vnc.VncBackend().validate({"host": "h", "vnc_client": "custom"})
    assert any("Custom binary path is required" in e for e in errors)


def test_validate_custom_binary_path():
    _make_tigervnc()
    errors = vnc.VncBackend().validate({"host": "h", "custom_binary": "/bin/true"})
    assert errors == []


def test_validate_custom_binary_missing_path():
    _make_tigervnc()
    errors = vnc.VncBackend().validate({"host": "h", "custom_binary": "/no/such/binary"})
    assert any("does not exist or is not executable" in e for e in errors)


def test_validate_host_with_space():
    _make_tigervnc()
    errors = vnc.VncBackend().validate({"host": "my host", "vnc_client": "tigervnc"})
    assert any("must not contain whitespace" in e for e in errors)


# ---------------------------------------------------------------------------
# Client discovery
# ---------------------------------------------------------------------------


def test_discover_clients_auto(monkeypatch):
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer", "gvncviewer": "/usr/bin/gvncviewer"},
        {"vncviewer": "TigerVNC viewer version 1.14.0",
         "gvncviewer": "gvncviewer version 1.2.0"})
    clients = vnc._discover_vnc_clients()
    ids = [c.client_id for c in clients]
    assert "tigervnc" in ids
    assert "gvncviewer" in ids


def test_discover_no_client_found(monkeypatch):
    _make_discovery({})
    assert vnc._discover_vnc_clients() == ()


def test_discover_shared_vncviewer_requires_fingerprint(monkeypatch):
    """A shared 'vncviewer' with no version output must not be matched."""
    _make_discovery({"vncviewer": "/usr/bin/vncviewer"}, {})
    assert vnc._discover_vnc_clients() == ()


def test_discover_unique_binary_accepted_without_version(monkeypatch):
    """Uniquely-named binaries are accepted even without version output."""
    _make_discovery({"xtigervncviewer": "/usr/bin/xtigervncviewer"}, {})
    clients = vnc._discover_vnc_clients()
    assert [c.client_id for c in clients] == ["tigervnc"]


def test_discover_shared_vncviewer_resolved_by_version(monkeypatch):
    """Version fingerprinting must resolve the shared vncviewer name."""
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "RealVNC Viewer version 7.1.0"})
    clients = vnc._discover_vnc_clients()
    ids = [c.client_id for c in clients]
    assert "tigervnc" not in ids
    assert "realvnc" in ids


def test_discovery_ttl(monkeypatch):
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "TigerVNC viewer version 1.14.0"})
    now = [100.0]
    monkeypatch.setattr(vnc.time, "monotonic", lambda: now[0])

    first = vnc._discover_vnc_clients()
    assert [c.client_id for c in first] == ["tigervnc"]

    # Within the TTL the cached result is used even if PATH changes.
    vnc.shutil.which = lambda name: None
    assert vnc._discover_vnc_clients() == first

    # After the TTL the cache is refreshed.
    now[0] += vnc._DISCOVERY_TTL_SECONDS + 1
    assert vnc._discover_vnc_clients() == ()


# ---------------------------------------------------------------------------
# Client choices / fields
# ---------------------------------------------------------------------------


def test_choices_have_no_auto():
    _make_tigervnc()
    choices = vnc.VncBackend()._vnc_client_choices()
    ids = [cid for cid, _ in choices]
    assert "auto" not in ids
    assert ids[0] == "tigervnc"
    assert ids[-1] == "custom"


def test_choices_without_clients_still_offer_custom():
    _make_discovery({})
    choices = vnc.VncBackend()._vnc_client_choices()
    assert choices == [("custom", "Custom (binary path below)")]


def test_connection_fields_default_client():
    _make_tigervnc()
    fields = {f.key: f for f in vnc.VncBackend().connection_fields()}
    assert fields["vnc_client"].default == "tigervnc"
    assert fields["vnc_client"].choices[0] == ("tigervnc", "TigerVNC")
    assert fields["custom_binary"].group == "Custom"


def test_connection_fields_no_clients_no_default():
    """With no client installed the field must not default to 'custom':
    validation then shows the install-a-client warning instead."""
    _make_discovery({})
    fields = {f.key: f for f in vnc.VncBackend().connection_fields()}
    assert fields["vnc_client"].default == ""
    assert [cid for cid, _ in fields["vnc_client"].choices] == ["custom"]


def test_connection_fields_present():
    backend = vnc.VncBackend()
    fields = backend.connection_fields()
    keys = [f.key for f in fields]
    for required in ("host", "port", "display", "username", "credential",
                     "vnc_client", "view_only", "fullscreen", "shared",
                     "quality", "compress", "encoding", "color_depth",
                     "extra_args", "custom_binary"):
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
    assert groups["custom_binary"] == "Custom"


def test_connection_fields_required():
    _make_tigervnc()
    backend = vnc.VncBackend()
    fields = {f.key: f for f in backend.connection_fields()}
    assert fields["host"].required is True
    assert fields["port"].default == 5900
    assert fields["shared"].default is True


def test_connection_fields_color_depth_default():
    """24-bit is the default depth for every new connection."""
    fields = {f.key: f for f in vnc.VncBackend().connection_fields()}
    assert fields["color_depth"].default == "24"


# ---------------------------------------------------------------------------
# build_spawn() — TigerVNC
# ---------------------------------------------------------------------------


def test_build_spawn_tigervnc_basic(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/usr/bin/vncviewer"
    assert "10.0.0.1::5900" in spawn.argv[1]  # default port


def test_build_spawn_tigervnc_viewonly(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc", "view_only": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-ViewOnly" in spawn.argv


def test_build_spawn_tigervnc_fullscreen(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc", "fullscreen": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-FullScreen" in spawn.argv


def test_build_spawn_tigervnc_shared(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-Shared" in spawn.argv


def test_build_spawn_tigervnc_not_shared(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc", "shared": False})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-Shared=0" in spawn.argv
    assert "-NOShared" not in spawn.argv


def test_build_spawn_tigervnc_display(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "tigervnc", "display": 5})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert ":5" in spawn.argv[1]


def test_build_spawn_tigervnc_encoding(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc", "encoding": "Hextile"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    idx = spawn.argv.index("-PreferredEncoding")
    assert spawn.argv[idx + 1] == "Hextile"


def test_build_spawn_tigervnc_quality(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc", "quality": "7"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    idx = spawn.argv.index("-QualityLevel")
    assert spawn.argv[idx + 1] == "7"


def test_build_spawn_tigervnc_clipboard(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "tigervnc",
        "tigervnc_accept_clipboard": False, "tigervnc_send_clipboard": False})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-AcceptClipboard=0" in spawn.argv
    assert "-SendClipboard=0" in spawn.argv
    # The two-token form would leave a stray '0' positional argument.
    assert spawn.argv.count("0") == 0


def test_build_spawn_tigervnc_color_depth(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(
        _FakeConnection({"host": "h", "vnc_client": "tigervnc", "color_depth": "8"}), ctx)
    idx = spawn.argv.index("-LowColorLevel")
    assert spawn.argv[idx + 1] == "2"
    assert "-colorDepth" not in spawn.argv

    spawn = backend.build_spawn(
        _FakeConnection({"host": "h", "vnc_client": "tigervnc", "color_depth": "32"}), ctx)
    assert "-FullColor" in spawn.argv

    # 16-bit has no TigerVNC equivalent: no option should be emitted.
    spawn = backend.build_spawn(
        _FakeConnection({"host": "h", "vnc_client": "tigervnc", "color_depth": "16"}), ctx)
    assert "-colorDepth" not in spawn.argv
    assert "-LowColorLevel" not in spawn.argv


def test_build_spawn_tigervnc_extra_args(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc", "extra_args": "-Log *:debug"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-Log" in spawn.argv
    assert "*:debug" in spawn.argv


def test_build_spawn_ipv6(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "::1", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "[::1]" in spawn.argv[1]


def test_build_spawn_host_with_embedded_port(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "vnc.example.com:5901", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "::5901" in spawn.argv[1]


# ---------------------------------------------------------------------------
# build_spawn() — TurboVNC (own parameter set)
# ---------------------------------------------------------------------------


def _make_turbovnc():
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "TurboVNC viewer version 3.1.0"})


def test_build_spawn_turbovnc_flags(monkeypatch):
    _make_turbovnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "turbovnc",
        "encoding": "ZRLE", "quality": "9", "compress": "3",
        "turbovnc_geometry": "1280x720", "shared": False,
        "turbovnc_jpeg": True, "turbovnc_local": False,
        "tigervnc_accept_clipboard": False, "tigervnc_send_clipboard": False})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    argv = spawn.argv
    assert "-Encoding" in argv
    assert argv[argv.index("-Encoding") + 1] == "ZRLE"
    assert "-Quality" in argv
    assert argv[argv.index("-Quality") + 1] == "95"  # 9 -> 95
    assert "-CompressLevel" in argv
    assert "-DesktopSize" in argv
    assert argv[argv.index("-DesktopSize") + 1] == "1280x720"
    assert "-Shared=0" in argv
    assert "-JPEG=1" in argv
    assert "-LocalCursor=0" in argv
    assert "-RecvClipboard=0" in argv
    assert "-SendClipboard=0" in argv
    assert "-PreferredEncoding" not in argv  # TurboVNC has no such option


def test_build_spawn_turbovnc_colors(monkeypatch):
    _make_turbovnc()
    backend = vnc.VncBackend()
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(
        _FakeConnection({"host": "h", "vnc_client": "turbovnc", "color_depth": "24"}), ctx)
    idx = spawn.argv.index("-Colors")
    assert spawn.argv[idx + 1] == "16777216"
    spawn = backend.build_spawn(
        _FakeConnection({"host": "h", "vnc_client": "turbovnc", "color_depth": "32"}), ctx)
    assert spawn.argv[spawn.argv.index("-Colors") + 1] == "16777216"


# ---------------------------------------------------------------------------
# build_spawn() — TightVNC
# ---------------------------------------------------------------------------


def _make_tightvnc():
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "TightVNC viewer version 1.3.10"})


def test_build_spawn_tightvnc_flags(monkeypatch):
    _make_tightvnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "tightvnc",
        "view_only": True, "fullscreen": True, "shared": False,
        "encoding": "Hextile", "quality": "7", "compress": "2",
        "color_depth": "8"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    argv = spawn.argv
    assert "-viewonly" in argv
    assert "-fullscreen" in argv
    assert "-noshared" in argv
    assert argv[argv.index("-encodings") + 1] == "Hextile"
    assert argv[argv.index("-quality") + 1] == "7"
    assert argv[argv.index("-compresslevel") + 1] == "2"
    assert "-bgr233" in argv
    assert "-bcolors" not in argv  # TightVNC has no such option


def test_build_spawn_tightvnc_truecolour(monkeypatch):
    _make_tightvnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "tightvnc", "color_depth": "24"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-truecolour" in spawn.argv


# ---------------------------------------------------------------------------
# build_spawn() — RealVNC
# ---------------------------------------------------------------------------


def _make_realvnc():
    _make_discovery(
        {"vncviewer": "/usr/bin/vncviewer"},
        {"vncviewer": "RealVNC Viewer version 7.1.0"})


def test_build_spawn_realvnc_flags(monkeypatch):
    _make_realvnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "realvnc",
        "view_only": True, "fullscreen": True, "shared": True,
        "encoding": "Hextile", "quality": "7"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    argv = spawn.argv
    assert "-ViewOnly" in argv
    assert "-FullScreen" in argv
    assert "-Shared" in argv
    assert argv[argv.index("-PreferredEncoding") + 1] == "Hextile"
    # RealVNC does not expose quality/compression levels.
    assert "-QualityLevel" not in argv
    assert "-CompressLevel" not in argv


def test_build_spawn_realvnc_skips_tight_encoding(monkeypatch):
    _make_realvnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "realvnc", "encoding": "Tight"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-PreferredEncoding" not in spawn.argv


# ---------------------------------------------------------------------------
# build_spawn() — KRDC / Vinagre (vnc:// URIs, no password)
# ---------------------------------------------------------------------------


def _make_krdc():
    _make_discovery({"krdc": "/usr/bin/krdc"}, {})


def _make_vinagre():
    _make_discovery({"vinagre": "/usr/bin/vinagre"}, {})


def test_build_spawn_krdc_uri(monkeypatch):
    _make_krdc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "krdc", "port": 5905})
    ctx, secrets = make_ctx(secrets_get=lambda key: "sekret")
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[1] == "vnc://10.0.0.1:5905"
    assert "-f" not in spawn.argv
    # KRDC cannot take a password on the command line: it must not leak it.
    assert "VNC_PASSWORD" not in spawn.env
    assert not any("sekret" in a for a in spawn.argv)


def test_build_spawn_krdc_display(monkeypatch):
    _make_krdc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "krdc", "display": 3, "fullscreen": True})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[1] == "vnc://10.0.0.1:5903"
    assert "-f" in spawn.argv


def test_build_spawn_vinagre_uri(monkeypatch):
    _make_vinagre()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "10.0.0.1", "vnc_client": "vinagre", "port": 5901})
    ctx, secrets = make_ctx(secrets_get=lambda key: "sekret")
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[1] == "vnc://10.0.0.1:5901"
    assert "VNC_PASSWORD" not in spawn.env
    assert not any("sekret" in a for a in spawn.argv)


# ---------------------------------------------------------------------------
# build_spawn() — gvncviewer (no CLI options)
# ---------------------------------------------------------------------------


def _make_gvncviewer():
    _make_discovery({"gvncviewer": "/usr/bin/gvncviewer"}, {})


def test_build_spawn_gvncviewer_target_only(monkeypatch):
    """gvncviewer has no CLI flags: launch target only, prompt for password."""
    _make_gvncviewer()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "10.0.0.1", "vnc_client": "gvncviewer", "port": 5905,
        "view_only": True, "fullscreen": True, "shared": False,
        "color_depth": "8"})
    ctx, secrets = make_ctx(secrets_get=lambda key: "sekret")
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv == ["/usr/bin/gvncviewer", "10.0.0.1::5905"]
    assert "VNC_PASSWORD" not in spawn.env
    assert not any("sekret" in a for a in spawn.argv)


def test_build_spawn_gvncviewer_extra_args(monkeypatch):
    _make_gvncviewer()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "gvncviewer",
        "extra_args": "--zoom 2"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[-2:] == ["--zoom", "2"]


# ---------------------------------------------------------------------------
# build_spawn() — Remmina profile
# ---------------------------------------------------------------------------


def _make_remmina():
    _make_discovery({"remmina": "/usr/bin/remmina"}, {})


def test_build_spawn_remmina_profile(monkeypatch):
    _make_remmina()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "10.0.0.1", "vnc_client": "remmina", "port": 5905,
        "username": "bob", "fullscreen": True, "view_only": True})
    ctx, secrets = make_ctx(secrets_get=lambda key: "sekret")
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/usr/bin/remmina"
    assert spawn.argv[1] == "--connect"
    profile_path = spawn.argv[2]
    assert profile_path.startswith("/tmp/remmina-vnc-")
    content = Path(profile_path).read_text()
    assert "server=10.0.0.1:5905" in content
    assert "viewonly=1" in content
    assert "viewmode=2" in content
    assert "username=bob" in content
    assert "password=sekret" in content
    assert "protocol=VNC" in content
    assert "sekret" not in spawn.argv
    assert profile_path in vnc._TEMP_FILES


def test_build_spawn_remmina_extra_args_ignored(monkeypatch):
    _make_remmina()
    backend = vnc.VncBackend()
    conn = _FakeConnection({
        "host": "h", "vnc_client": "remmina", "extra_args": "-FullScreen"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-FullScreen" not in spawn.argv  # no argv passthrough for Remmina


# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------


def test_password_from_keyring(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx(secrets_get=lambda key: "s3cret")
    spawn = backend.build_spawn(conn, ctx)
    assert "-passwd" in spawn.argv


def test_no_password_when_absent(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert "-passwd" not in spawn.argv


def test_password_uses_tmp_file_not_argv(monkeypatch):
    """Password must appear only in a temp passwd file, never in argv directly."""
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx(secrets_get=lambda key: "my secret pass")
    spawn = backend.build_spawn(conn, ctx)
    for arg in spawn.argv:
        assert "my secret pass" not in arg


def test_password_truncated_to_8_chars(caplog, monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx(secrets_get=lambda key: "1234567890")
    with caplog.at_level(logging.WARNING):
        spawn = backend.build_spawn(conn, ctx)
    assert any("limited to 8 characters" in r.message for r in caplog.records)
    passwd_idx = spawn.argv.index("-passwd")
    content = Path(spawn.argv[passwd_idx + 1]).read_text()
    assert content == "12345678"


def test_plaintext_fallback_warns(caplog, monkeypatch):
    """Without vncpasswd the plugin must warn, not silently pass plaintext."""
    _make_tigervnc()
    vnc.shutil.which = lambda name: "/usr/bin/vncviewer" if name == "vncviewer" else None
    with caplog.at_level(logging.WARNING):
        vnc._create_passwd_file("pw")
    assert any("vncpasswd was not found" in r.message for r in caplog.records)


def test_legacy_password_migrated_to_keyring(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc", "credential": "legacy-pass"})
    ctx, secrets = make_ctx()
    backend.build_spawn(conn, ctx)
    assert secrets.calls == [("set", "vnc_password_test", "legacy-pass")]
    assert "credential" not in conn.data


def test_temp_files_cleaned_on_deactivate(monkeypatch):
    path = vnc._create_passwd_file("pw")
    assert path is not None and os.path.exists(path)
    assert path in vnc._TEMP_FILES
    vnc.Plugin().deactivate()
    assert not os.path.exists(path)
    assert path not in vnc._TEMP_FILES


# ---------------------------------------------------------------------------
# Client selection
# ---------------------------------------------------------------------------


def test_build_spawn_explicit_tigervnc(monkeypatch):
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/usr/bin/vncviewer"


def test_build_spawn_client_not_found(monkeypatch):
    _make_discovery({})
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "tigervnc"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="not installed"):
        backend.build_spawn(conn, ctx)


def test_build_spawn_no_client_found(monkeypatch):
    _make_discovery({})
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="No VNC client was found"):
        backend.build_spawn(conn, ctx)


def test_build_spawn_auto_is_an_error(monkeypatch):
    """Selecting the old 'auto' value must produce a clear error."""
    _make_tigervnc()
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "auto"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="'auto' is not installed"):
        backend.build_spawn(conn, ctx)


def test_build_spawn_custom_binary_path(monkeypatch):
    _make_discovery({})
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "custom",
                            "custom_binary": "/bin/true"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/bin/true"
    assert "h::5900" in spawn.argv[1]


def test_build_spawn_custom_binary_by_name(monkeypatch):
    def fake_which(name):
        if name == "myviewer":
            return "/opt/vnc/myviewer"
        return None
    _make_discovery({})
    vnc.shutil.which = fake_which
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "custom_binary": "myviewer"})
    ctx, _ = make_ctx()
    spawn = backend.build_spawn(conn, ctx)
    assert spawn.argv[0] == "/opt/vnc/myviewer"


def test_build_spawn_custom_binary_missing(monkeypatch):
    _make_discovery({})
    backend = vnc.VncBackend()
    conn = _FakeConnection({"host": "h", "vnc_client": "custom",
                            "custom_binary": "/no/such/binary"})
    ctx, _ = make_ctx()
    with pytest.raises(vnc.ProtocolError, match="does not exist"):
        backend.build_spawn(conn, ctx)


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


def test_flatpak_prefix_without_flatpak_spawn_warns(caplog, monkeypatch):
    monkeypatch.setattr(vnc.os.path, "exists", lambda p: p == "/.flatpak-info")
    monkeypatch.setattr(vnc.shutil, "which", lambda name: None)
    with caplog.at_level(logging.WARNING):
        assert vnc._flatpak_prefix() == ()


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


def test_vnc_uri_single_colon():
    assert vnc._vnc_uri({}, "10.0.0.1") == "vnc://10.0.0.1:5900"
    assert vnc._vnc_uri({"port": 5901}, "10.0.0.1") == "vnc://10.0.0.1:5901"
    assert vnc._vnc_uri({"display": 2}, "10.0.0.1") == "vnc://10.0.0.1:5902"
    assert vnc._vnc_uri({}, "10.0.0.1:5903") == "vnc://10.0.0.1:5903"
    assert vnc._vnc_uri({}, "[::1]") == "vnc://[::1]:5900"


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
