# VNC Pilot — SSH Pilot Plugin

A VNC protocol plugin for [SSH Pilot](https://github.com/mfat/sshpilot), modeled
after [rdp-pilot](https://github.com/SirafimsBrain/rdp-pilot). It lets you launch
VNC connections from SSH Pilot with automatic detection of the installed VNC
client and a set of shared plus client-specific settings.

## Supported clients (v0.1)

| ID        | Binaries                      | Notes                                    |
|-----------|-------------------------------|------------------------------------------|
| `tigervnc` | `vncviewer`, `xtigervncviewer` | Most common CLI client                   |
| `turbovnc` | `vncviewer`, `tvncviewer`    | High performance; CLI similar to TigerVNC |
| `tightvnc` | `vncviewer`, `xtightvncviewer` | Older client, still in use              |
| `realvnc` | `vncviewer`                     | Commercial; different CLI               |
| `remmina` | `remmina`                       | GUI multi-protocol; launched via `.remmina` profile file |
| `krdc`    | `krdc`                          | KDE Remote Desktop Client               |
| `vinagre` | `vinagre`                       | GNOME (being replaced by Connections)   |
| `gvncviewer` | `gvncviewer`                | gtk-vnc                                 |
| `custom`  | path from `VNC_PILOT_BIN`       | Arbitrary binary + raw extra args       |

### Detection

All clients are detected via **version fingerprinting**: the binary is found
through `PATH`, then `--version` / `-version` output is compared against a
whitelist of markers (e.g. `TigerVNC`, `TurboVNC`, `RealVNC`).

**Important:** the name `vncviewer` is shared by TigerVNC / TurboVNC / TightVNC
/ RealVNC. Version detection resolves the conflict.

## Environment variables

| Variable        | Description                                              |
|-------------------|-------------------------------------------------------|
| `VNC_PILOT_BIN`   | Path to a custom VNC client (overrides auto-detection) |
| `VNC_PILOT_CLIENT`| Force a specific client from the whitelist            |

## Installation

```bash
# Standard installation
mkdir -p ~/.local/share/sshpilot/plugins/vnc/
cp __init__.py plugin.json ~/.local/share/sshpilot/plugins/vnc/

# Flatpak (if SSH Pilot runs as a Flatpak)
flatpak override --user --talk-name=org.freedesktop.Flatpak \
  org.mfat.sshpilot
```

## Connection fields

### Common fields (always visible)

| key           | type    | label             | default     |
|---------------|---------|-------------------|-------------|
| `host`        | text    | IP / HOSTNAME     | *(required)*|
| `port`        | int     | Port              | 5900        |
| `display`     | int     | Display number    |             |
| `username`    | text    | Username          |             |
| `credential`  | password| Password          | keyring     |
| `vnc_client`  | choice  | VNC Client        | auto        |
| `view_only`   | switch  | View only         | off         |
| `fullscreen`  | switch  | Fullscreen        | off         |
| `shared`      | switch  | Shared session    | on          |
| `quality`     | choice  | Quality / JPEG    | auto        |
| `compress`    | choice  | Compression level | auto        |
| `encoding`    | choice  | Preferred encoding| auto        |
| `color_depth` | choice  | Color depth       | auto        |
| `extra_args`  | text    | Extra CLI args    |             |

### Client-specific groups

Fields are grouped by client (`group="TigerVNC"`, `group="TurboVNC"`,
`group="Remmina"`, `group="Custom"`). **Fields from other client groups are
ignored** when building `argv` — only the fields relevant to the selected
`vnc_client` are used.

## Limitations (v0.1)

- **Window title:** not all clients support setting a window title. Remmina
  uses the connection nickname as the profile name; TigerVNC/TurboVNC/TightVNC
  have no standard flag.
- **Password:** VNC clients rarely accept a password via `argv`. The plugin
  creates a temporary passwd file with `chmod 0o600` and removes it via `atexit`.
- **Static fields:** `connection_fields()` returns a static list. Hiding
  irrelevant groups in the UI is a nice-to-have for v0.2 if a stable SDK hook
  becomes available.
- **RealVNC:** commercial with licensing restrictions. Basic support is
  included; advanced options are deferred to v0.2.

## Tests

```bash
cd "/path/to/vnc-pilot"
python3 -m pytest tests/ -v
```

## License

MIT. See [LICENSE](LICENSE).
