# VNC Pilot — SSH Pilot Plugin

A VNC protocol plugin for [SSH Pilot](https://github.com/mfat/sshpilot), modeled
after [rdp-pilot](https://github.com/SirafimsBrain/rdp-pilot). It lets you launch
VNC connections from SSH Pilot with automatic detection of the installed VNC
client and a set of shared plus client-specific settings.

## Supported clients (v0.2)

| ID        | Binaries                      | Notes                                    |
|-----------|-------------------------------|------------------------------------------|
| `tigervnc` | `vncviewer`, `xtigervncviewer` | Most common CLI client                   |
| `turbovnc` | `vncviewer`, `tvncviewer`    | High performance; own parameter set (not TigerVNC-compatible) |
| `tightvnc` | `vncviewer`, `xtightvncviewer` | Older client, still in use              |
| `realvnc` | `vncviewer`                     | Commercial; own option set              |
| `remmina` | `remmina`                       | GUI multi-protocol; launched via a temporary `.remmina` profile (Remmina ≥ 1.4) |
| `krdc`    | `krdc`                          | KDE Remote Desktop Client               |
| `vinagre` | `vinagre`                       | GNOME (being replaced by Connections)   |
| `gvncviewer` | `gvncviewer`                | gtk-vnc                                 |
| `custom`  | path from the connection form   | Arbitrary binary + raw extra args       |

### Detection

Clients are detected via **version fingerprinting**: the binary is found
through `PATH`, then `--version` / `-version` output is compared against a
whitelist of markers (e.g. `TigerVNC`, `TurboVNC`, `RealVNC`).

**Important:** the name `vncviewer` is shared by TigerVNC / TurboVNC / TightVNC
/ RealVNC. Version detection resolves the conflict, and a shared `vncviewer`
that cannot be fingerprinted is **not** silently matched to any of them.

The detection result is cached briefly; if you install a client while SSH
Pilot is running, it shows up when you next open the connection dialog.

## Choosing a client

There is **no "auto" mode** — the selection is always explicit:

1. Open a connection and pick the **VNC Client** from the dropdown. It lists
   only the clients actually installed on this system, plus **Custom**.
2. If no VNC client is installed, validation shows a clear warning listing
   the supported clients — the connection cannot be saved with a client
   until you install one or choose **Custom**.
3. **Custom** launches an arbitrary binary: enter its path (or a name found
   on `PATH`) in the **Custom binary path** field. This is a per-connection
   setting.

## Installation

```bash
# Standard installation
mkdir -p ~/.local/share/sshpilot/plugins/vnc/
cp __init__.py plugin.json ~/.local/share/sshpilot/plugins/vnc/
```

Then open SSH Pilot → **Settings → Plugins**, enable **VNC** and restart the app.

For Flatpak installations, SSH Pilot needs `flatpak-spawn` available so the
plugin can reach host-system VNC clients:

```bash
flatpak override --user --talk-name=org.freedesktop.Flatpak \
  org.mfat.sshpilot
```

## Connection fields

### Common fields (always visible)

| key           | type    | label             | default                          |
|---------------|---------|-------------------|----------------------------------|
| `host`        | text    | IP / HOSTNAME     | *(required)*                     |
| `port`        | int     | Port              | 5900                             |
| `display`     | int     | Display number    |                                  |
| `username`    | text    | Username          |                                  |
| `credential`  | password| Password          | keyring (max 8 chars)            |
| `vnc_client`  | choice  | VNC Client        | first installed client           |
| `view_only`   | switch  | View only         | off                              |
| `fullscreen`  | switch  | Fullscreen        | off                              |
| `shared`      | switch  | Shared session    | on                               |
| `quality`     | choice  | Quality / JPEG    | auto                             |
| `compress`    | choice  | Compression level | auto                             |
| `encoding`    | choice  | Preferred encoding| auto                             |
| `color_depth` | choice  | Color depth       | 24 (8/16/32 and auto available)  |
| `extra_args`  | text    | Extra CLI args    |                                  |

### Client-specific groups

Fields are grouped by client (`group="TigerVNC"`, `group="TurboVNC"`,
`group="Custom"`). Only the fields relevant to the selected `vnc_client` are
used when building the command line:

- **TigerVNC**: `-ViewOnly`, `-FullScreen`, `-Shared`/`-Shared=0`,
  `-PreferredEncoding`, `-QualityLevel` (0-9), `-CompressLevel` (0-9),
  `-LowColorLevel 2` (8-bit) / `-FullColor` (24/32-bit), `-geometry`,
  `-via`, `-AcceptClipboard=0`, `-SendClipboard=0`, `-passwd <file>`.
- **TurboVNC**: its own parameter names — `-Encoding`, `-Quality` (1-100,
  mapped from the 0-9 choice), `-CompressLevel`, `-DesktopSize`, `-Via`,
  `-RecvClipboard`, `-SendClipboard`, `-JPEG`, `-LocalCursor`, `-Colors`,
  `-passwd <file>`.
- **TightVNC**: `-viewonly`, `-fullscreen`, `-shared`/`-noshared`,
  `-encodings`, `-quality`, `-compresslevel`, `-bgr233`/`-truecolour`,
  `-passwd <file>`.
- **RealVNC**: `-ViewOnly`, `-FullScreen`, `-Shared`,
  `-PreferredEncoding` (ZRLE / Hextile / Raw only), `-via`,
  `-passwd <file>`. Quality/compression are not exposed by RealVNC.
- **Remmina** (≥ 1.4): a temporary `.remmina` profile is generated
  (`server=host:port`, `username`, `password`, `viewonly`, `quality`,
  `colordepth`, `viewmode=2` for fullscreen) and opened with
  `remmina --connect <file>`. `extra_args` has no Remmina equivalent and is
  ignored.
- **KRDC / Vinagre**: launched with a `vnc://host:port` URI. Neither client
  accepts credentials on the command line, so they will prompt for the
  password.
- **gvncviewer**: launched with a `host::port` target only. gvncviewer
  exposes no command-line options (no fullscreen/view-only/color depth and
  no password file), so it prompts for the password itself; pass any
  client-specific flags via `extra_args`.
- **Custom**: `host::port` target + raw `extra_args`; `-passwd <file>` is
  assumed TigerVNC-style (pass different flags via `extra_args`).

The `accept_clipboard` / `send_clipboard` switches (group **Display**) apply
to both TigerVNC and TurboVNC (`-AcceptClipboard=0` / `-SendClipboard=0` and
`-RecvClipboard=0` / `-SendClipboard=0` respectively). The old `tigervnc_*`
keys are still read as a fallback for connections saved before the rename.

## Passwords

- Passwords are stored **only in the SSH Pilot backend** (system keyring via
  `ctx.secrets`, key `vnc_password_<connection nickname>`) so SSH Pilot's own
  backup/import of configuration and logins keeps working. They are never
  persisted in the connection config.
- Legacy plaintext passwords previously stored under the `credential` key are
  migrated into the keyring on first use and removed from the config.
- At launch, a temporary password file (`vncpasswd -f` format, mode `0600`)
  is passed to CLI clients that support it. The file is removed when SSH
  Pilot exits or the plugin is disabled.
- VNC protocol authentication is limited to **8 characters**; longer
  passwords are truncated with a warning.
- If `vncpasswd` is not installed (or fails to convert), the plugin does not
  pass a plain-text file — the standard viewers would reject it with a
  confusing "password incorrect" error. Instead it logs a warning with
  install instructions (e.g. `sudo apt install tigervnc-common` or
  `sudo dnf install tigervnc`) and the viewer prompts for the password
  manually.

## Limitations (v0.2)

- **Window title:** not all clients support setting a window title. Remmina
  uses the connection name as the profile name; TigerVNC/TurboVNC/TightVNC
  have no standard flag.
- **Static fields:** `connection_fields()` returns a static list. Hiding
  irrelevant groups in the UI is a nice-to-have for a later version if a
  stable SDK hook becomes available.
- **RealVNC:** commercial with licensing restrictions. Basic support is
  included; advanced options are deferred.
- **Remmina profile format** is best-effort against Remmina ≥ 1.4; some
  Remmina versions store passwords in the secret service and may prompt
  instead of using the profile value.

## Tests

```bash
cd "/path/to/vnc-pilot"
python3 -m pytest tests/ -v
```

## License

MIT. See [LICENSE](LICENSE).
