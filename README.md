# VNC Pilot — SSH Pilot Plugin

Визуальное расширение плагина rdp-pilot для протокола VNC. Позволяет запускать
VNC-соединения из SSH Pilot с выбором установленного в системе VNC-клиента и
набором общих + клиент-специфичных настроек.

## Поддерживаемые клиенты (v0.1)

| ID        | Бинарники                         | Комментарий                                  |
|-----------|-----------------------------------|----------------------------------------------|
| `tigervnc` | `vncviewer`, `xtigervncviewer`   | Самый распространённый CLI-клиент            |
| `turbovnc` | `vncviewer`, `tvncviewer`        | Высокая производительность                   |
| `tightvnc` | `vncviewer`, `xtightvncviewer`   | Старый, но всё ещё встречается               |
| `realvnc` | `vncviewer`                       | Коммерческий; CLI отличается                 |
| `remmina` | `remmina`                         | GUI-мультипротокол; запуск через `.remmina`-файл |
| `krdc`    | `krdc`                            | KDE Remote Desktop Client                    |
| `vinagre` | `vinagre`                         | GNOME (устаревает в пользу Connections)      |
| `gvncviewer` | `gvncviewer`                   | gtk-vnc                                      |
| `custom`  | путь из `VNC_PILOT_BIN`           | Произвольный бинарь + raw extra args         |

### Детекция

Для всех клиентов используется **версионный fingerprint**: бинарник ищется по
`PATH`, затем выполняется `--version` / `-version` и результат сопоставляется с
белым списком маркеров (например, `TigerVNC`, `TurboVNC`, `RealVNC`).

**Важно:** имя `vncviewer` конфликтует между TigerVNC / TurboVNC / TightVNC /
RealVNC. Детекция по версии разрешает конфликт.

## Переменные окружения

| Переменная        | Описание                                              |
|-------------------|-------------------------------------------------------|
| `VNC_PILOT_BIN`   | Путь к пользовательскому VNC-клиенту (переопределяет авто-детекцию) |
| `VNC_PILOT_CLIENT`| ID клиента из whitelist для форсированного выбора     |

## Установка

```bash
# Обычная установка
mkdir -p ~/.local/share/sshpilot/plugins/vnc/
cp __init__.py plugin.json ~/.local/share/sshpilot/plugins/vnc/

# Flatpak-путь (если SSH Pilot запущен в Flatpak)
flatpak override --user --talk-name=org.freedesktop.Flatpak \
  org.mfat.sshpilot
```

## Поля подключения

### Общие (всегда видны)

| key           | тип     | label             | по умолчанию |
|---------------|---------|-------------------|--------------|
| `host`        | text    | IP / HOSTNAME     | (обязательно)|
| `port`        | int     | Port              | 5900         |
| `display`     | int     | Display number    |              |
| `username`    | text    | Username          |              |
| `credential`  | password| Password          | keyring      |
| `vnc_client`  | choice  | VNC Client        | auto         |
| `view_only`   | switch  | View only         | выкл.        |
| `fullscreen`  | switch  | Fullscreen        | выкл.        |
| `shared`      | switch  | Shared session    | вкл.         |
| `quality`     | choice  | Quality / JPEG    | auto         |
| `compress`    | choice  | Compression level | auto         |
| `encoding`    | choice  | Preferred encoding| auto         |
| `color_depth` | choice  | Color depth       | auto         |
| `extra_args`  | text    | Extra CLI args    |              |

### Клиент-специфичные группы

Поля сгруппированы по клиенту (`group="TigerVNC"`, `group="TurboVNC"`,
`group="Remmina"`, `group="Custom"`). **Поля групп других клиентов
игнорируются** при сборке argv — используются только поля для выбранного
`vnc_client`.

## Ограничения (v0.1)

- **Window title:** не все клиенты поддерживают задание заголовка окна.
  Remmina использует `nickname` как имя профиля; TigerVNC/TurboVNC/TightVNC —
  нет стандартного флага.
- **Пароль:** VNC-клиенты не принимают пароль в argv. Плагин создаёт временный
  passwd-файл с `chmod 0o600` и удаляет его через `atexit`.
- **Динамические поля:** `connection_fields()` возвращает статический список.
  Скрытие нерелевантных групп в UI — nice-to-have в v0.2 при наличии хука.
- **RealVNC:** коммерческий, лицензионные ограничения. Базовая поддержка
  добавлена, продвинутые опции — в v0.2.

## Тесты

```bash
cd "/DISK1/projects/sshpilot_plugin/VNC Pilot"
python3 -m pytest tests/ -v
```

## Лицензия

MIT. См. [LICENSE](LICENSE).
