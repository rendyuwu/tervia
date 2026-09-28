# Changelog

The latest release only. Every earlier version:
[GitHub Releases](https://github.com/rendyuwu/tervia/releases). Versions:
[SemVer](https://semver.org/); before `1.0` a minor bump may break things.

## [0.1.3] - 28-09-2026

### Added

- In an SSH session, the status bar can show live Linux host CPU, RAM, network, disk I/O, root filesystem usage, uptime and local ping. Its visibility choice is remembered across launches. Contributed by @okkinurf.

### Fixed

- A terminal pane's column count now matches its width after the renderer changes (the App opacity crossing the glass edge, turning the WebGL setting off or on, a lost GPU context) or the window moves to a display with another scale. Text no longer runs past the pane's right edge, typing near the edge no longer scrolls the pane sideways, and a new pane no longer starts a few columns narrower than it is.
