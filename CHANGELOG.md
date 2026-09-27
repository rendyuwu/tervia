# Changelog

The latest release only. Every earlier version:
[GitHub Releases](https://github.com/rendyuwu/tervia/releases). Versions:
[SemVer](https://semver.org/); before `1.0` a minor bump may break things.

## [0.1.1] - 27-09-2026

### Added

**SFTP**

- Download a remote file from its context menu (save dialog), or drag its row onto a folder in the local Files explorer. Up to 256 MiB.
- Move remote files and folders by dragging them onto another remote folder, or onto empty tree space for the root. Open editor tabs follow the new path.
- Paste files copied in the OS file manager into the Remote tree to upload them: Paste in the context menu uploads into the folder under the cursor, `Ctrl+V` (`Cmd+V` on macOS) into the selected folder.

**Terminal**

- Copies from tmux, vim and other programs that use OSC 52 reach the system clipboard, local or over SSH. Clipboard reads are never answered, and copies over 1 MiB are dropped.
- macOS: `Option`+drag selects text inside programs that use the mouse (tmux, vim, htop), as `Shift`+drag does on Linux and Windows.

### Changed

- A row in the Files or Remote tree dims and shows "Deleting…" until its delete finishes.

### Fixed

- Deleting a remote folder with contents removes it and everything inside, instead of silently doing nothing. Symlinks inside are removed as links and their targets are left alone. A failed delete shows a toast.
- A terminal selection is copied wherever the mouse button is released: past the end of a line, below the pane while autoscrolling, or on the pane padding.
