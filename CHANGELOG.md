# Changelog

The latest release only. Every earlier version:
[GitHub Releases](https://github.com/rendyuwu/tervia/releases). Versions:
[SemVer](https://semver.org/); before `1.0` a minor bump may break things.

## [0.1.2] - 27-09-2026

### Added

- Drag a file from the local Files explorer onto the Remote tree to upload it: onto a folder, onto a file for that file's folder, or onto empty tree space for the root. A drag never replaces an existing remote file; OS drop and paste still do.

### Changed

- A remote file dragged onto the local Files explorer can also land on a file row (its folder) or on empty tree space (the root), not only on a folder row.

### Fixed

- omp and other programs that briefly open the alternate screen on every resize no longer flicker nonstop after an overlay closes or the pane is resized, locally or over SSH. After leaving the alternate screen, only a detected AI CLI gets a resize nudge.
