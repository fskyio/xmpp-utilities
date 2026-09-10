# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-09-10

### Added

- [XEP-0050](https://xmpp.org/extensions/xep-0050.html) ad-hoc commands for the same diagnostics as `!xmpp` text commands, run against the bot's full JID.
- TOML configuration file support (`xmpp-utilities.toml`, `--config` / `-c`, or `XMPP_UTILS_CONFIG`), with `XMPP_UTILS_*` environment variables overlaid on top.
- Optional MUC invites (direct [XEP-0249](https://xmpp.org/extensions/xep-0249.html) and mediated), with ACL options for who may invite the bot and which conference hosts it may join.
- Service discovery identity advertising the account as a bot, and software version via [XEP-0092](https://xmpp.org/extensions/xep-0092.html).
- Avatar and vCard on the bot account.

### Fixed

- OCI image builds by including `README.md`, `LICENSE`, and the `src/` layout expected by the package build.

## [1.2.0] - 2026-09-08

### Added

- `!xmpp xep` (or `!xep`) command for looking up XEPs.
- `!xmpp tlsa` (or `!xmpp dane`) command for looking up and validating a server's TLSA records.
- `!xmpp about` command showing information about the bot.
- `!xmpp` with no arguments, showing a short summary of the bot including its version.

### Changed

- Updated project page and repository URLs.
- Relicensed the project from The Unlicense to [0BSD](https://opensource.org/license/0bsd).

## [1.1.0] - 2026-04-23

### Added

- Packaging for installation from PyPI and FSKY Foundry (`pip` / `pipx`), including an `xmpp-utilities` console script.

### Changed

- `XMPP_UTILS_MUCS` is now optional, so the bot can run without joining any rooms.
- Default MUC nickname is now `XMPP Utilities`.

### Fixed

- Event loop setup so the bot starts correctly under current Python versions.
- Minor command-handling and DNS lookup issues.

## [1.0.0] - 2026-03-23

### Added

- Initial release of the XMPP diagnostic bot.
- `!xmpp` commands for help, software version, service items, contact information, identities and features, ping, uptime, SRV lookups, and Conversations compliance scores.
- MUC support via configured room JIDs.
- Container image and a systemd Quadlet unit.

[unreleased]: https://foundry.fsky.io/fsky/xmpp-utilities/compare/1.3.0...HEAD
[1.3.0]: https://foundry.fsky.io/fsky/xmpp-utilities/compare/1.2.0...HEAD
[1.2.0]: https://foundry.fsky.io/fsky/xmpp-utilities/compare/1.1.0...1.2.0
[1.1.0]: https://foundry.fsky.io/fsky/xmpp-utilities/compare/1.0.0...1.1.0
[1.0.0]: https://foundry.fsky.io/fsky/xmpp-utilities/releases/tag/1.0.0
