# XMPP Utilities

XMPP Utilities is a simple XMPP bot that provides various diagnostic and informational tools for XMPP entities and domains. It can be used to check software versions, service items, contact information, uptime, and more.

## Features

The bot responds to `!xmpp` commands in both direct
messages and Multi-User Chats (MUCs). Rooms can be listed
in config and, if invites are enabled, the bot will also
join rooms it is invited to. Invited rooms are remembered
as PEP bookmarks on the bot account (XEP-0402). The same
diagnostics are also available as [XEP-0050](https://xmpp.org/extensions/xep-0050.html)
ad-hoc commands on the bot's full JID.

### Available Commands

- `!xmpp` - Shows a short summary of the bot, including its version.
- `!xmpp help` - Displays the help message with all available commands.
- `!xmpp about` - Shows the bot's version, project links, and license.
- `!xmpp version <jid>` - Shows the software version of an XMPP entity (XEP-0092).
- `!xmpp items <jid>` - Lists the service items of an XMPP entity (XEP-0030).
- `!xmpp contact <jid>` - Displays contact information for an XMPP entity (XEP-0030).
- `!xmpp info <jid>` - Lists the identities and features of an XMPP entity (XEP-0030).
- `!xmpp ping <jid>` - Pings an XMPP entity and reports the round-trip time (XEP-0199).
- `!xmpp uptime <jid>` - Shows the uptime of an XMPP entity (XEP-0012).
- `!xmpp srv <domain>` - Performs DNS SRV lookups for XMPP services (`_xmpp-client`, `_xmpp-server`, etc.).
- `!xmpp tlsa <domain> [--no-validate]` - Shows and validates DANE TLSA records for the domain's XMPP endpoints. `!xmpp dane` is an alias.
- `!xmpp compliance <domain>` - Shows the compliance score of a server from [compliance.conversations.im](https://compliance.conversations.im/).
- `!xmpp xep <number>` - Shows the title, abstract, authors, status, type, and link for an XMPP Extension Protocol. The shorter `!xep <number>` alias also works.

The XEP lookup accepts common number formats such as `516`, `0516`, `XEP516`,
`XEP-516`, and `XEP-0516`. Its title uses XEP-0393 strong-emphasis formatting.

Clients that support ad-hoc commands can run the same lookups from a form
instead of typing `!xmpp` commands. Execute the command against the bot's
full JID (including resource). `!xmpp dane` is only a text alias; the ad-hoc
command is `tlsa`. `help` is omitted because service discovery already lists
the available commands.

The TLSA lookup follows each XMPP SRV record and queries the TLSA name derived
from its target and port, as specified by
[RFC 7673](https://www.rfc-editor.org/rfc/rfc7673.html). It covers client and
server connections using either STARTTLS or direct TLS (XEP-0368). It connects
to each public endpoint and checks its certificate against usable TLSA records
by default; add `--no-validate` for a DNS-only lookup. DNSSEC results come from
the bot's configured validating resolver.

## Configuration

The bot reads a TOML config file, then overlays any `XMPP_UTILS_*`
environment variables that are set. Env values win.

Copy the example and edit it:

```sh
cp config.example.toml xmpp-utilities.toml
# Edit xmpp-utilities.toml with your credentials
```

```toml
jid = "xmpp-utilities@telepath.im"
password = "your-password"
nick = "XMPP Utilities"
mucs = [
  "offtopic@room.telepath.im",
  "bot-testing@room.telepath.im",
]

[invite]
enabled = false
persist = true
# max_rooms = 32
# allow_from = ["alice@example.org"]
# allow_domains = ["example.org"]
# deny_from = []
# allow_muc_hosts = ["room.telepath.im"]
```

The file is resolved in this order:

1. `--config PATH` / `-c PATH`
2. `XMPP_UTILS_CONFIG`
3. `./xmpp-utilities.toml` if that file exists
4. Environment variables only

`jid` and `password` are required after that merge. Prefer
`XMPP_UTILS_PASSWORD` over storing a password in the file.

| TOML | Environment | Description | Required | Default |
|------|-------------|-------------|----------|---------|
| `jid` | `XMPP_UTILS_JID` | The JID of the bot account (e.g., `bot@example.com`). | Yes | - |
| `password` | `XMPP_UTILS_PASSWORD` | The password for the bot account. | Yes | - |
| `mucs` | `XMPP_UTILS_MUCS` | MUC JIDs to join. TOML uses an array; the env var is comma-separated. These rooms are always joined and are not stored as bookmarks. | No | - |
| `nick` | `XMPP_UTILS_NICK` | The nickname to use in MUCs. | No | `XMPP Utilities` |
| `invite.enabled` | `XMPP_UTILS_INVITE_ENABLED` | Accept direct (XEP-0249) and mediated MUC invites. | No | `false` |
| `invite.persist` | `XMPP_UTILS_INVITE_PERSIST` | Remember invited rooms as PEP bookmarks (XEP-0402) on the bot account. | No | `true` |
| `invite.max_rooms` | `XMPP_UTILS_INVITE_MAX_ROOMS` | Cap on invited/bookmarked rooms. Omitted means unlimited. | No | unlimited |
| `invite.allow_from` | `XMPP_UTILS_INVITE_ALLOW_FROM` | Inviter bare JIDs that may invite the bot. Empty with no domain list means anyone. | No | - |
| `invite.allow_domains` | `XMPP_UTILS_INVITE_ALLOW_DOMAINS` | Inviter domains that may invite the bot. | No | - |
| `invite.deny_from` | `XMPP_UTILS_INVITE_DENY_FROM` | Inviter bare JIDs that are always refused. | No | - |
| `invite.allow_muc_hosts` | `XMPP_UTILS_INVITE_ALLOW_MUC_HOSTS` | Conference hosts the bot may be invited into. Empty means any host. | No | - |
| — | `XMPP_UTILS_CONFIG` | Path to a TOML config file. | No | `./xmpp-utilities.toml` |

Boolean env values accept `true`/`false`, `1`/`0`, `yes`/`no`, and `on`/`off`. List env vars are comma-separated.

When invites are enabled, use a dedicated bot account. Invited rooms persist as account bookmarks, so a container does not need a volume to rejoin them after restart. A kick or ban unbookmarks the room; a new invite joins it again. Configured `mucs` are never written to PEP.

## Requirements

- Python 3.13+
- slixmpp
- dnspython with its DNSSEC dependencies

## Installation

### pip/pipx (PyPI)

You can install XMPP Utilities from PyPI with pip:

```sh
pip install xmpp-utilities
```

Or with pipx for an isolated environment:

```sh
pipx install xmpp-utilities
```

### pip/pipx (FSKY Foundry)

To download the package from FSKY Foundry instead of PyPI:

```sh
pip install xmpp-utilities --pip-args="--index-url https://foundry.fsky.io/api/packages/fsky/pypi/simple --extra-index-url https://pypi.org/simple"
```

Or with pipx:

```sh
pipx install xmpp-utilities --pip-args="--index-url https://foundry.fsky.io/api/packages/fsky/pypi/simple --extra-index-url https://pypi.org/simple"
```

### From wheel

Download the wheel from the [releases page](https://foundry.fsky.io/fsky/xmpp-utilities/releases) and install with pip:

```sh
pip install xmpp_utilities-*.whl
```

## Running

### Installed package

After installing, create a config file and run the bot:

```sh
cp config.example.toml xmpp-utilities.toml
# Edit xmpp-utilities.toml
xmpp-utilities
```

Or point at a file elsewhere:

```sh
xmpp-utilities --config /etc/xmpp-utilities.toml
```

Environment variables still work, including as an overlay for secrets:

```sh
export XMPP_UTILS_PASSWORD="your-password"
xmpp-utilities --config /etc/xmpp-utilities.toml
```

### Local development

Requires [uv](https://github.com/astral-sh/uv).

1. Clone the repository:
   ```sh
   git clone https://foundry.fsky.io/fsky/xmpp-utilities.git
   cd xmpp-utilities
   ```

2. Install dependencies:
   ```sh
   uv sync
   ```

3. Create a config file and run the bot:
   ```sh
   cp config.example.toml xmpp-utilities.toml
   # Edit xmpp-utilities.toml
   uv run xmpp-utilities
   ```

### Container (Docker/Podman)

A container image is available for this project.

```sh
podman run -d \
  --name xmpp-utilities \
  -e XMPP_UTILS_JID="xmpp-utilities@telepath.im" \
  -e XMPP_UTILS_PASSWORD="your-password" \
  foundry.fsky.io/fsky/xmpp-utilities:latest
```

### Systemd Quadlet

A Quadlet file is available at `contrib/quadlet/xmpp-utilities.container`. You can use it to manage the container via systemd.

Edit the file to suit your needs, place it into `~/.config/containers/systemd/` or `/etc/containers/systemd/`, and run:

```sh
systemctl --user daemon-reload
systemctl --user start xmpp-utilities
```

## License

This project is licensed under the [Zero-Clause BSD License (0BSD)](LICENSE).
