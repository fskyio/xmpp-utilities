# XMPP Utilities

XMPP Utilities is a simple XMPP bot that provides various diagnostic and informational tools for XMPP entities and domains. It can be used to check software versions, service items, contact information, uptime, and more.

## Features

The bot responds to `!xmpp` commands in both direct
messages and configured Multi-User Chats (MUCs).

### Available Commands

- `!xmpp help` - Displays the help message with all available commands.
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

The TLSA lookup follows each XMPP SRV record and queries the TLSA name derived
from its target and port, as specified by
[RFC 7673](https://www.rfc-editor.org/rfc/rfc7673.html). It covers client and
server connections using either STARTTLS or direct TLS (XEP-0368). It connects
to each public endpoint and checks its certificate against usable TLSA records
by default; add `--no-validate` for a DNS-only lookup. DNSSEC results come from
the bot's configured validating resolver.

## Configuration

The bot is configured using environment variables. You can copy `.env.example` to `.env` and fill in your details:

```sh
cp .env.example .env
# Edit .env with your credentials
```

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `XMPP_UTILS_JID` | The JID of the bot account (e.g., `bot@example.com`). | Yes | - |
| `XMPP_UTILS_PASSWORD` | The password for the bot account. | Yes | - |
| `XMPP_UTILS_MUCS` | A comma-separated list of MUC JIDs to join. | No | - |
| `XMPP_UTILS_NICK` | The nickname to use in MUCs. | No | `XMPP Utilities` |

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

After installing, set the environment variables and run the bot:

```sh
export XMPP_UTILS_JID="xmpp-utilities@telepath.im"
export XMPP_UTILS_PASSWORD="your-password"
xmpp-utilities
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

3. Set the environment variables and run the bot:
   ```sh
   export XMPP_UTILS_JID="xmpp-utilities@telepath.im"
   export XMPP_UTILS_PASSWORD="your-password"
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

This project is released into the public domain under the [Unlicense](LICENSE).
