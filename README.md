# XMPP Utilities

XMPP Utilities is a simple XMPP bot that provides various diagnostic and informational tools for XMPP entities and domains. It can be used to check software versions, service items, contact information, uptime, and more.

## Features

The bot responds to commands prefixed with `!xmpp` in both direct messages and configured Multi-User Chats (MUCs).

### Available Commands

- `!xmpp help` - Displays the help message with all available commands.
- `!xmpp version <jid>` - Shows the software version of an XMPP entity (XEP-0092).
- `!xmpp items <jid>` - Lists the service items of an XMPP entity (XEP-0030).
- `!xmpp contact <jid>` - Displays contact information for an XMPP entity (XEP-0030).
- `!xmpp info <jid>` - Lists the identities and features of an XMPP entity (XEP-0030).
- `!xmpp ping <jid>` - Pings an XMPP entity and reports the round-trip time (XEP-0199).
- `!xmpp uptime <jid>` - Shows the uptime of an XMPP entity (XEP-0012).
- `!xmpp srv <domain>` - Performs DNS SRV lookups for XMPP services (`_xmpp-client`, `_xmpp-server`, etc.).
- `!xmpp compliance <domain>` - Shows the compliance score of a server from [compliance.conversations.im](https://compliance.conversations.im/).

## Configuration

The bot is configured using environment variables. You can copy `.env.example` to `.env` and fill in your details:

```bash
cp .env.example .env
# Edit .env with your credentials
```

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `XMPP_UTILS_JID` | The JID of the bot account (e.g., `bot@example.com`). | Yes | - |
| `XMPP_UTILS_PASSWORD` | The password for the bot account. | Yes | - |
| `XMPP_UTILS_MUCS` | A comma-separated list of MUC JIDs to join. | Yes | - |
| `XMPP_UTILS_NICK` | The nickname to use in MUCs. | No | `XMPP utilities` |

## Getting Started

### Prerequisites

- Python 3.13 or newer
- [uv](https://github.com/astral-sh/uv) (recommended for dependency management)

### Running locally

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/xmpp-utilities.git
   cd xmpp-utilities
   ```

2. Install dependencies:
   ```bash
   uv sync
   ```

3. Set the environment variables and run the bot:
   ```bash
   export XMPP_UTILS_JID="your-jid@example.com"
   export XMPP_UTILS_PASSWORD="your-password"
   export XMPP_UTILS_MUCS="room@conference.example.com"
   uv run main.py
   ```

## Deployment

### Container (Docker/Podman)

A container image is available for this project.

```bash
podman run -d \
  --name xmpp-utilities \
  -e XMPP_UTILS_JID="your-jid@example.com" \
  -e XMPP_UTILS_PASSWORD="your-password" \
  -e XMPP_UTILS_MUCS="room@conference.example.com" \
  foundry.fsky.io/telepath/xmpp-utilities
```

### Systemd Quadlet

A Quadlet file is available at `contrib/quadlet/xmpp-utilities.container`. You can use it to manage the container via systemd.

Edit the file to suit your needs, place it into `~/.config/containers/systemd/` or `/etc/containers/systemd/`, and run:

```bash
systemctl --user daemon-reload
systemctl --user start xmpp-utilities
```

## License

This project is released into the public domain under the [Unlicense](LICENSE).
