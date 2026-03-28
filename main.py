import asyncio
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import dns.asyncresolver
import dns.resolver
import slixmpp
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.plugins.xep_0004.stanza import Form

LOGGER = logging.getLogger(__name__)
COMMAND_PREFIX = "!xmpp"


@dataclass(frozen=True)
class AppConfig:
    jid: str
    password: str
    muc_jids: tuple[str, ...]
    nick: str

    @classmethod
    def from_env(cls) -> "AppConfig":
        jid = os.getenv("XMPP_UTILS_JID", "").strip()
        password = os.getenv("XMPP_UTILS_PASSWORD", "").strip()
        raw_mucs = os.getenv("XMPP_UTILS_MUCS", "")
        nick = (
            os.getenv("XMPP_UTILS_NICK", "XMPP utilities").strip() or "XMPP utilities"
        )

        muc_jids = [muc.strip() for muc in raw_mucs.split(",") if muc.strip()]

        missing = []
        if not jid:
            missing.append("XMPP_UTILS_JID")
        if not password:
            missing.append("XMPP_UTILS_PASSWORD")
        if not muc_jids:
            missing.append("XMPP_UTILS_MUCS")

        if missing:
            raise ValueError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        return cls(jid=jid, password=password, muc_jids=tuple(muc_jids), nick=nick)


class XMPPUtilities(slixmpp.ClientXMPP):
    CONTACT_FIELDS = {
        "abuse-addresses",
        "admin-addresses",
        "feedback-addresses",
        "sales-addresses",
        "security-addresses",
        "status-addresses",
        "support-addresses",
    }

    def __init__(self, jid: str, password: str, muc_jids: tuple[str, ...], nick: str) -> None:
        super().__init__(jid, password)
        self.muc_jids = muc_jids
        self.nick = nick
        self._shutdown_requested = False
        self._resolver = dns.asyncresolver.Resolver()

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("groupchat_message", self.muc_message)
        self.add_event_handler("message", self.dm_message)
        self.add_event_handler("disconnected", self.on_disconnected)

        self.register_plugin("xep_0004")
        self.register_plugin("xep_0012")
        self.register_plugin("xep_0030")
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0092")
        self.register_plugin("xep_0199")

        self.commands: dict[str, Callable[[str | None], Awaitable[str]]] = {
            "help": self.cmd_help,
            "version": self.cmd_version,
            "items": self.cmd_items,
            "contact": self.cmd_contact,
            "info": self.cmd_info,
            "ping": self.cmd_ping,
            "uptime": self.cmd_uptime,
            "srv": self.cmd_srv,
            "compliance": self.cmd_compliance,
        }

    def request_shutdown(self) -> None:
        self._shutdown_requested = True

    def on_disconnected(self, reason: object) -> None:
        if self._shutdown_requested:
            LOGGER.info("Disconnected during shutdown: %s", reason)
            return
        if self.is_connecting():
            return
        LOGGER.warning("Disconnected from XMPP server (%s), reconnecting", reason)
        self.connect()

    async def start(self, _event: object) -> None:
        self.send_presence()
        await self.get_roster()
        for muc_jid in self.muc_jids:
            LOGGER.info("Joining MUC: %s", muc_jid)
            self.plugin["xep_0045"].join_muc(muc_jid, self.nick)

    async def muc_message(self, msg: slixmpp.Message) -> None:
        body = (msg["body"] or "").strip()
        if msg["mucnick"] == self.nick or not body.startswith(COMMAND_PREFIX):
            return

        response = await self.handle_command(body)
        self.send_message(mto=msg["from"].bare, mbody=response, mtype="groupchat")

    async def dm_message(self, msg: slixmpp.Message) -> None:
        body = (msg["body"] or "").strip()
        if msg["type"] not in ("chat", "normal") or not body.startswith(COMMAND_PREFIX):
            return

        response = await self.handle_command(body)
        msg.reply(response).send()

    async def handle_command(self, body: str) -> str:
        command, argument = self.parse_command(body)
        if not command:
            return f'Use "{COMMAND_PREFIX} help" to list all commands.'

        handler = self.commands.get(command)
        if handler is None:
            return f'Unknown command. Use "{COMMAND_PREFIX} help" to list all commands.'

        return await handler(argument)

    @staticmethod
    def parse_command(body: str) -> tuple[str | None, str | None]:
        parts = body.strip().split(maxsplit=2)
        if len(parts) < 2:
            return None, None
        command = parts[1].strip().lower()
        argument = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        return command, argument

    async def cmd_help(self, _argument: str | None) -> str:
        return (
            "Available commands:\n"
            f"{COMMAND_PREFIX} version <jid> - shows the version of an XMPP entity.\n"
            f"{COMMAND_PREFIX} items <jid> - shows the items of an XMPP entity.\n"
            f"{COMMAND_PREFIX} contact <jid> - shows the contact information of an XMPP entity.\n"
            f"{COMMAND_PREFIX} info <jid> - shows the identities and features of an XMPP entity.\n"
            f"{COMMAND_PREFIX} ping <jid> - pings an XMPP entity and reports the round-trip time.\n"
            f"{COMMAND_PREFIX} uptime <jid> - shows the uptime of an XMPP entity.\n"
            f"{COMMAND_PREFIX} srv <domain> - performs DNS SRV lookups for XMPP services.\n"
            f"{COMMAND_PREFIX} compliance <domain> - shows the compliance score of a server.\n"
            f"{COMMAND_PREFIX} help - displays this message."
        )

    async def cmd_version(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} version - shows the version of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} version <jid>"
            )

        try:
            iq = await self.plugin["xep_0092"].get_version(argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Version lookup failed for %s: %s", argument, exc)
            return f"Could not retrieve version for {argument}: {exc}"

        software_version = iq["software_version"]
        name = software_version["name"] or "unknown"
        version = software_version["version"] or "unknown"
        os_name = software_version["os"]

        if os_name:
            return f"{argument} is running {name} {version} on {os_name}."
        return f"{argument} is running {name} {version}."

    async def cmd_items(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} items - shows the items of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} items <jid>"
            )

        try:
            items = await self.get_service_items(argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Items lookup failed for %s: %s", argument, exc)
            return f"Could not retrieve items for {argument}: {exc}"

        if not items:
            return f"No items found for service {argument}."

        lines = [f"Items for service {argument}:"]
        for item in items:
            name = item.get("name")
            jid = item.get("jid", "unknown")
            lines.append(f"{jid} - {name}" if name else str(jid))
        return "\n".join(lines)

    async def cmd_contact(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} contact - shows the contact information of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} contact <jid>"
            )

        try:
            iq = await self.plugin["xep_0030"].get_info(jid=argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Contact lookup failed for %s: %s", argument, exc)
            return f"Could not retrieve contact information for {argument}: {exc}"

        contact_info: dict[str, list[str]] = {}
        info = iq["disco_info"]

        for sub in info["substanzas"]:
            if isinstance(sub, Form) and sub["type"] == "result":
                values = sub["values"]
                for field, val in values.items():
                    if field in self.CONTACT_FIELDS:
                        if isinstance(val, list):
                            contact_info[field] = val
                        elif isinstance(val, str) and val.strip():
                            contact_info[field] = [val]

        if not contact_info:
            return f"No contact information found for service {argument}."

        lines = [f"Contact information for service {argument}:"]
        for field, values in sorted(contact_info.items()):
            if not values:
                continue
            field_name = (
                field.replace("-addresses", "").replace("-", " ").title().strip()
            )
            lines.append(f"\n{field_name}:")
            lines.extend([f"  - {value}" for value in values])
        return "\n".join(lines)

    async def cmd_info(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} info - shows the identities and features of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} info <jid>"
            )

        try:
            iq = await self.plugin["xep_0030"].get_info(jid=argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Info lookup failed for %s: %s", argument, exc)
            return f"Could not retrieve info for {argument}: {exc}"

        info = iq["disco_info"]
        lines = [f"Info for {argument}:"]

        identities = list(info["identities"])
        if identities:
            lines.append("\nIdentities:")
            for category, itype, lang, name in sorted(identities):
                identity_str = f"  - {category}/{itype}"
                if name:
                    identity_str += f" ({name})"
                lines.append(identity_str)

        features = sorted(info["features"])
        if features:
            lines.append("\nFeatures:")
            for feature in features:
                lines.append(f"  - {feature}")

        return "\n".join(lines)

    async def cmd_ping(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} ping - pings an XMPP entity and reports the round-trip time.\n"
                f"Usage: {COMMAND_PREFIX} ping <jid>"
            )

        try:
            rtt = await self.plugin["xep_0199"].ping(jid=argument)
            return f"Pong from {argument} in {rtt * 1000:.2f}ms"
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Ping failed for %s: %s", argument, exc)
            return f"Ping failed for {argument}: {exc}"

    async def cmd_uptime(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} uptime - shows the uptime of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} uptime <jid>"
            )

        try:
            iq = await self.plugin["xep_0012"].get_last_activity(jid=argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Uptime lookup failed for %s: %s", argument, exc)
            return f"Could not retrieve uptime for {argument}: {exc}"

        seconds = int(iq["last_activity"]["seconds"])

        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        duration = " ".join(parts)
        return f"Uptime for {argument}: {duration}"

    async def cmd_srv(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} srv - performs DNS SRV lookups for XMPP services.\n"
                f"Usage: {COMMAND_PREFIX} srv <domain>"
            )

        domain = argument.strip()
        lines = [f"SRV records for {domain}:"]

        records_to_check = [
            ("Client-to-Server", "_xmpp-client._tcp"),
            ("Client-to-Server (Direct TLS)", "_xmpps-client._tcp"),
            ("Server-to-Server", "_xmpp-server._tcp"),
            ("Server-to-Server (Direct TLS)", "_xmpps-server._tcp"),
        ]

        for label, prefix in records_to_check:
            name = f"{prefix}.{domain}"
            lines.append(f"\n{label} ({prefix}):")
            try:
                answers = await self._resolver.resolve(name, "SRV")
                records = []
                for rdata in answers:
                    records.append(
                        f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    )
                for r in sorted(records):
                    lines.append(f"  - {r}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                lines.append("  - No records found")
            except Exception as e:
                LOGGER.warning("DNS lookup failed for %s: %s", name, e)
                lines.append(f"  - Lookup failed: {e}")

        return "\n".join(lines)

    async def cmd_compliance(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} compliance - shows the compliance score of a server.\n"
                f"Usage: {COMMAND_PREFIX} compliance <domain>"
            )

        domain = argument.strip()
        url = f"https://compliance.conversations.im/badge/{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        def fetch() -> str:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode("utf-8")

        try:
            svg = await asyncio.to_thread(fetch)
            match = re.search(
                r'<text x="2255" y="140"[^>]*>\s*(.+?)\s*</text>', svg, re.DOTALL
            )
            if match:
                score = match.group(1).strip()
                if score == "Unavailable":
                    return (
                        f"Compliance score for {domain} is unavailable. "
                        f"It may not be registered on compliance.conversations.im.\n"
                        f"You can add it here: https://compliance.conversations.im/add/"
                    )
                return (
                    f"Compliance score for {domain}: {score}\n"
                    f"More details: https://compliance.conversations.im/server/{domain}/"
                )
            return f"Could not parse compliance badge for {domain}."
        except urllib.error.HTTPError as e:
            return f"Error fetching compliance score for {domain}: HTTP {e.code}"
        except Exception as e:
            LOGGER.warning("Compliance lookup failed for %s: %s", domain, e)
            return f"Error fetching compliance score for {domain}: {e}"

    async def get_service_items(self, service: str) -> list[dict]:
        disco = self.plugin["xep_0030"]
        items = await disco.get_items(jid=service)
        return items.get("disco_items", [])


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    try:
        config = AppConfig.from_env()
    except ValueError as exc:
        LOGGER.error("Invalid configuration: %s", exc)
        raise SystemExit(2) from exc

    xmpp = XMPPUtilities(config.jid, config.password, config.muc_jids, config.nick)

    loop = asyncio.new_event_loop()
    connect_result = loop.run_until_complete(xmpp.connect())
    if connect_result is False:
        LOGGER.warning(
            "Initial connect attempt failed for %s; keeping loop running for retries",
            config.jid,
        )
    else:
        LOGGER.info("Connected as %s", config.jid)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        LOGGER.info("Received interrupt, shutting down")
    finally:
        xmpp.request_shutdown()
        xmpp.disconnect(wait=True)


if __name__ == "__main__":
    main()
