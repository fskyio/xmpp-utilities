import asyncio
import logging
import os
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.resolver
import slixmpp
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.plugins.xep_0004.stanza import Form
from slixmpp.plugins.xep_0054.stanza import VCardTemp

from .dane import (
    XMPP_SERVICES,
    discover_dane,
    format_dane_report,
    parse_dane_argument,
    validate_dane,
)

__version__ = "1.2.0"
__homepage__ = "https://fsky.io/projects/xmpp-utilities/"
__repository__ = "https://foundry.fsky.io/fsky/xmpp-utilities.git"
__issues__ = "https://foundry.fsky.io/fsky/xmpp-utilities/issues"
__license__ = "0BSD"

BOT_NAME = "XMPP Utilities"
BOT_DESCRIPTION = "An XMPP bot with diagnostics and monitoring tools."
BOT_ORG = "FSKY"
AVATAR_RESOURCE = "avatar.png"
AVATAR_TYPE = "image/png"
AVATAR_WIDTH = 128
AVATAR_HEIGHT = 128

LOGGER = logging.getLogger(__name__)
COMMAND_PREFIX = "!xmpp"
XEP_COMMAND_PREFIX = "!xep"
XEP_XML_URL = "https://xmpp.org/extensions/xep-{number}.xml"
XEP_PAGE_URL = "https://xmpp.org/extensions/xep-{number}.html"
ADHOC_COMMANDS_NODE = "http://jabber.org/protocol/commands"


@dataclass(frozen=True)
class XEPInfo:
    number: str
    title: str
    abstract: str
    authors: tuple[str, ...]
    status: str
    type: str

    @property
    def page_url(self) -> str:
        return XEP_PAGE_URL.format(number=self.number)


def normalize_xep_number(value: str) -> str | None:
    """Return a four-digit XEP number from common user-facing spellings."""
    patterns = (
        r"(?:https?://)?(?:www\.)?xmpp\.org/extensions/xep[-_](\d{1,4})(?:\.(?:html|xml))?/?",
        r"(?:xep)?[\s._:#/\-\u2010\u2011\u2012\u2013\u2014\u2015]*(\d{1,4})",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value.strip(), flags=re.IGNORECASE)
        if match:
            number = int(match.group(1))
            if number > 0:
                return f"{number:04d}"
    return None


def _element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def parse_xep_document(document: bytes, requested_number: str) -> XEPInfo:
    root = ET.fromstring(document)
    header = root.find("header")
    if header is None:
        raise ValueError("XEP document has no header")

    number = _element_text(header.find("number")) or requested_number
    if not number.isdigit():
        raise ValueError("XEP document has an invalid number")
    number = f"{int(number):04d}"

    title = _element_text(header.find("title"))
    abstract = _element_text(header.find("abstract"))
    status = _element_text(header.find("status"))
    xep_type = _element_text(header.find("type"))
    if not all((title, abstract, status, xep_type)):
        raise ValueError("XEP document is missing required metadata")

    authors = []
    for author in header.findall("author"):
        name = " ".join(
            part
            for part in (
                _element_text(author.find("firstname")),
                _element_text(author.find("surname")),
            )
            if part
        )
        if not name:
            name = _element_text(author.find("name"))
        if name:
            authors.append(name)

    return XEPInfo(
        number=number,
        title=title,
        abstract=abstract,
        authors=tuple(authors),
        status=status,
        type=xep_type,
    )


def fetch_xep(number: str) -> XEPInfo:
    url = XEP_XML_URL.format(number=number)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/xml, text/xml;q=0.9",
            "User-Agent": f"xmpp-utilities/{__version__}",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return parse_xep_document(response.read(), number)


def format_xep_response(xep: XEPInfo) -> str:
    heading = f"XEP-{xep.number}: {xep.title}"
    authors = ", ".join(xep.authors) if xep.authors else "Unknown"
    return (
        f"*{heading}*\n"
        f"{xep.abstract}\n"
        f"Authors: {authors}\n"
        f"Status: {xep.status}\n"
        f"Type: {xep.type}\n"
        f"{xep.page_url}"
    )


@dataclass(frozen=True)
class AdHocField:
    var: str
    ftype: str
    label: str
    required: bool = True
    value: str | bool | None = None
    desc: str = ""


@dataclass(frozen=True)
class AdHocCommand:
    node: str
    name: str
    command: str
    instructions: str
    fields: tuple[AdHocField, ...] = ()


ADHOC_COMMANDS: tuple[AdHocCommand, ...] = (
    AdHocCommand(
        "about",
        "About",
        "about",
        "Shows information about this bot.",
    ),
    AdHocCommand(
        "version",
        "Software Version",
        "version",
        "Shows the software version of an XMPP entity (XEP-0092).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "items",
        "Service Items",
        "items",
        "Lists the service items of an XMPP entity (XEP-0030).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "contact",
        "Contact Information",
        "contact",
        "Displays contact information for an XMPP entity (XEP-0030).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "info",
        "Entity Info",
        "info",
        "Lists the identities and features of an XMPP entity (XEP-0030).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "ping",
        "Ping",
        "ping",
        "Pings an XMPP entity and reports the round-trip time (XEP-0199).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "uptime",
        "Uptime",
        "uptime",
        "Shows the uptime of an XMPP entity (XEP-0012).",
        (AdHocField("jid", "jid-single", "JID"),),
    ),
    AdHocCommand(
        "srv",
        "SRV Lookup",
        "srv",
        "Performs DNS SRV lookups for XMPP services.",
        (AdHocField("domain", "text-single", "Domain"),),
    ),
    AdHocCommand(
        "tlsa",
        "DANE TLSA",
        "tlsa",
        "Shows and validates DANE TLSA records for the domain's XMPP endpoints.",
        (
            AdHocField("domain", "text-single", "Domain"),
            AdHocField(
                "validate",
                "boolean",
                "Validate certificates",
                required=False,
                value=True,
                desc=(
                    "Connect to each public endpoint and check its certificate "
                    "against TLSA records."
                ),
            ),
        ),
    ),
    AdHocCommand(
        "compliance",
        "Compliance Score",
        "compliance",
        "Shows the compliance score of a server from compliance.conversations.im.",
        (AdHocField("domain", "text-single", "Domain"),),
    ),
    AdHocCommand(
        "xep",
        "XEP Lookup",
        "xep",
        "Shows the title, abstract, authors, status, type, and link for an XEP.",
        (AdHocField("number", "text-single", "XEP number"),),
    ),
)

_ADHOC_BY_NODE = {command.node: command for command in ADHOC_COMMANDS}

_FALSE_VALUES = {False, "0", "false"}


def adhoc_form_values(payload: object) -> dict[str, object]:
    if payload is None:
        return {}
    if isinstance(payload, list):
        if not payload:
            return {}
        payload = payload[0]
    if isinstance(payload, Form):
        return payload["values"]
    return {}


def adhoc_argument(spec: AdHocCommand, values: dict[str, object]) -> str | None:
    if spec.node == "tlsa":
        domain = str(values.get("domain") or "").strip()
        if not domain:
            return None
        raw = values.get("validate", True)
        if raw in _FALSE_VALUES:
            return f"{domain} --no-validate"
        return domain

    if not spec.fields:
        return None

    raw = values.get(spec.fields[0].var)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


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
            os.getenv("XMPP_UTILS_NICK", "XMPP Utilities").strip() or "XMPP Utilities"
        )

        muc_jids = [muc.strip() for muc in raw_mucs.split(",") if muc.strip()]

        missing = []
        if not jid:
            missing.append("XMPP_UTILS_JID")
        if not password:
            missing.append("XMPP_UTILS_PASSWORD")

        if missing:
            raise ValueError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        return cls(jid=jid, password=password, muc_jids=tuple(muc_jids), nick=nick)


def load_avatar() -> bytes:
    return Path(__file__).with_name(AVATAR_RESOURCE).read_bytes()


def avatar_metadata_item(avatar: bytes, avatar_id: str) -> dict[str, str]:
    return {
        "id": avatar_id,
        "type": AVATAR_TYPE,
        "bytes": str(len(avatar)),
        "width": str(AVATAR_WIDTH),
        "height": str(AVATAR_HEIGHT),
    }


class XMPPUtilities(slixmpp.ClientXMPP):
    CONTACT_FIELDS: ClassVar[set[str]] = {
        "abuse-addresses",
        "admin-addresses",
        "feedback-addresses",
        "sales-addresses",
        "security-addresses",
        "status-addresses",
        "support-addresses",
    }

    def __init__(
        self, jid: str, password: str, muc_jids: tuple[str, ...], nick: str
    ) -> None:
        super().__init__(jid, password)
        self.muc_jids = muc_jids
        self.nick = nick
        self._shutdown_requested = False
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.flags = dns.flags.RD | dns.flags.AD
        self._dane_validation_lock = asyncio.Lock()

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("groupchat_message", self.muc_message)
        self.add_event_handler("message", self.dm_message)
        self.add_event_handler("disconnected", self.on_disconnected)

        self.register_plugin("xep_0004")
        self.register_plugin("xep_0012")
        self.register_plugin("xep_0030")
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0050")
        self.register_plugin("xep_0054")
        self.register_plugin("xep_0084")
        self.register_plugin(
            "xep_0092",
            pconfig={
                "software_name": BOT_NAME,
                "version": __version__,
            },
        )
        self.register_plugin("xep_0115")
        self.register_plugin("xep_0153")
        self.register_plugin("xep_0163")
        self.register_plugin("xep_0172")
        self.register_plugin("xep_0199")

        self.plugin["xep_0030"].add_identity(
            category="client",
            itype="bot",
            name=BOT_NAME,
        )

        self.commands: dict[str, Callable[[str | None], Awaitable[str]]] = {
            "help": self.cmd_help,
            "about": self.cmd_about,
            "version": self.cmd_version,
            "items": self.cmd_items,
            "contact": self.cmd_contact,
            "info": self.cmd_info,
            "ping": self.cmd_ping,
            "uptime": self.cmd_uptime,
            "srv": self.cmd_srv,
            "tlsa": self.cmd_tlsa,
            "dane": self.cmd_tlsa,
            "compliance": self.cmd_compliance,
            "xep": self.cmd_xep,
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
        await self.advertise_profile()
        self.register_adhoc_commands()
        await self.plugin["xep_0115"].update_caps()
        self.send_presence(pnick=self.nick)
        await self.get_roster()
        for muc_jid in self.muc_jids:
            LOGGER.info("Joining MUC: %s", muc_jid)
            self.plugin["xep_0045"].join_muc(muc_jid, self.nick)

    def register_adhoc_commands(self) -> None:
        adhoc = self.plugin["xep_0050"]
        for spec in ADHOC_COMMANDS:
            adhoc.add_command(
                node=spec.node,
                name=spec.name,
                handler=self._adhoc_start,
            )

    async def _adhoc_start(self, _iq: slixmpp.Iq, session: dict) -> dict:
        spec = _ADHOC_BY_NODE[session["node"]]
        if not spec.fields:
            return await self._adhoc_finish(session, spec.command, None)

        form = self.plugin["xep_0004"].make_form(
            "form", spec.name, spec.instructions
        )
        for field in spec.fields:
            form.add_field(
                var=field.var,
                ftype=field.ftype,
                label=field.label,
                required=field.required,
                value=field.value,
                desc=field.desc,
            )
        session["payload"] = form
        session["next"] = self._adhoc_submit
        session["has_next"] = False
        return session

    async def _adhoc_submit(self, payload: object, session: dict) -> dict:
        spec = _ADHOC_BY_NODE[session["node"]]
        argument = adhoc_argument(spec, adhoc_form_values(payload))
        return await self._adhoc_finish(session, spec.command, argument)

    async def _adhoc_finish(
        self, session: dict, command: str, argument: str | None
    ) -> dict:
        result = await self.commands[command](argument)
        session["notes"] = [("info", result)]
        session["payload"] = None
        session["next"] = None
        return session

    def build_vcard(self, avatar: bytes) -> VCardTemp:
        vcard = self.plugin["xep_0054"].make_vcard()
        vcard["FN"] = self.nick
        vcard["NICKNAME"] = self.nick
        vcard["DESC"] = BOT_DESCRIPTION
        vcard["URL"] = __homepage__
        vcard["JABBERID"] = str(self.boundjid.bare)
        vcard["ORG"]["ORGNAME"] = BOT_ORG
        vcard["PHOTO"]["TYPE"] = AVATAR_TYPE
        vcard["PHOTO"]["BINVAL"] = avatar
        return vcard

    async def advertise_profile(self) -> None:
        avatar = load_avatar()
        avatar_id = self.plugin["xep_0084"].generate_id(avatar)

        try:
            await self.plugin["xep_0054"].publish_vcard(self.build_vcard(avatar))
            await self.plugin["xep_0153"].api["set_hash"](self.boundjid, args=avatar_id)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Could not publish vCard: %s", exc)

        try:
            await self.plugin["xep_0172"].publish_nick(nick=self.nick)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Could not publish nickname: %s", exc)

        try:
            await self.plugin["xep_0084"].publish_avatar(avatar)
            await self.plugin["xep_0084"].publish_avatar_metadata(
                items=avatar_metadata_item(avatar, avatar_id)
            )
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Could not publish avatar: %s", exc)

    async def muc_message(self, msg: slixmpp.Message) -> None:
        body = (msg["body"] or "").strip()
        if msg["mucnick"] == self.nick or not self.is_command_message(body):
            return

        response = await self.handle_command(body)
        self.send_message(
            mto=msg["from"].bare,
            mbody=response,
            mtype="groupchat",
        )

    async def dm_message(self, msg: slixmpp.Message) -> None:
        body = (msg["body"] or "").strip()
        if (
            msg["type"] not in ("chat", "normal")
            or not self.is_command_message(body)
        ):
            return

        response = await self.handle_command(body)
        msg.reply(response).send()

    async def handle_command(self, body: str) -> str:
        if body.strip().lower() == COMMAND_PREFIX:
            return (
                f"{BOT_NAME} {__version__} - diagnostics and monitoring tools for XMPP. "
                f'Use "{COMMAND_PREFIX} about" for details or '
                f'"{COMMAND_PREFIX} help" for commands.'
            )

        command, argument = self.parse_command(body)
        if not command:
            return f'Use "{COMMAND_PREFIX} help" to list all commands.'

        handler = self.commands.get(command)
        if handler is None:
            return f'Unknown command. Use "{COMMAND_PREFIX} help" to list all commands.'

        return await handler(argument)

    @staticmethod
    def is_command_message(body: str) -> bool:
        first_word = body.strip().split(maxsplit=1)[0].lower() if body.strip() else ""
        return first_word in (COMMAND_PREFIX, XEP_COMMAND_PREFIX)

    @staticmethod
    def parse_command(body: str) -> tuple[str | None, str | None]:
        parts = body.strip().split(maxsplit=1)
        if parts and parts[0].lower() == XEP_COMMAND_PREFIX:
            argument = (
                parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
            )
            return "xep", argument

        parts = body.strip().split(maxsplit=2)
        if len(parts) < 2 or parts[0].lower() != COMMAND_PREFIX:
            return None, None
        command = parts[1].strip().lower()
        argument = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        return command, argument

    async def cmd_help(self, _argument: str | None) -> str:
        return (
            "Available commands:\n"
            f"{COMMAND_PREFIX} about - shows information about this bot.\n"
            f"{COMMAND_PREFIX} version <jid> - shows the version of an XMPP entity.\n"
            f"{COMMAND_PREFIX} items <jid> - shows the items of an XMPP entity.\n"
            f"{COMMAND_PREFIX} contact <jid> - shows the contact information of an XMPP entity.\n"
            f"{COMMAND_PREFIX} info <jid> - shows the identities and features of an XMPP entity.\n"
            f"{COMMAND_PREFIX} ping <jid> - pings an XMPP entity and reports the round-trip time.\n"
            f"{COMMAND_PREFIX} uptime <jid> - shows the uptime of an XMPP entity.\n"
            f"{COMMAND_PREFIX} srv <domain> - performs DNS SRV lookups for XMPP services.\n"
            f"{COMMAND_PREFIX} tlsa <domain> [--no-validate] - shows and validates "
            "DANE TLSA records for XMPP services (alias: dane).\n"
            f"{COMMAND_PREFIX} compliance <domain> - shows the compliance score of a server.\n"
            f"{COMMAND_PREFIX} xep <number> - shows information about an XMPP Extension Protocol "
            f"(alias: {XEP_COMMAND_PREFIX} <number>).\n"
            f"{COMMAND_PREFIX} help - displays this message.\n"
            "These commands are also available as XEP-0050 ad-hoc commands."
        )

    async def cmd_about(self, _argument: str | None) -> str:
        return (
            f"*{BOT_NAME} {__version__}*\n"
            f"{BOT_DESCRIPTION}\n"
            f"Homepage: {__homepage__}\n"
            f"Repository: {__repository__}\n"
            f"Issues: {__issues__}\n"
            f"License: {__license__}\n"
            f'Use "{COMMAND_PREFIX} help" to list all commands.'
        )

    async def cmd_xep(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} xep - shows information about an XMPP Extension Protocol.\n"
                f"Usage: {COMMAND_PREFIX} xep <number> "
                f"(alias: {XEP_COMMAND_PREFIX} <number>)"
            )

        number = normalize_xep_number(argument)
        if number is None:
            return (
                f'Invalid XEP number: "{argument}". '
                f"Try {COMMAND_PREFIX} xep 516 or {COMMAND_PREFIX} xep XEP-0516."
            )

        try:
            xep = await asyncio.to_thread(fetch_xep, number)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return f"XEP-{number} was not found."
            LOGGER.warning("XEP lookup failed for %s: HTTP %s", number, exc.code)
            return f"Could not retrieve XEP-{number}: HTTP {exc.code}"
        except (ET.ParseError, ValueError, urllib.error.URLError, TimeoutError) as exc:
            LOGGER.warning("XEP lookup failed for %s: %s", number, exc)
            return f"Could not retrieve XEP-{number}. Please try again later."

        return format_xep_response(xep)

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

        for service in XMPP_SERVICES:
            label = service.label
            prefix = service.prefix
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
            except dns.exception.DNSException as e:
                LOGGER.warning("DNS lookup failed for %s: %s", name, e)
                lines.append(f"  - Lookup failed: {e}")

        return "\n".join(lines)

    async def cmd_tlsa(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} tlsa - shows DANE TLSA records for XMPP services.\n"
                f"Usage: {COMMAND_PREFIX} tlsa <domain> [--no-validate] "
                f"(alias: {COMMAND_PREFIX} dane)"
            )

        parsed = parse_dane_argument(argument)
        if parsed is None:
            return (
                f'Invalid TLSA lookup arguments: "{argument}". '
                f"Usage: {COMMAND_PREFIX} tlsa <domain> [--no-validate]"
            )
        domain, should_validate = parsed

        if not should_validate:
            report = await discover_dane(self._resolver, domain)
            return format_dane_report(report)

        if self._dane_validation_lock.locked():
            return "A DANE validation is already running. Please try again shortly."
        async with self._dane_validation_lock:
            report = await discover_dane(self._resolver, domain)
            report = await validate_dane(self._resolver, report)
        return format_dane_report(report)

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
        except (urllib.error.URLError, TimeoutError, UnicodeError) as e:
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

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    xmpp = XMPPUtilities(config.jid, config.password, config.muc_jids, config.nick)
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
