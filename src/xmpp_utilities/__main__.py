import argparse
import asyncio
import logging
import os
import re
import tomllib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Mapping
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
from slixmpp.plugins.xep_0066.stanza import OOB

from .dane import (
    XMPP_SERVICES,
    discover_dane,
    format_dane_report,
    parse_dane_argument,
    validate_dane,
)
from .muc import InviteConfig, MucManager, parse_bool, parse_jid_csv, parse_jid_list, parse_max_rooms

__version__ = "1.3.0"
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
COMPLIANCE_BADGE_URL = "https://compliance.conversations.im/badge/{domain}/"
COMPLIANCE_SERVER_URL = "https://compliance.conversations.im/server/{domain}/"
COMPLIANCE_ADD_URL = "https://compliance.conversations.im/add/"
NOTE_ONLY_ADHOC_COMMANDS = frozenset({"ping", "uptime"})


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


async def load_xep(number: str) -> XEPInfo | str:
    try:
        return await asyncio.to_thread(fetch_xep, number)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return f"XEP-{number} was not found."
        LOGGER.warning("XEP lookup failed for %s: HTTP %s", number, exc.code)
        return f"Could not retrieve XEP-{number}: HTTP {exc.code}"
    except (ET.ParseError, ValueError, urllib.error.URLError, TimeoutError) as exc:
        LOGGER.warning("XEP lookup failed for %s: %s", number, exc)
        return f"Could not retrieve XEP-{number}. Please try again later."


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


@dataclass(frozen=True)
class AdHocPresentation:
    notes: tuple[tuple[str, str], ...]
    payload: Form | OOB | list[Form | OOB] | None = None


@dataclass(frozen=True)
class SRVServiceLookup:
    label: str
    prefix: str
    records: tuple[tuple[str, str, str, str], ...] = ()
    status: str | None = None


@dataclass(frozen=True)
class ComplianceLookup:
    domain: str
    score: str | None = None
    unavailable: bool = False
    unparsed: bool = False
    http_error: int | None = None
    error: str | None = None


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


def contact_field_label(field: str) -> str:
    return field.replace("-addresses", "").replace("-", " ").title().strip()


def adhoc_note_type(message: str) -> str:
    head = message.lower()
    if head.startswith(("could not", "ping failed", "error ", "invalid ")):
        return "error"
    if "already running" in head:
        return "warn"
    return "info"


def make_oob(url: str, desc: str) -> OOB:
    oob = OOB()
    oob["url"] = url
    oob["desc"] = desc
    return oob


def apply_adhoc_presentation(session: dict, presentation: AdHocPresentation) -> dict:
    session["notes"] = list(presentation.notes)
    session["payload"] = presentation.payload
    session["next"] = None
    return session


DEFAULT_CONFIG_PATH = Path("xmpp-utilities.toml")
DEFAULT_NICK = BOT_NAME


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xmpp-utilities", description=BOT_DESCRIPTION)
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to a TOML config file",
    )
    return parser.parse_args(argv)


def resolve_config_path(
    path: Path | None = None,
    *,
    default_path: Path = DEFAULT_CONFIG_PATH,
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    if path is not None:
        return path.expanduser()
    env = os.environ if environ is None else environ
    env_path = env.get("XMPP_UTILS_CONFIG", "").strip()
    if env_path:
        return Path(env_path).expanduser()
    if default_path.is_file():
        return default_path
    return None


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _parse_mucs_csv(raw: str) -> tuple[str, ...]:
    return tuple(muc.strip() for muc in raw.split(",") if muc.strip())


def _parse_mucs_toml(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("mucs must be an array of strings")
    return tuple(item.strip() for item in value if item.strip())


def _parse_invite_table(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("invite must be a table")
    invite: dict[str, object] = {}
    if "enabled" in value:
        invite["enabled"] = parse_bool(value["enabled"], "invite.enabled")
    if "persist" in value:
        invite["persist"] = parse_bool(value["persist"], "invite.persist")
    if "max_rooms" in value:
        invite["max_rooms"] = parse_max_rooms(value["max_rooms"], "invite.max_rooms")
    if "allow_from" in value:
        invite["allow_from"] = parse_jid_list(value["allow_from"], "invite.allow_from")
    if "allow_domains" in value:
        invite["allow_domains"] = parse_jid_list(
            value["allow_domains"], "invite.allow_domains"
        )
    if "deny_from" in value:
        invite["deny_from"] = parse_jid_list(value["deny_from"], "invite.deny_from")
    if "allow_muc_hosts" in value:
        invite["allow_muc_hosts"] = parse_jid_list(
            value["allow_muc_hosts"], "invite.allow_muc_hosts"
        )
    return invite


def read_toml_config(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Config file not found: {path}")

    with path.open("rb") as handle:
        try:
            data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid TOML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Invalid TOML in {path}: expected a table")

    values: dict[str, object] = {}
    if "jid" in data:
        values["jid"] = _require_string(data["jid"], "jid").strip()
    if "password" in data:
        values["password"] = _require_string(data["password"], "password").strip()
    if "nick" in data:
        values["nick"] = _require_string(data["nick"], "nick").strip()
    if "mucs" in data:
        values["muc_jids"] = _parse_mucs_toml(data["mucs"])
    if "invite" in data:
        values["invite"] = _parse_invite_table(data["invite"])
    return values


def read_env_config(environ: Mapping[str, str] | None = None) -> dict[str, object]:
    env = os.environ if environ is None else environ
    values: dict[str, object] = {}
    if "XMPP_UTILS_JID" in env:
        values["jid"] = env["XMPP_UTILS_JID"].strip()
    if "XMPP_UTILS_PASSWORD" in env:
        values["password"] = env["XMPP_UTILS_PASSWORD"].strip()
    if "XMPP_UTILS_NICK" in env:
        values["nick"] = env["XMPP_UTILS_NICK"].strip()
    if "XMPP_UTILS_MUCS" in env:
        values["muc_jids"] = _parse_mucs_csv(env["XMPP_UTILS_MUCS"])
    invite: dict[str, object] = {}
    if "XMPP_UTILS_INVITE_ENABLED" in env:
        invite["enabled"] = parse_bool(
            env["XMPP_UTILS_INVITE_ENABLED"], "invite.enabled"
        )
    if "XMPP_UTILS_INVITE_PERSIST" in env:
        invite["persist"] = parse_bool(
            env["XMPP_UTILS_INVITE_PERSIST"], "invite.persist"
        )
    if "XMPP_UTILS_INVITE_MAX_ROOMS" in env:
        raw_max = env["XMPP_UTILS_INVITE_MAX_ROOMS"].strip()
        if raw_max:
            try:
                invite["max_rooms"] = parse_max_rooms(
                    int(raw_max), "invite.max_rooms"
                )
            except ValueError as exc:
                raise ValueError("invite.max_rooms must be a positive integer") from exc
    if "XMPP_UTILS_INVITE_ALLOW_FROM" in env:
        invite["allow_from"] = parse_jid_csv(env["XMPP_UTILS_INVITE_ALLOW_FROM"])
    if "XMPP_UTILS_INVITE_ALLOW_DOMAINS" in env:
        invite["allow_domains"] = parse_jid_csv(env["XMPP_UTILS_INVITE_ALLOW_DOMAINS"])
    if "XMPP_UTILS_INVITE_DENY_FROM" in env:
        invite["deny_from"] = parse_jid_csv(env["XMPP_UTILS_INVITE_DENY_FROM"])
    if "XMPP_UTILS_INVITE_ALLOW_MUC_HOSTS" in env:
        invite["allow_muc_hosts"] = parse_jid_csv(
            env["XMPP_UTILS_INVITE_ALLOW_MUC_HOSTS"]
        )
    if invite:
        values["invite"] = invite
    return values


def _merge_config_values(
    file_values: Mapping[str, object], env_values: Mapping[str, object]
) -> dict[str, object]:
    values = dict(file_values)
    invite = dict(values.pop("invite", {}) or {})
    env_invite = dict(env_values.get("invite", {}) or {})
    invite.update(env_invite)
    values.update({key: value for key, value in env_values.items() if key != "invite"})
    if invite:
        values["invite"] = invite
    return values


@dataclass(frozen=True)
class AppConfig:
    jid: str
    password: str
    muc_jids: tuple[str, ...]
    nick: str
    invite: InviteConfig = InviteConfig()

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> "AppConfig":
        jid = _require_string(values.get("jid", ""), "jid").strip()
        password = _require_string(values.get("password", ""), "password").strip()
        nick = _require_string(values.get("nick", DEFAULT_NICK), "nick").strip()
        muc_jids = values.get("muc_jids", ())
        if not isinstance(muc_jids, tuple) or not all(
            isinstance(item, str) for item in muc_jids
        ):
            raise ValueError("mucs must be an array of strings")

        missing = [
            name
            for name, value in (("jid", jid), ("password", password))
            if not value
        ]
        if missing:
            raise ValueError("Missing required configuration: " + ", ".join(missing))

        invite_values = values.get("invite", {})
        if invite_values in (None, {}):
            invite = InviteConfig()
        elif isinstance(invite_values, InviteConfig):
            invite = invite_values
        elif isinstance(invite_values, Mapping):
            invite = InviteConfig.from_mapping(invite_values)
        else:
            raise ValueError("invite must be a table")

        return cls(
            jid=jid,
            password=password,
            muc_jids=muc_jids,
            nick=nick or DEFAULT_NICK,
            invite=invite,
        )

    @classmethod
    def load(
        cls,
        path: Path | None = None,
        *,
        default_path: Path = DEFAULT_CONFIG_PATH,
        environ: Mapping[str, str] | None = None,
    ) -> "AppConfig":
        resolved = resolve_config_path(
            path, default_path=default_path, environ=environ
        )
        file_values: dict[str, object] = {}
        if resolved is not None:
            LOGGER.info("Loading configuration from %s", resolved)
            file_values = read_toml_config(resolved)
        return cls.from_mapping(_merge_config_values(file_values, read_env_config(environ)))


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
        self,
        jid: str,
        password: str,
        muc_jids: tuple[str, ...],
        nick: str,
        invite: InviteConfig | None = None,
    ) -> None:
        super().__init__(jid, password)
        self.muc_jids = muc_jids
        self.nick = nick
        self.invite = invite or InviteConfig()
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
        self.register_plugin("xep_0060")
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
        self.register_plugin("xep_0223")
        self.register_plugin("xep_0249")
        self.register_plugin("xep_0402")
        self.register_plugin("xep_0410")

        self.plugin["xep_0030"].add_identity(
            category="client",
            itype="bot",
            name=BOT_NAME,
        )
        self.mucs = MucManager(self, muc_jids, nick, self.invite)

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
        self.mucs.shutdown()

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
        await self.mucs.start()

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
        if command in NOTE_ONLY_ADHOC_COMMANDS:
            presentation = await self._adhoc_present_note(command, argument)
        else:
            presenter = getattr(self, f"_adhoc_present_{command}")
            presentation = await presenter(argument)
        return apply_adhoc_presentation(session, presentation)

    def _adhoc_error(self, message: str, note_type: str = "error") -> AdHocPresentation:
        return AdHocPresentation(notes=((note_type, message),))

    def _result_form(self, title: str, instructions: str = "") -> Form:
        return self.plugin["xep_0004"].make_form("result", title, instructions)

    def _add_result_fields(
        self,
        form: Form,
        fields: tuple[tuple[str, str, str, object], ...],
    ) -> None:
        for var, ftype, label, value in fields:
            if value is None or value == "" or value == []:
                continue
            form.add_field(var=var, ftype=ftype, label=label, value=value)

    def _result_table(
        self,
        title: str,
        columns: tuple[tuple[str, str, str], ...],
        rows: list[dict[str, str]],
        instructions: str = "",
    ) -> Form:
        form = self._result_form(title, instructions)
        for var, ftype, label in columns:
            form.add_reported(var, ftype=ftype, label=label)
        for row in rows:
            form.add_item(row)
        return form

    def _with_oob(
        self, form: Form, url: str, desc: str
    ) -> list[Form | OOB]:
        return [form, make_oob(url, desc)]

    async def _adhoc_present_note(
        self, command: str, argument: str | None
    ) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A JID is required.")
        result = await self.commands[command](argument)
        return AdHocPresentation(notes=((adhoc_note_type(result), result),))

    async def _adhoc_present_about(self, _argument: str | None) -> AdHocPresentation:
        form = self._result_form(BOT_NAME, BOT_DESCRIPTION)
        self._add_result_fields(
            form,
            (
                ("name", "text-single", "Name", BOT_NAME),
                ("version", "text-single", "Version", __version__),
                ("homepage", "text-single", "Homepage", __homepage__),
                ("repository", "text-single", "Repository", __repository__),
                ("issues", "text-single", "Issues", __issues__),
                ("license", "text-single", "License", __license__),
            ),
        )
        return AdHocPresentation(
            notes=(("info", f"{BOT_NAME} {__version__}"),),
            payload=self._with_oob(form, __homepage__, BOT_NAME),
        )

    async def _adhoc_present_version(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A JID is required.")
        result = await self._query_version(argument)
        if isinstance(result, str):
            return self._adhoc_error(result)
        name, version, os_name = result
        form = self._result_form("Software Version", argument)
        self._add_result_fields(
            form,
            (
                ("jid", "jid-single", "JID", argument),
                ("name", "text-single", "Name", name),
                ("version", "text-single", "Version", version),
                ("os", "text-single", "Operating system", os_name),
            ),
        )
        if os_name:
            note = f"{argument} is running {name} {version} on {os_name}."
        else:
            note = f"{argument} is running {name} {version}."
        return AdHocPresentation(notes=(("info", note),), payload=form)

    async def _adhoc_present_items(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A JID is required.")
        try:
            items = await self.get_service_items(argument)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Items lookup failed for %s: %s", argument, exc)
            return self._adhoc_error(f"Could not retrieve items for {argument}: {exc}")
        rows = []
        for item in items:
            rows.append(
                {
                    "jid": str(item.get("jid") or "unknown"),
                    "name": item.get("name") or "",
                }
            )
        if not rows:
            return self._adhoc_error(
                f"No items found for service {argument}.", note_type="warn"
            )
        form = self._result_table(
            "Service Items",
            (
                ("jid", "jid-single", "JID"),
                ("name", "text-single", "Name"),
            ),
            rows,
            instructions=argument,
        )
        noun = "item" if len(rows) == 1 else "items"
        return AdHocPresentation(
            notes=(("info", f"Found {len(rows)} {noun} for {argument}."),),
            payload=form,
        )

    async def _adhoc_present_contact(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A JID is required.")
        result = await self._query_contact(argument)
        if isinstance(result, str):
            return self._adhoc_error(result)
        if not result:
            return self._adhoc_error(
                f"No contact information found for service {argument}.",
                note_type="warn",
            )
        form = self._result_form("Contact Information", argument)
        fields = []
        for field, values in sorted(result.items()):
            if not values:
                continue
            ftype = "text-multi" if len(values) > 1 else "text-single"
            value: object = values if len(values) > 1 else values[0]
            fields.append((field, ftype, contact_field_label(field), value))
        self._add_result_fields(form, tuple(fields))
        return AdHocPresentation(
            notes=(("info", f"Contact information for {argument}."),),
            payload=form,
        )

    async def _adhoc_present_info(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A JID is required.")
        result = await self._query_info(argument)
        if isinstance(result, str):
            return self._adhoc_error(result)
        identities, features = result
        if not identities and not features:
            return self._adhoc_error(
                f"No identities or features found for {argument}.", note_type="warn"
            )
        form = self._result_form("Entity Info", argument)
        if identities:
            form.add_reported("category", ftype="text-single", label="Category")
            form.add_reported("type", ftype="text-single", label="Type")
            form.add_reported("name", ftype="text-single", label="Name")
            for category, itype, _lang, name in sorted(identities):
                form.add_item(
                    {
                        "category": category,
                        "type": itype,
                        "name": name or "",
                    }
                )
        if features:
            form.add_field(
                var="features",
                ftype="list-multi",
                label="Features",
                value=sorted(features),
            )
        return AdHocPresentation(
            notes=(("info", f"Disco info for {argument}."),),
            payload=form,
        )

    async def _adhoc_present_srv(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A domain is required.")
        domain = argument.strip()
        lookups = await self._query_srv(domain)
        rows: list[dict[str, str]] = []
        for lookup in lookups:
            if lookup.status:
                rows.append(
                    {
                        "service": lookup.label,
                        "prefix": lookup.prefix,
                        "priority": "",
                        "weight": "",
                        "port": "",
                        "target": lookup.status,
                    }
                )
                continue
            for priority, weight, port, target in lookup.records:
                rows.append(
                    {
                        "service": lookup.label,
                        "prefix": lookup.prefix,
                        "priority": priority,
                        "weight": weight,
                        "port": port,
                        "target": target,
                    }
                )
        form = self._result_table(
            "SRV Lookup",
            (
                ("service", "text-single", "Service"),
                ("prefix", "text-single", "Name"),
                ("priority", "text-single", "Priority"),
                ("weight", "text-single", "Weight"),
                ("port", "text-single", "Port"),
                ("target", "text-single", "Target"),
            ),
            rows,
            instructions=domain,
        )
        return AdHocPresentation(
            notes=(("info", f"SRV records for {domain}."),),
            payload=form,
        )

    async def _adhoc_present_tlsa(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A domain is required.")
        parsed = parse_dane_argument(argument)
        if parsed is None:
            return self._adhoc_error("Invalid TLSA lookup arguments.")
        domain, should_validate = parsed
        result = await self.cmd_tlsa(argument)
        if result.startswith("A DANE validation"):
            return self._adhoc_error(result, note_type="warn")
        form = self._result_form("DANE TLSA", domain)
        self._add_result_fields(
            form,
            (
                ("domain", "text-single", "Domain", domain),
                (
                    "validate",
                    "boolean",
                    "Certificates validated",
                    should_validate,
                ),
                ("report", "text-multi", "Report", result),
            ),
        )
        note = f"TLSA records for {domain}."
        if not should_validate:
            note = f"TLSA records for {domain} (without certificate validation)."
        return AdHocPresentation(notes=(("info", note),), payload=form)

    async def _adhoc_present_compliance(
        self, argument: str | None
    ) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A domain is required.")
        lookup = await self._query_compliance(argument.strip())
        if lookup.http_error is not None:
            return self._adhoc_error(
                f"Error fetching compliance score for {lookup.domain}: "
                f"HTTP {lookup.http_error}"
            )
        if lookup.error:
            return self._adhoc_error(
                f"Error fetching compliance score for {lookup.domain}: {lookup.error}"
            )
        if lookup.unparsed:
            return self._adhoc_error(
                f"Could not parse compliance badge for {lookup.domain}."
            )
        details = COMPLIANCE_SERVER_URL.format(domain=lookup.domain)
        if lookup.unavailable:
            form = self._result_form("Compliance Score", lookup.domain)
            self._add_result_fields(
                form,
                (
                    ("domain", "text-single", "Domain", lookup.domain),
                    ("score", "text-single", "Score", "Unavailable"),
                    ("add", "text-single", "Register", COMPLIANCE_ADD_URL),
                ),
            )
            return AdHocPresentation(
                notes=(
                    (
                        "warn",
                        f"Compliance score for {lookup.domain} is unavailable.",
                    ),
                ),
                payload=self._with_oob(
                    form, COMPLIANCE_ADD_URL, "Add this server"
                ),
            )
        form = self._result_form("Compliance Score", lookup.domain)
        self._add_result_fields(
            form,
            (
                ("domain", "text-single", "Domain", lookup.domain),
                ("score", "text-single", "Score", lookup.score),
                ("details", "text-single", "Details", details),
            ),
        )
        return AdHocPresentation(
            notes=(
                ("info", f"Compliance score for {lookup.domain}: {lookup.score}"),
            ),
            payload=self._with_oob(form, details, f"{lookup.domain} compliance"),
        )

    async def _adhoc_present_xep(self, argument: str | None) -> AdHocPresentation:
        if not argument:
            return self._adhoc_error("A XEP number is required.")
        number = normalize_xep_number(argument)
        if number is None:
            return self._adhoc_error(f'Invalid XEP number: "{argument}".')
        result = await load_xep(number)
        if isinstance(result, str):
            note_type = "warn" if "was not found" in result else "error"
            return self._adhoc_error(result, note_type=note_type)
        authors = ", ".join(result.authors) if result.authors else "Unknown"
        form = self._result_form(f"XEP-{result.number}: {result.title}")
        self._add_result_fields(
            form,
            (
                ("number", "text-single", "Number", f"XEP-{result.number}"),
                ("title", "text-single", "Title", result.title),
                ("abstract", "text-multi", "Abstract", result.abstract),
                ("authors", "text-single", "Authors", authors),
                ("status", "text-single", "Status", result.status),
                ("type", "text-single", "Type", result.type),
                ("url", "text-single", "URL", result.page_url),
            ),
        )
        return AdHocPresentation(
            notes=(("info", f"XEP-{result.number}: {result.title}"),),
            payload=self._with_oob(form, result.page_url, f"XEP-{result.number}"),
        )

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
        if self.mucs.is_invite_message(msg):
            return
        body = (msg["body"] or "").strip()
        if msg["type"] not in ("chat", "normal") or not body:
            return

        if self.is_command_message(body):
            response = await self.handle_command(body)
        else:
            response = self.intro_response()
        msg.reply(response).send()

    async def handle_command(self, body: str) -> str:
        if body.strip().lower() == COMMAND_PREFIX:
            return XMPPUtilities.intro_response()

        command, argument = self.parse_command(body)
        if not command:
            return f'Use "{COMMAND_PREFIX} help" to list all commands.'

        handler = self.commands.get(command)
        if handler is None:
            return f'Unknown command. Use "{COMMAND_PREFIX} help" to list all commands.'

        return await handler(argument)

    @staticmethod
    def intro_response() -> str:
        return (
            f"{BOT_NAME} {__version__} - diagnostics and monitoring tools for XMPP. "
            f'Use "{COMMAND_PREFIX} about" for details or '
            f'"{COMMAND_PREFIX} help" for commands.'
        )

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

        xep = await load_xep(number)
        if isinstance(xep, str):
            return xep
        return format_xep_response(xep)

    async def cmd_version(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} version - shows the version of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} version <jid>"
            )

        result = await self._query_version(argument)
        if isinstance(result, str):
            return result
        name, version, os_name = result
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

        contact_info = await self._query_contact(argument)
        if isinstance(contact_info, str):
            return contact_info

        if not contact_info:
            return f"No contact information found for service {argument}."

        lines = [f"Contact information for service {argument}:"]
        for field, values in sorted(contact_info.items()):
            if not values:
                continue
            lines.append(f"\n{contact_field_label(field)}:")
            lines.extend([f"  - {value}" for value in values])
        return "\n".join(lines)

    async def cmd_info(self, argument: str | None) -> str:
        if not argument:
            return (
                f"{COMMAND_PREFIX} info - shows the identities and features of an XMPP entity.\n"
                f"Usage: {COMMAND_PREFIX} info <jid>"
            )

        result = await self._query_info(argument)
        if isinstance(result, str):
            return result
        identities, features = result

        lines = [f"Info for {argument}:"]

        if identities:
            lines.append("\nIdentities:")
            for category, itype, _lang, name in sorted(identities):
                identity_str = f"  - {category}/{itype}"
                if name:
                    identity_str += f" ({name})"
                lines.append(identity_str)

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

        for lookup in await self._query_srv(domain):
            lines.append(f"\n{lookup.label} ({lookup.prefix}):")
            if lookup.status:
                lines.append(f"  - {lookup.status}")
                continue
            for priority, weight, port, target in lookup.records:
                lines.append(f"  - {priority} {weight} {port} {target}")

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

        lookup = await self._query_compliance(argument.strip())
        if lookup.http_error is not None:
            return (
                f"Error fetching compliance score for {lookup.domain}: "
                f"HTTP {lookup.http_error}"
            )
        if lookup.error:
            return f"Error fetching compliance score for {lookup.domain}: {lookup.error}"
        if lookup.unparsed:
            return f"Could not parse compliance badge for {lookup.domain}."
        if lookup.unavailable:
            return (
                f"Compliance score for {lookup.domain} is unavailable. "
                f"It may not be registered on compliance.conversations.im.\n"
                f"You can add it here: {COMPLIANCE_ADD_URL}"
            )
        return (
            f"Compliance score for {lookup.domain}: {lookup.score}\n"
            f"More details: {COMPLIANCE_SERVER_URL.format(domain=lookup.domain)}"
        )

    async def _query_version(
        self, jid: str
    ) -> tuple[str, str, str | None] | str:
        try:
            iq = await self.plugin["xep_0092"].get_version(jid)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Version lookup failed for %s: %s", jid, exc)
            return f"Could not retrieve version for {jid}: {exc}"

        software_version = iq["software_version"]
        os_name = software_version["os"] or None
        return (
            software_version["name"] or "unknown",
            software_version["version"] or "unknown",
            os_name,
        )

    async def _query_contact(self, jid: str) -> dict[str, list[str]] | str:
        try:
            iq = await self.plugin["xep_0030"].get_info(jid=jid)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Contact lookup failed for %s: %s", jid, exc)
            return f"Could not retrieve contact information for {jid}: {exc}"

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
        return contact_info

    async def _query_info(
        self, jid: str
    ) -> tuple[list[tuple[str, str, str, str]], list[str]] | str:
        try:
            iq = await self.plugin["xep_0030"].get_info(jid=jid)
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Info lookup failed for %s: %s", jid, exc)
            return f"Could not retrieve info for {jid}: {exc}"

        info = iq["disco_info"]
        return list(info["identities"]), sorted(info["features"])

    async def _query_srv(self, domain: str) -> list[SRVServiceLookup]:
        lookups: list[SRVServiceLookup] = []
        for service in XMPP_SERVICES:
            name = f"{service.prefix}.{domain}"
            try:
                answers = await self._resolver.resolve(name, "SRV")
                records = []
                for rdata in answers:
                    records.append(
                        f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    )
                parsed: list[tuple[str, str, str, str]] = []
                for row in sorted(records):
                    priority, weight, port, target = row.split(None, 3)
                    parsed.append((priority, weight, port, target))
                lookups.append(
                    SRVServiceLookup(service.label, service.prefix, tuple(parsed))
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                lookups.append(
                    SRVServiceLookup(
                        service.label, service.prefix, status="No records found"
                    )
                )
            except dns.exception.DNSException as exc:
                LOGGER.warning("DNS lookup failed for %s: %s", name, exc)
                lookups.append(
                    SRVServiceLookup(
                        service.label,
                        service.prefix,
                        status=f"Lookup failed: {exc}",
                    )
                )
        return lookups

    async def _query_compliance(self, domain: str) -> ComplianceLookup:
        url = COMPLIANCE_BADGE_URL.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        def fetch() -> str:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode("utf-8")

        try:
            svg = await asyncio.to_thread(fetch)
        except urllib.error.HTTPError as exc:
            return ComplianceLookup(domain=domain, http_error=exc.code)
        except (urllib.error.URLError, TimeoutError, UnicodeError) as exc:
            LOGGER.warning("Compliance lookup failed for %s: %s", domain, exc)
            return ComplianceLookup(domain=domain, error=str(exc))

        match = re.search(
            r'<text x="2255" y="140"[^>]*>\s*(.+?)\s*</text>', svg, re.DOTALL
        )
        if not match:
            return ComplianceLookup(domain=domain, unparsed=True)
        score = match.group(1).strip()
        if score == "Unavailable":
            return ComplianceLookup(domain=domain, unavailable=True)
        return ComplianceLookup(domain=domain, score=score)

    async def get_service_items(self, service: str) -> list[dict]:
        disco = self.plugin["xep_0030"]
        items = await disco.get_items(jid=service)
        return items.get("disco_items", [])


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    args = parse_args(argv)

    try:
        config = AppConfig.load(args.config)
    except (OSError, ValueError) as exc:
        LOGGER.error("Invalid configuration: %s", exc)
        raise SystemExit(2) from exc

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    xmpp = XMPPUtilities(
        config.jid, config.password, config.muc_jids, config.nick, config.invite
    )
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
