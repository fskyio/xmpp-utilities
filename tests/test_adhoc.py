import unittest
from unittest.mock import AsyncMock, patch

from slixmpp.plugins.xep_0004.stanza import Form
from slixmpp.plugins.xep_0050 import Command
from slixmpp.plugins.xep_0066.stanza import OOB

from xmpp_utilities.__main__ import (
    ADHOC_COMMANDS,
    ADHOC_COMMANDS_NODE,
    BOT_DESCRIPTION,
    BOT_NAME,
    COMPLIANCE_ADD_URL,
    COMPLIANCE_SERVER_URL,
    AdHocCommand,
    AdHocField,
    ComplianceLookup,
    SRVServiceLookup,
    XEPInfo,
    XMPPUtilities,
    __homepage__,
    __issues__,
    __license__,
    __repository__,
    __version__,
    adhoc_argument,
    adhoc_form_values,
    adhoc_note_type,
    contact_field_label,
)


def _session(node: str) -> dict:
    return {
        "id": "session-1",
        "from": "user@example.org",
        "to": "bot@example.org",
        "node": node,
        "payload": None,
        "interfaces": set(),
        "payload_classes": set(),
        "notes": None,
        "has_next": False,
        "allow_complete": False,
        "allow_prev": False,
        "past": [],
        "next": None,
        "prev": None,
        "cancel": None,
    }


def _form_and_oob(payload: object) -> tuple[Form, OOB]:
    assert isinstance(payload, list)
    form, oob = payload
    assert isinstance(form, Form)
    assert isinstance(oob, OOB)
    return form, oob


def _field_values(form: Form) -> dict[str, object]:
    return {var: field["value"] for var, field in form.get_fields().items()}


class AdHocArgumentTests(unittest.TestCase):
    def test_returns_none_without_fields(self) -> None:
        spec = AdHocCommand("about", "About", "about", "About this bot.")

        self.assertIsNone(adhoc_argument(spec, {}))

    def test_reads_the_first_field(self) -> None:
        spec = AdHocCommand(
            "ping",
            "Ping",
            "ping",
            "Ping an entity.",
            (AdHocField("jid", "jid-single", "JID"),),
        )

        self.assertEqual(
            adhoc_argument(spec, {"jid": " target@example.org "}),
            "target@example.org",
        )
        self.assertIsNone(adhoc_argument(spec, {}))
        self.assertIsNone(adhoc_argument(spec, {"jid": "  "}))

    def test_tlsa_validate_flag(self) -> None:
        spec = AdHocCommand(
            "tlsa",
            "DANE TLSA",
            "tlsa",
            "Lookup TLSA records.",
            (
                AdHocField("domain", "text-single", "Domain"),
                AdHocField("validate", "boolean", "Validate", required=False, value=True),
            ),
        )

        self.assertEqual(adhoc_argument(spec, {"domain": "example.org"}), "example.org")
        self.assertEqual(
            adhoc_argument(spec, {"domain": "example.org", "validate": False}),
            "example.org --no-validate",
        )
        self.assertEqual(
            adhoc_argument(spec, {"domain": "example.org", "validate": "0"}),
            "example.org --no-validate",
        )
        self.assertIsNone(adhoc_argument(spec, {"validate": False}))

    def test_reads_values_from_a_form_payload(self) -> None:
        form = Form()
        form.add_field(var="jid", ftype="jid-single", value="room@muc.example.org")

        self.assertEqual(adhoc_form_values(form)["jid"], "room@muc.example.org")
        self.assertEqual(adhoc_form_values([form])["jid"], "room@muc.example.org")
        self.assertEqual(adhoc_form_values(None), {})
        self.assertEqual(adhoc_form_values([]), {})

    def test_note_type_and_contact_labels(self) -> None:
        self.assertEqual(adhoc_note_type("Pong from a@b in 1ms"), "info")
        self.assertEqual(adhoc_note_type("Ping failed for a@b: timeout"), "error")
        self.assertEqual(
            adhoc_note_type("A DANE validation is already running. Please try again shortly."),
            "warn",
        )
        self.assertEqual(contact_field_label("admin-addresses"), "Admin")


class AdHocCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.xmpp = XMPPUtilities("bot@example.org", "password", (), "Bot")

    def tearDown(self) -> None:
        self.xmpp.abort()

    async def test_disco_lists_adhoc_commands(self) -> None:
        self.xmpp.register_adhoc_commands()

        info = await self.xmpp.plugin["xep_0030"].get_info(local=True)
        items = await self.xmpp.plugin["xep_0030"].get_items(
            jid=self.xmpp.boundjid,
            node=ADHOC_COMMANDS_NODE,
            local=True,
        )

        self.assertIn(Command.namespace, info["features"])
        listed = items["items"]
        nodes = {node for _jid, node, _name in listed}
        names = {name for _jid, _node, name in listed}
        self.assertEqual(nodes, {command.node for command in ADHOC_COMMANDS})
        self.assertEqual(names, {command.name for command in ADHOC_COMMANDS})
        self.assertNotIn("help", nodes)
        self.assertNotIn("dane", nodes)

    async def test_about_uses_a_result_form_without_chat_markup(self) -> None:
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("about"))
        form, oob = _form_and_oob(session["payload"])
        values = _field_values(form)

        self.assertIsNone(session["next"])
        self.assertEqual(session["notes"], [("info", f"{BOT_NAME} {__version__}")])
        self.assertNotIn("*", session["notes"][0][1])
        self.assertNotIn("!xmpp help", str(values))
        self.assertEqual(form["title"], BOT_NAME)
        self.assertEqual(form["instructions"], BOT_DESCRIPTION)
        self.assertEqual(values["version"], __version__)
        self.assertEqual(values["homepage"], __homepage__)
        self.assertEqual(values["repository"], __repository__)
        self.assertEqual(values["issues"], __issues__)
        self.assertEqual(values["license"], __license__)
        self.assertEqual(oob["url"], __homepage__)

    async def test_ping_stays_a_note_and_rejects_a_missing_jid(self) -> None:
        handler = AsyncMock(return_value="Pong from target@example.org in 12.00ms")
        self.xmpp.commands["ping"] = handler
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("ping"))
        form = session["payload"]
        form["values"] = {"jid": "target@example.org"}
        result = await session["next"](form, session)

        handler.assert_awaited_once_with("target@example.org")
        self.assertIsNone(result["payload"])
        self.assertEqual(
            result["notes"],
            [("info", "Pong from target@example.org in 12.00ms")],
        )

        missing = await self.xmpp._adhoc_finish(_session("ping"), "ping", None)
        self.assertEqual(missing["notes"], [("error", "A JID is required.")])
        self.assertNotIn("!xmpp", missing["notes"][0][1])

    async def test_ping_failures_use_an_error_note(self) -> None:
        self.xmpp.commands["ping"] = AsyncMock(
            return_value="Ping failed for missing@example.org: timeout"
        )
        result = await self.xmpp._adhoc_finish(
            _session("ping"), "ping", "missing@example.org"
        )

        self.assertEqual(result["notes"][0][0], "error")
        self.assertIsNone(result["payload"])

    async def test_version_uses_labeled_fields(self) -> None:
        self.xmpp._query_version = AsyncMock(  # type: ignore[method-assign]
            return_value=("Prosody", "0.12.4", "Linux")
        )
        result = await self.xmpp._adhoc_finish(
            _session("version"), "version", "example.org"
        )
        form = result["payload"]
        values = _field_values(form)

        self.assertEqual(
            result["notes"],
            [("info", "example.org is running Prosody 0.12.4 on Linux.")],
        )
        self.assertEqual(form["title"], "Software Version")
        self.assertEqual(values["name"], "Prosody")
        self.assertEqual(values["version"], "0.12.4")
        self.assertEqual(values["os"], "Linux")

    async def test_items_uses_a_result_table(self) -> None:
        self.xmpp.get_service_items = AsyncMock(  # type: ignore[method-assign]
            return_value=[
                {"jid": "muc.example.org", "name": "Chatrooms"},
                {"jid": "pubsub.example.org"},
            ]
        )
        result = await self.xmpp._adhoc_finish(
            _session("items"), "items", "example.org"
        )
        form = result["payload"]

        self.assertEqual(
            result["notes"],
            [("info", "Found 2 items for example.org.")],
        )
        self.assertEqual(
            form["items"],
            [
                {"jid": "muc.example.org", "name": "Chatrooms"},
                {"jid": "pubsub.example.org", "name": ""},
            ],
        )

    async def test_contact_uses_labeled_address_fields(self) -> None:
        self.xmpp._query_contact = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "admin-addresses": [
                    "mailto:admin@example.org",
                    "xmpp:admin@example.org",
                ],
                "abuse-addresses": ["mailto:abuse@example.org"],
            }
        )
        result = await self.xmpp._adhoc_finish(
            _session("contact"), "contact", "example.org"
        )
        values = _field_values(result["payload"])

        self.assertEqual(
            result["notes"],
            [("info", "Contact information for example.org.")],
        )
        self.assertEqual(values["abuse-addresses"], "mailto:abuse@example.org")
        self.assertEqual(
            values["admin-addresses"],
            ["mailto:admin@example.org", "xmpp:admin@example.org"],
        )

    async def test_info_uses_identities_table_and_feature_list(self) -> None:
        self.xmpp._query_info = AsyncMock(  # type: ignore[method-assign]
            return_value=(
                [("server", "im", "", "Prosody")],
                ["http://jabber.org/protocol/disco#info"],
            )
        )
        result = await self.xmpp._adhoc_finish(_session("info"), "info", "example.org")
        form = result["payload"]
        values = _field_values(form)

        self.assertEqual(result["notes"], [("info", "Disco info for example.org.")])
        self.assertEqual(
            form["items"],
            [{"category": "server", "type": "im", "name": "Prosody"}],
        )
        self.assertEqual(
            values["features"], ["http://jabber.org/protocol/disco#info"]
        )

    async def test_srv_uses_a_result_table(self) -> None:
        self.xmpp._query_srv = AsyncMock(  # type: ignore[method-assign]
            return_value=[
                SRVServiceLookup(
                    "Client-to-Server",
                    "_xmpp-client._tcp",
                    records=(("0", "0", "5222", "xmpp.example.org."),),
                ),
                SRVServiceLookup(
                    "Server-to-Server",
                    "_xmpp-server._tcp",
                    status="No records found",
                ),
            ]
        )
        result = await self.xmpp._adhoc_finish(_session("srv"), "srv", "example.org")
        form = result["payload"]

        self.assertEqual(result["notes"], [("info", "SRV records for example.org.")])
        self.assertEqual(
            form["items"],
            [
                {
                    "service": "Client-to-Server",
                    "prefix": "_xmpp-client._tcp",
                    "priority": "0",
                    "weight": "0",
                    "port": "5222",
                    "target": "xmpp.example.org.",
                },
                {
                    "service": "Server-to-Server",
                    "prefix": "_xmpp-server._tcp",
                    "priority": "",
                    "weight": "",
                    "port": "",
                    "target": "No records found",
                },
            ],
        )

    async def test_tlsa_puts_the_report_in_a_text_field(self) -> None:
        report = "TLSA records for example.org:\n  - 3 1 1 DEADBEEF"
        self.xmpp.cmd_tlsa = AsyncMock(return_value=report)  # type: ignore[method-assign]
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("tlsa"))
        form = session["payload"]
        form["values"] = {"domain": "example.org", "validate": False}
        result = await session["next"](form, session)
        values = _field_values(result["payload"])

        self.xmpp.cmd_tlsa.assert_awaited_once_with("example.org --no-validate")
        self.assertEqual(
            result["notes"],
            [
                (
                    "info",
                    "TLSA records for example.org (without certificate validation).",
                )
            ],
        )
        self.assertEqual(values["domain"], "example.org")
        self.assertFalse(values["validate"])
        self.assertEqual("\n".join(values["report"]), report)

    async def test_compliance_uses_a_score_field_and_oob_link(self) -> None:
        self.xmpp._query_compliance = AsyncMock(  # type: ignore[method-assign]
            return_value=ComplianceLookup(domain="example.org", score="100%")
        )
        result = await self.xmpp._adhoc_finish(
            _session("compliance"), "compliance", "example.org"
        )
        form, oob = _form_and_oob(result["payload"])
        values = _field_values(form)
        details = COMPLIANCE_SERVER_URL.format(domain="example.org")

        self.assertEqual(
            result["notes"],
            [("info", "Compliance score for example.org: 100%")],
        )
        self.assertEqual(values["score"], "100%")
        self.assertEqual(values["details"], details)
        self.assertEqual(oob["url"], details)

    async def test_unavailable_compliance_warns_and_links_to_registration(self) -> None:
        self.xmpp._query_compliance = AsyncMock(  # type: ignore[method-assign]
            return_value=ComplianceLookup(domain="example.org", unavailable=True)
        )
        result = await self.xmpp._adhoc_finish(
            _session("compliance"), "compliance", "example.org"
        )
        form, oob = _form_and_oob(result["payload"])

        self.assertEqual(result["notes"][0][0], "warn")
        self.assertEqual(_field_values(form)["score"], "Unavailable")
        self.assertEqual(oob["url"], COMPLIANCE_ADD_URL)

    async def test_xep_uses_a_result_form_without_chat_markup(self) -> None:
        xep = XEPInfo(
            number="0050",
            title="Ad-Hoc Commands",
            abstract="A workflow protocol.",
            authors=("Matthew Miller",),
            status="Final",
            type="Standards Track",
        )
        with patch("xmpp_utilities.__main__.load_xep", new=AsyncMock(return_value=xep)):
            result = await self.xmpp._adhoc_finish(_session("xep"), "xep", "50")
        form, oob = _form_and_oob(result["payload"])
        values = _field_values(form)

        self.assertEqual(result["notes"], [("info", "XEP-0050: Ad-Hoc Commands")])
        self.assertNotIn("*", result["notes"][0][1])
        self.assertEqual(form["title"], "XEP-0050: Ad-Hoc Commands")
        self.assertEqual(values["abstract"], ["A workflow protocol."])
        self.assertEqual(values["authors"], "Matthew Miller")
        self.assertEqual(oob["url"], xep.page_url)


if __name__ == "__main__":
    unittest.main()
