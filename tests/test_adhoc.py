import unittest
from unittest.mock import AsyncMock

from slixmpp.plugins.xep_0004.stanza import Form
from slixmpp.plugins.xep_0050 import Command

from xmpp_utilities.__main__ import (
    ADHOC_COMMANDS,
    ADHOC_COMMANDS_NODE,
    AdHocCommand,
    AdHocField,
    XMPPUtilities,
    adhoc_argument,
    adhoc_form_values,
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

    async def test_about_completes_immediately(self) -> None:
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("about"))

        self.assertIsNone(session["next"])
        self.assertIsNone(session["payload"])
        self.assertEqual(session["notes"][0][0], "info")
        self.assertIn("XMPP Utilities", session["notes"][0][1])

    async def test_ping_asks_for_a_jid_then_runs_the_text_handler(self) -> None:
        handler = AsyncMock(return_value="Pong from target@example.org in 12.00ms")
        self.xmpp.commands["ping"] = handler
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("ping"))
        form = session["payload"]

        self.assertEqual(form["title"], "Ping")
        self.assertEqual(form.get_fields()["jid"]["type"], "jid-single")
        self.assertIsNotNone(session["next"])

        form["values"] = {"jid": "target@example.org"}
        result = await session["next"](form, session)

        handler.assert_awaited_once_with("target@example.org")
        self.assertIsNone(result["next"])
        self.assertEqual(
            result["notes"],
            [("info", "Pong from target@example.org in 12.00ms")],
        )

    async def test_tlsa_passes_the_no_validate_flag(self) -> None:
        handler = AsyncMock(return_value="TLSA report")
        self.xmpp.commands["tlsa"] = handler
        session = await self.xmpp._adhoc_start(self.xmpp.Iq(), _session("tlsa"))
        form = session["payload"]

        self.assertEqual(form.get_fields()["validate"]["type"], "boolean")
        self.assertTrue(form.get_fields()["validate"]["value"])

        form["values"] = {"domain": "example.org", "validate": False}
        result = await session["next"](form, session)

        handler.assert_awaited_once_with("example.org --no-validate")
        self.assertEqual(result["notes"], [("info", "TLSA report")])


if __name__ == "__main__":
    unittest.main()
