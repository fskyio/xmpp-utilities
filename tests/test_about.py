import unittest
from unittest.mock import AsyncMock, MagicMock

from xmpp_utilities.__main__ import (
    BOT_NAME,
    XMPPUtilities,
    __homepage__,
    __issues__,
    __license__,
    __repository__,
    __version__,
)


class AboutCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_bare_prefix_shows_a_short_summary(self) -> None:
        response = await XMPPUtilities.handle_command(None, "  !XmPp  ")

        self.assertIn(f"{BOT_NAME} {__version__}", response)
        self.assertIn("!xmpp about", response)
        self.assertIn("!xmpp help", response)
        self.assertNotIn(__repository__, response)

    async def test_about_shows_full_project_information(self) -> None:
        response = await XMPPUtilities.cmd_about(None, None)

        self.assertIn(f"*{BOT_NAME} {__version__}*", response)
        self.assertIn(__homepage__, response)
        self.assertIn(__repository__, response)
        self.assertIn(__issues__, response)
        self.assertIn(f"License: {__license__}", response)

    async def test_help_lists_about(self) -> None:
        response = await XMPPUtilities.cmd_help(None, None)

        self.assertIn("!xmpp about", response)
        self.assertIn("XEP-0050", response)


class AboutParsingTests(unittest.TestCase):
    def test_parses_about_command(self) -> None:
        self.assertEqual(
            XMPPUtilities.parse_command("!xmpp about"),
            ("about", None),
        )


class DirectMessageIntroTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.xmpp = XMPPUtilities("bot@example.org", "password", (), "Bot")
        self.xmpp.handle_command = AsyncMock(return_value="handled")

    def tearDown(self) -> None:
        self.xmpp.abort()

    def _message(self, *, body: str, msg_type: str = "chat") -> MagicMock:
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {
            "body": body,
            "type": msg_type,
            "mucnick": "someone",
            "from": MagicMock(bare="room@muc.example.org"),
        }[key]
        msg.reply.return_value = MagicMock()
        return msg

    async def test_non_command_dm_gets_intro(self) -> None:
        msg = self._message(body="hello")

        await self.xmpp.dm_message(msg)

        msg.reply.assert_called_once_with(XMPPUtilities.intro_response())
        msg.reply.return_value.send.assert_called_once()
        self.xmpp.handle_command.assert_not_awaited()

    async def test_command_dm_is_still_handled(self) -> None:
        msg = self._message(body="!xmpp help")

        await self.xmpp.dm_message(msg)

        self.xmpp.handle_command.assert_awaited_once_with("!xmpp help")
        msg.reply.assert_called_once_with("handled")

    async def test_empty_dm_is_ignored(self) -> None:
        msg = self._message(body="   ")

        await self.xmpp.dm_message(msg)

        msg.reply.assert_not_called()
        self.xmpp.handle_command.assert_not_awaited()

    async def test_groupchat_type_does_not_get_intro(self) -> None:
        msg = self._message(body="hello", msg_type="groupchat")

        await self.xmpp.dm_message(msg)

        msg.reply.assert_not_called()
        self.xmpp.handle_command.assert_not_awaited()

    async def test_muc_non_command_is_ignored(self) -> None:
        msg = self._message(body="hello")
        self.xmpp.send_message = MagicMock()

        await self.xmpp.muc_message(msg)

        self.xmpp.send_message.assert_not_called()
        self.xmpp.handle_command.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
