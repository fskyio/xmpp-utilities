import unittest

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


class AboutParsingTests(unittest.TestCase):
    def test_parses_about_command(self) -> None:
        self.assertEqual(
            XMPPUtilities.parse_command("!xmpp about"),
            ("about", None),
        )


if __name__ == "__main__":
    unittest.main()
