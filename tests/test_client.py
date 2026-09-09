import unittest

from xmpp_utilities.__main__ import BOT_NAME, XMPPUtilities, __version__


class ClientIdentityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.xmpp = XMPPUtilities("bot@example.org", "password", (), "Bot")

    def tearDown(self) -> None:
        self.xmpp.abort()

    def test_advertises_software_version(self) -> None:
        version = self.xmpp.plugin["xep_0092"]

        self.assertEqual(version.software_name, BOT_NAME)
        self.assertEqual(version.version, __version__)

    def test_registers_entity_capabilities(self) -> None:
        self.assertIn("xep_0115", self.xmpp.plugin)

    async def test_advertises_bot_identity(self) -> None:
        info = await self.xmpp.plugin["xep_0030"].get_info(local=True)
        identities = info["identities"]

        self.assertTrue(
            any(
                category == "client" and itype == "bot" and name == BOT_NAME
                for category, itype, _lang, name in identities
            )
        )


if __name__ == "__main__":
    unittest.main()
