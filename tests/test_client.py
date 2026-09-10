import struct
import unittest
from unittest.mock import AsyncMock

from slixmpp.exceptions import IqTimeout
from slixmpp.plugins.xep_0084.stanza import MetaData
from slixmpp.xmlstream.tostring import tostring

from xmpp_utilities.__main__ import (
    AVATAR_HEIGHT,
    AVATAR_TYPE,
    AVATAR_WIDTH,
    BOT_DESCRIPTION,
    BOT_NAME,
    BOT_ORG,
    XMPPUtilities,
    __homepage__,
    __version__,
    avatar_metadata_item,
    load_avatar,
)


def png_dimensions(data: bytes) -> tuple[int, int]:
    return struct.unpack(">II", data[16:24])


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

    def test_registers_profile_plugins(self) -> None:
        for plugin in ("xep_0054", "xep_0084", "xep_0153", "xep_0163", "xep_0172"):
            self.assertIn(plugin, self.xmpp.plugin)

    def test_registers_muc_invite_plugins(self) -> None:
        for plugin in (
            "xep_0060",
            "xep_0223",
            "xep_0249",
            "xep_0402",
            "xep_0410",
        ):
            self.assertIn(plugin, self.xmpp.plugin)

    def test_registers_adhoc_commands_plugin(self) -> None:
        self.assertIn("xep_0050", self.xmpp.plugin)

    async def test_advertises_bot_identity(self) -> None:
        info = await self.xmpp.plugin["xep_0030"].get_info(local=True)
        identities = info["identities"]

        self.assertTrue(
            any(
                category == "client" and itype == "bot" and name == BOT_NAME
                for category, itype, _lang, name in identities
            )
        )

    def test_bundled_avatar_is_a_small_png(self) -> None:
        avatar = load_avatar()
        width, height = png_dimensions(avatar)

        self.assertTrue(avatar.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual((width, height), (AVATAR_WIDTH, AVATAR_HEIGHT))
        self.assertLess(len(avatar), 8 * 1024)

    def test_load_avatar_works_from_source_checkout_import(self) -> None:
        import src.xmpp_utilities.__main__ as checkout_main

        self.assertEqual(checkout_main.load_avatar(), load_avatar())

    def test_vcard_includes_name_details_and_avatar(self) -> None:
        avatar = load_avatar()
        vcard = self.xmpp.build_vcard(avatar)

        self.assertEqual(vcard["FN"], "Bot")
        self.assertEqual(vcard["NICKNAME"], ["Bot"])
        self.assertEqual(vcard["DESC"], BOT_DESCRIPTION)
        self.assertEqual(vcard["URL"], __homepage__)
        self.assertEqual(str(vcard["JABBERID"]), "bot@example.org")
        self.assertEqual(vcard["ORG"]["ORGNAME"], BOT_ORG)
        self.assertEqual(vcard["PHOTO"]["TYPE"], AVATAR_TYPE)
        self.assertEqual(vcard["PHOTO"]["BINVAL"], avatar)
        tostring(vcard.xml)

    def test_avatar_metadata_serializes_with_string_dimensions(self) -> None:
        avatar = load_avatar()
        avatar_id = self.xmpp.plugin["xep_0084"].generate_id(avatar)
        item = avatar_metadata_item(avatar, avatar_id)
        metadata = MetaData()
        metadata.add_info(
            item["id"],
            item["type"],
            item["bytes"],
            height=item["height"],
            width=item["width"],
        )

        xml = tostring(metadata.xml)
        self.assertIn(f'bytes="{len(avatar)}"', xml)
        self.assertIn(f'width="{AVATAR_WIDTH}"', xml)
        self.assertIn(f'height="{AVATAR_HEIGHT}"', xml)

    async def test_advertise_profile_publishes_vcard_nick_and_avatar(self) -> None:
        avatar = load_avatar()
        avatar_id = self.xmpp.plugin["xep_0084"].generate_id(avatar)
        publish_vcard = AsyncMock()
        publish_nick = AsyncMock()
        publish_avatar = AsyncMock()
        publish_metadata = AsyncMock()

        self.xmpp.plugin["xep_0054"].publish_vcard = publish_vcard
        self.xmpp.plugin["xep_0172"].publish_nick = publish_nick
        self.xmpp.plugin["xep_0084"].publish_avatar = publish_avatar
        self.xmpp.plugin["xep_0084"].publish_avatar_metadata = publish_metadata

        await self.xmpp.advertise_profile()

        published_vcard = publish_vcard.await_args.args[0]
        self.assertEqual(published_vcard["FN"], "Bot")
        self.assertEqual(published_vcard["PHOTO"]["BINVAL"], avatar)
        self.assertEqual(
            await self.xmpp.plugin["xep_0153"].api["get_hash"](self.xmpp.boundjid),
            avatar_id,
        )
        publish_nick.assert_awaited_with(nick="Bot")
        publish_avatar.assert_awaited_with(avatar)
        publish_metadata.assert_awaited_with(
            items=avatar_metadata_item(avatar, avatar_id)
        )

    async def test_advertise_profile_continues_if_vcard_publish_fails(self) -> None:
        self.xmpp.plugin["xep_0054"].publish_vcard = AsyncMock(
            side_effect=IqTimeout(None)
        )
        publish_nick = AsyncMock()
        publish_avatar = AsyncMock()
        publish_metadata = AsyncMock()
        self.xmpp.plugin["xep_0172"].publish_nick = publish_nick
        self.xmpp.plugin["xep_0084"].publish_avatar = publish_avatar
        self.xmpp.plugin["xep_0084"].publish_avatar_metadata = publish_metadata

        with self.assertLogs("xmpp_utilities.__main__", level="WARNING"):
            await self.xmpp.advertise_profile()

        publish_nick.assert_awaited()
        publish_avatar.assert_awaited()
        publish_metadata.assert_awaited()

    async def test_start_advertises_profile_before_presence(self) -> None:
        order: list[str] = []

        async def advertise() -> None:
            order.append("advertise")

        async def update_caps() -> None:
            order.append("caps")

        def send_presence(**kwargs: object) -> None:
            order.append("presence")
            self.assertEqual(kwargs, {"pnick": "Bot"})

        async def get_roster() -> None:
            order.append("roster")

        async def muc_start() -> None:
            order.append("mucs")

        def register_adhoc() -> None:
            order.append("adhoc")

        self.xmpp.advertise_profile = advertise  # type: ignore[method-assign]
        self.xmpp.register_adhoc_commands = register_adhoc  # type: ignore[method-assign]
        self.xmpp.plugin["xep_0115"].update_caps = update_caps
        self.xmpp.send_presence = send_presence  # type: ignore[method-assign]
        self.xmpp.get_roster = get_roster  # type: ignore[method-assign]
        self.xmpp.mucs.start = muc_start  # type: ignore[method-assign]

        await self.xmpp.start(None)

        self.assertEqual(
            order, ["advertise", "adhoc", "caps", "presence", "roster", "mucs"]
        )


if __name__ == "__main__":
    unittest.main()
