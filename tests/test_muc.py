import unittest
from unittest.mock import AsyncMock, MagicMock

from slixmpp import JID
from slixmpp.exceptions import PresenceError
from slixmpp.plugins.xep_0410 import PingStatus
from slixmpp.stanza import Presence

from xmpp_utilities.__main__ import XMPPUtilities
from xmpp_utilities.muc import (
    InviteConfig,
    classify_join_error,
    classify_unavailable,
)


class InviteAclTests(unittest.TestCase):
    def test_disabled_rejects_everyone(self) -> None:
        config = InviteConfig()
        self.assertFalse(config.allows_invite("alice@example.org", "room@muc.example.org"))

    def test_empty_allowlists_accept_anyone(self) -> None:
        config = InviteConfig(enabled=True)
        self.assertTrue(
            config.allows_invite("alice@example.org", "room@muc.example.org")
        )

    def test_deny_from_wins(self) -> None:
        config = InviteConfig(
            enabled=True,
            allow_domains=("example.org",),
            deny_from=("alice@example.org",),
        )
        self.assertFalse(
            config.allows_invite("alice@example.org", "room@muc.example.org")
        )

    def test_allow_from_and_domain(self) -> None:
        config = InviteConfig(
            enabled=True,
            allow_from=("alice@example.org",),
            allow_domains=("trusted.example.org",),
        )
        self.assertTrue(
            config.allows_invite("alice@example.org", "room@muc.example.org")
        )
        self.assertTrue(
            config.allows_invite("bob@trusted.example.org", "room@muc.example.org")
        )
        self.assertFalse(
            config.allows_invite("mallory@evil.example", "room@muc.example.org")
        )

    def test_allow_muc_hosts(self) -> None:
        config = InviteConfig(enabled=True, allow_muc_hosts=("muc.example.org",))
        self.assertTrue(
            config.allows_invite("alice@example.org", "room@muc.example.org")
        )
        self.assertFalse(
            config.allows_invite("alice@example.org", "room@other.example.org")
        )


class ClassificationTests(unittest.TestCase):
    def test_kick_and_ban_are_forgotten(self) -> None:
        self.assertEqual(
            classify_unavailable({110, 307}, destroyed=False, still_occupant=False),
            "forget",
        )
        self.assertEqual(
            classify_unavailable({110, 301}, destroyed=False, still_occupant=False),
            "forget",
        )

    def test_destroy_is_forgotten(self) -> None:
        self.assertEqual(
            classify_unavailable({110}, destroyed=True, still_occupant=False),
            "forget",
        )

    def test_members_only_removal_is_forgotten(self) -> None:
        self.assertEqual(
            classify_unavailable({110, 322}, destroyed=False, still_occupant=False),
            "forget",
        )
        self.assertEqual(
            classify_unavailable({110, 321}, destroyed=False, still_occupant=False),
            "forget",
        )

    def test_affiliation_change_while_still_in_room_is_ignored(self) -> None:
        self.assertEqual(
            classify_unavailable({321}, destroyed=False, still_occupant=True),
            "ignore",
        )

    def test_service_shutdown_retries(self) -> None:
        self.assertEqual(
            classify_unavailable({110, 332}, destroyed=False, still_occupant=False),
            "retry",
        )

    def test_unavailable_without_kick_retries(self) -> None:
        self.assertEqual(
            classify_unavailable({110}, destroyed=False, still_occupant=False),
            "retry",
        )

    def test_join_errors(self) -> None:
        self.assertEqual(classify_join_error("forbidden"), "forget")
        self.assertEqual(classify_join_error("item-not-found"), "forget")
        self.assertEqual(classify_join_error("gone"), "forget")
        self.assertEqual(classify_join_error("remote-server-timeout"), "retry")
        self.assertEqual(classify_join_error("conflict"), "retry")
        self.assertEqual(classify_join_error("not-authorized"), "retry")


class MucManagerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.xmpp = XMPPUtilities(
            "bot@example.org",
            "password",
            ("always@muc.example.org",),
            "Bot",
            InviteConfig(enabled=True, persist=True, max_rooms=2),
        )
        self.xmpp.plugin["xep_0045"].join_muc_wait = AsyncMock(
            return_value=(self._self_presence("room@muc.example.org"), None, [], [])
        )
        self.xmpp.plugin["xep_0045"].get_joined_rooms = MagicMock(return_value=[])
        self.xmpp.plugin["xep_0045"].leave_muc = MagicMock()
        self.xmpp.plugin["xep_0060"].get_items = AsyncMock(
            return_value=self._empty_items()
        )
        self.xmpp.plugin["xep_0060"].retract = AsyncMock()
        self.xmpp.plugin["xep_0223"].store = AsyncMock()
        self.xmpp.plugin["xep_0410"].enable_self_ping = MagicMock()
        self.xmpp.plugin["xep_0410"].disable_self_ping = MagicMock()
        self.xmpp.plugin["xep_0163"].add_interest = MagicMock()

    def tearDown(self) -> None:
        self.xmpp.mucs.shutdown()
        self.xmpp.abort()

    def _empty_items(self) -> MagicMock:
        iq = MagicMock()
        iq.__getitem__.side_effect = lambda key: {"pubsub": {"items": []}}[key]
        return iq

    def _self_presence(self, room: str, codes: set[int] | None = None) -> Presence:
        presence = self.xmpp.Presence()
        presence["from"] = f"{room}/Bot"
        if codes:
            presence["type"] = "unavailable"
            presence["muc"]["status_codes"] = codes
        return presence

    async def test_start_joins_config_rooms(self) -> None:
        await self.xmpp.mucs.start()
        self.xmpp.plugin["xep_0045"].join_muc_wait.assert_awaited()
        joined_room = self.xmpp.plugin["xep_0045"].join_muc_wait.await_args.args[0]
        self.assertEqual(str(joined_room), "always@muc.example.org")
        self.xmpp.plugin["xep_0223"].store.assert_not_awaited()

    async def test_invite_joins_and_bookmarks(self) -> None:
        await self.xmpp.mucs.handle_invite(
            "lobby@muc.example.org", "alice@example.org"
        )
        self.assertIn("lobby@muc.example.org", self.xmpp.mucs.invited_rooms)
        self.xmpp.plugin["xep_0223"].store.assert_awaited()
        self.xmpp.plugin["xep_0410"].enable_self_ping.assert_called()

    async def test_disabled_invite_is_ignored(self) -> None:
        self.xmpp.mucs.invite = InviteConfig(enabled=False)
        await self.xmpp.mucs.handle_invite(
            "lobby@muc.example.org", "alice@example.org"
        )
        self.xmpp.plugin["xep_0045"].join_muc_wait.assert_not_awaited()

    async def test_max_rooms_blocks_new_invites(self) -> None:
        self.xmpp.mucs.invited_rooms.update(
            {"one@muc.example.org", "two@muc.example.org"}
        )
        await self.xmpp.mucs.handle_invite(
            "three@muc.example.org", "alice@example.org"
        )
        self.xmpp.plugin["xep_0045"].join_muc_wait.assert_not_awaited()

    async def test_kick_unbookmarks_invited_room(self) -> None:
        room = "lobby@muc.example.org"
        self.xmpp.mucs.invited_rooms.add(room)
        self.xmpp.mucs._occupants[room] = JID(f"{room}/Bot")
        presence = self._self_presence(room, {110, 307})
        await self.xmpp.mucs.on_groupchat_presence(presence)
        self.assertNotIn(room, self.xmpp.mucs.invited_rooms)
        self.xmpp.plugin["xep_0060"].retract.assert_awaited()
        self.xmpp.plugin["xep_0410"].disable_self_ping.assert_called()

    async def test_reinvite_after_kick_rejoins_and_bookmarks(self) -> None:
        room = "lobby@muc.example.org"
        self.xmpp.mucs.invited_rooms.add(room)
        await self.xmpp.mucs.on_groupchat_presence(
            self._self_presence(room, {110, 307})
        )
        self.xmpp.plugin["xep_0223"].store.reset_mock()
        await self.xmpp.mucs.handle_invite(room, "alice@example.org")
        self.assertIn(room, self.xmpp.mucs.invited_rooms)
        self.xmpp.plugin["xep_0223"].store.assert_awaited()

    async def test_config_kick_holds_until_reinvite(self) -> None:
        room = "always@muc.example.org"
        self.xmpp.mucs._occupants[room] = JID(f"{room}/Bot")
        await self.xmpp.mucs.on_groupchat_presence(
            self._self_presence(room, {110, 307})
        )
        self.assertIn(room, self.xmpp.mucs.session_held)
        self.xmpp.plugin["xep_0060"].retract.assert_not_awaited()
        await self.xmpp.mucs.handle_invite(room, "alice@example.org")
        self.assertNotIn(room, self.xmpp.mucs.session_held)
        self.xmpp.plugin["xep_0045"].join_muc_wait.assert_awaited()

    async def test_forbidden_join_forgets_invited_room(self) -> None:
        error = Presence()
        error["type"] = "error"
        error["error"]["condition"] = "forbidden"
        self.xmpp.plugin["xep_0045"].join_muc_wait = AsyncMock(
            side_effect=PresenceError(error)
        )
        await self.xmpp.mucs.handle_invite(
            "secret@muc.example.org", "alice@example.org"
        )
        self.assertNotIn("secret@muc.example.org", self.xmpp.mucs.invited_rooms)
        self.xmpp.plugin["xep_0060"].retract.assert_awaited()

    async def test_join_timeout_keeps_invited_room_for_retry(self) -> None:
        self.xmpp.mucs.retry_delays = (0.01,)
        self.xmpp.plugin["xep_0045"].join_muc_wait = AsyncMock(
            side_effect=TimeoutError()
        )
        await self.xmpp.mucs.handle_invite(
            "flaky@muc.example.org", "alice@example.org"
        )
        self.assertIn("flaky@muc.example.org", self.xmpp.mucs.invited_rooms)
        self.xmpp.plugin["xep_0223"].store.assert_awaited()
        self.assertIn("flaky@muc.example.org", self.xmpp.mucs._retry_tasks)

    async def test_self_ping_disconnect_rejoins_without_unbookmarking(self) -> None:
        room = "lobby@muc.example.org"
        occupant = JID(f"{room}/Bot")
        self.xmpp.mucs.invited_rooms.add(room)
        self.xmpp.mucs._occupants[room] = occupant
        self.xmpp.mucs.retry_delays = (0.01,)
        await self.xmpp.mucs.on_muc_ping_changed(
            {
                "key": (occupant, self.xmpp.boundjid),
                "previous": PingStatus.JOINED,
                "result": PingStatus.DISCONNECTED,
            }
        )
        self.xmpp.plugin["xep_0060"].retract.assert_not_awaited()
        self.assertIn(room, self.xmpp.mucs.invited_rooms)
        self.assertIn(room, self.xmpp.mucs._retry_tasks)

    async def test_direct_invite_message_is_not_treated_as_a_dm(self) -> None:
        msg = self.xmpp.Message()
        msg["from"] = "alice@example.org"
        msg["to"] = "bot@example.org"
        msg["type"] = "chat"
        msg["body"] = "Join this room"
        msg["groupchat_invite"]["jid"] = "lobby@muc.example.org"
        self.xmpp.send = MagicMock()
        await self.xmpp.dm_message(msg)
        self.xmpp.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
