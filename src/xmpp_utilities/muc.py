from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from slixmpp import JID, Message, Presence
from slixmpp.exceptions import IqError, IqTimeout, PresenceError
from slixmpp.plugins.xep_0402.stanza import Conference
from slixmpp.plugins.xep_0410 import PingStatus

LOGGER = logging.getLogger(__name__)

BOOKMARK_NODE = "urn:xmpp:bookmarks:1"
JOIN_TIMEOUT = 30
RETRY_DELAYS = (30, 60, 120, 300)

FORGET_STATUS_CODES = frozenset({301, 307, 321, 322})
RETRY_STATUS_CODES = frozenset({332})
FORGET_JOIN_ERRORS = frozenset(
    {
        "item-not-found",
        "gone",
        "forbidden",
        "not-allowed",
        "registration-required",
    }
)

JoinOutcome = Literal["ok", "retry", "forget"]
PresenceOutcome = Literal["forget", "retry", "ignore"]


def bare_jid(value: object) -> str:
    return str(JID(str(value)).bare)


def _casefold_set(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(item.casefold() for item in values if item)


_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def parse_bool(value: object, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        folded = value.strip().casefold()
        if folded in _TRUE_VALUES:
            return True
        if folded in _FALSE_VALUES:
            return False
    raise ValueError(f"{name} must be a boolean")


def parse_jid_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(bare_jid(item.strip()) for item in value if item.strip())


def parse_jid_csv(raw: str) -> tuple[str, ...]:
    return tuple(bare_jid(item.strip()) for item in raw.split(",") if item.strip())


def parse_max_rooms(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a positive integer")
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class InviteConfig:
    enabled: bool = False
    persist: bool = True
    max_rooms: int | None = None
    allow_from: tuple[str, ...] = ()
    allow_domains: tuple[str, ...] = ()
    deny_from: tuple[str, ...] = ()
    allow_muc_hosts: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> "InviteConfig":
        max_rooms = values.get("max_rooms")
        return cls(
            enabled=parse_bool(values.get("enabled", False), "invite.enabled"),
            persist=parse_bool(values.get("persist", True), "invite.persist"),
            max_rooms=parse_max_rooms(max_rooms, "invite.max_rooms"),
            allow_from=_as_jid_tuple(values.get("allow_from", ()), "invite.allow_from"),
            allow_domains=_as_jid_tuple(
                values.get("allow_domains", ()), "invite.allow_domains"
            ),
            deny_from=_as_jid_tuple(values.get("deny_from", ()), "invite.deny_from"),
            allow_muc_hosts=_as_jid_tuple(
                values.get("allow_muc_hosts", ()), "invite.allow_muc_hosts"
            ),
        )

    def allows_invite(self, inviter: str, room: str) -> bool:
        if not self.enabled:
            return False
        inviter_bare = bare_jid(inviter).casefold()
        room_host = JID(room).domain.casefold()
        if inviter_bare in _casefold_set(self.deny_from):
            return False
        if self.allow_muc_hosts and room_host not in _casefold_set(self.allow_muc_hosts):
            return False
        if not self.allow_from and not self.allow_domains:
            return True
        if inviter_bare in _casefold_set(self.allow_from):
            return True
        inviter_domain = JID(inviter).domain.casefold()
        return inviter_domain in _casefold_set(self.allow_domains)


def _as_jid_tuple(value: object, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
        return tuple(bare_jid(item) for item in value if item)
    if isinstance(value, list):
        return parse_jid_list(value, name)
    raise ValueError(f"{name} must be an array of strings")


def classify_unavailable(
    status_codes: set[int], *, destroyed: bool, still_occupant: bool
) -> PresenceOutcome:
    if destroyed:
        return "forget"
    if still_occupant:
        return "ignore"
    if FORGET_STATUS_CODES & status_codes:
        return "forget"
    if RETRY_STATUS_CODES & status_codes:
        return "retry"
    return "retry"


def classify_join_error(condition: str | None) -> JoinOutcome:
    if condition in FORGET_JOIN_ERRORS:
        return "forget"
    return "retry"


class MucManager:
    def __init__(
        self,
        xmpp: object,
        muc_jids: tuple[str, ...],
        nick: str,
        invite: InviteConfig,
        *,
        join_timeout: float = JOIN_TIMEOUT,
        retry_delays: tuple[int, ...] = RETRY_DELAYS,
    ) -> None:
        self.xmpp = xmpp
        self.nick = nick
        self.invite = invite
        self.join_timeout = join_timeout
        self.retry_delays = retry_delays
        self.config_rooms = frozenset(bare_jid(room) for room in muc_jids)
        self.invited_rooms: set[str] = set()
        self.passwords: dict[str, str] = {}
        self.session_held: set[str] = set()
        self._occupants: dict[str, JID] = {}
        self._retry_tasks: dict[str, asyncio.Task[None]] = {}
        self._joining: set[str] = set()
        self._shutdown = False

        pep = xmpp.plugin["xep_0223"]
        pep.node_profiles[BOOKMARK_NODE] = {
            "pubsub#max_items": "max",
            "pubsub#send_last_published_item": "never",
        }
        xmpp.plugin["xep_0030"].add_feature(f"{BOOKMARK_NODE}+notify")
        xmpp.add_event_handler("groupchat_direct_invite", self.on_direct_invite)
        xmpp.add_event_handler("groupchat_invite", self.on_mediated_invite)
        xmpp.add_event_handler("groupchat_presence", self.on_groupchat_presence)
        xmpp.add_event_handler("muc_ping_changed", self.on_muc_ping_changed)

    def shutdown(self) -> None:
        self._shutdown = True
        for room, task in list(self._retry_tasks.items()):
            task.cancel()
            self._retry_tasks.pop(room, None)
        for occupant in list(self._occupants.values()):
            self._disable_ping(occupant)

    def is_invite_message(self, msg: object) -> bool:
        return isinstance(msg, Message) and (
            msg.get_plugin("groupchat_invite", check=True) is not None
            or (
                msg.get_plugin("muc", check=True) is not None
                and msg["muc"].get_plugin("invite", check=True) is not None
            )
        )

    async def start(self) -> None:
        self._shutdown = False
        self.session_held.clear()
        self._cancel_retries()
        rooms = set(self.config_rooms)
        if self.invite.persist:
            bookmarks = await self._fetch_bookmarks()
            for room, password in bookmarks.items():
                if room in self.config_rooms:
                    if password:
                        self.passwords[room] = password
                    continue
                self.invited_rooms.add(room)
                if password:
                    self.passwords[room] = password
                rooms.add(room)
        await asyncio.gather(
            *(self.join_room(room, persist=False) for room in sorted(rooms)),
            return_exceptions=True,
        )

    async def join_room(
        self, room: str, *, persist: bool, password: str | None = None
    ) -> JoinOutcome:
        room = bare_jid(room)
        if self._shutdown:
            return "retry"
        if room in self._joining or self._is_joined(room):
            return "ok"
        if password:
            self.passwords[room] = password
        self._joining.add(room)
        try:
            outcome = await self._join_once(room)
        finally:
            self._joining.discard(room)

        if outcome == "ok":
            self.session_held.discard(room)
            if persist and room not in self.config_rooms:
                self.invited_rooms.add(room)
                await self._publish_bookmark(room)
            elif room not in self.config_rooms:
                self.invited_rooms.add(room)
            return "ok"

        if outcome == "forget":
            await self._forget(room, unbookmark=room not in self.config_rooms)
            return "forget"

        self._schedule_retry(room)
        return "retry"

    async def handle_invite(
        self, room: str, inviter: str, password: str | None = None
    ) -> None:
        room = bare_jid(room)
        inviter = bare_jid(inviter)
        if not self.invite.enabled:
            LOGGER.info("Ignoring invite to %s from %s (invites disabled)", room, inviter)
            return
        if not self.invite.allows_invite(inviter, room):
            LOGGER.info(
                "Ignoring invite to %s from %s (ACL denied)", room, inviter
            )
            return
        if room in self.config_rooms and room not in self.session_held:
            if self._is_joined(room) or room in self._joining:
                LOGGER.info("Ignoring invite to %s; already configured", room)
                return
        elif room in self.invited_rooms and (
            self._is_joined(room)
            or room in self._joining
            or room in self._retry_tasks
        ):
            LOGGER.info("Ignoring invite to %s; already joined", room)
            return
        if (
            self.invite.max_rooms is not None
            and room not in self.invited_rooms
            and room not in self.config_rooms
            and len(self.invited_rooms) >= self.invite.max_rooms
        ):
            LOGGER.info(
                "Ignoring invite to %s; invited room limit %s reached",
                room,
                self.invite.max_rooms,
            )
            return

        LOGGER.info("Accepting invite to %s from %s", room, inviter)
        persist = self.invite.persist and room not in self.config_rooms
        if password:
            self.passwords[room] = password
        if room not in self.config_rooms:
            self.invited_rooms.add(room)
            if persist:
                await self._publish_bookmark(room)
        await self.join_room(room, persist=False, password=password)

    async def on_direct_invite(self, msg: Message) -> None:
        room = msg["groupchat_invite"]["jid"]
        if not room:
            return
        password = msg["groupchat_invite"]["password"] or None
        await self.handle_invite(str(room), str(msg["from"]), password)

    async def on_mediated_invite(self, msg: Message) -> None:
        room = str(msg["from"])
        inviter = msg["muc"]["invite"]["from"]
        await self.handle_invite(room, str(inviter) if inviter else str(msg["from"]))

    async def on_groupchat_presence(self, presence: Presence) -> None:
        if presence["type"] != "unavailable":
            return
        room = bare_jid(presence["from"])
        if not self._is_self_presence(presence, room):
            return
        codes = set(presence["muc"]["status_codes"] or ())
        destroyed = presence["muc"].get_plugin("destroy", check=True) is not None
        outcome = classify_unavailable(
            codes, destroyed=destroyed, still_occupant=False
        )
        LOGGER.info(
            "MUC unavailable for %s codes=%s destroy=%s outcome=%s",
            room,
            sorted(codes),
            destroyed,
            outcome,
        )
        if outcome == "forget":
            await self._forget(room, unbookmark=room not in self.config_rooms)
        elif outcome == "retry":
            self._disable_room_ping(room)
            if self._should_rejoin(room):
                self._schedule_retry(room)

    async def on_muc_ping_changed(self, event: Mapping[str, object]) -> None:
        result = event.get("result")
        key = event.get("key")
        if not isinstance(key, tuple) or len(key) != 2:
            return
        occupant = key[0]
        if not isinstance(occupant, JID):
            return
        room = bare_jid(occupant)
        if result is PingStatus.TIMEOUT:
            LOGGER.warning("MUC self-ping timed out for %s", room)
            return
        if result is not PingStatus.DISCONNECTED:
            return
        LOGGER.warning("MUC self-ping lost occupancy in %s; rejoining", room)
        self._disable_room_ping(room)
        if self._should_rejoin(room):
            self._schedule_retry(room)

    def _is_self_presence(self, presence: Presence, room: str) -> bool:
        codes = set(presence["muc"]["status_codes"] or ())
        if 110 in codes:
            return True
        occupant = self._occupants.get(room)
        if occupant is not None and presence["from"] == occupant:
            return True
        return presence["from"].resource == self.nick

    def _should_rejoin(self, room: str) -> bool:
        if room in self.config_rooms:
            return room not in self.session_held
        return room in self.invited_rooms

    def _is_joined(self, room: str) -> bool:
        joined = {
            bare_jid(item)
            for item in self.xmpp.plugin["xep_0045"].get_joined_rooms()
        }
        return room in joined

    async def _join_once(self, room: str) -> JoinOutcome:
        password = self.passwords.get(room)
        LOGGER.info("Joining MUC: %s", room)
        try:
            result = await self.xmpp.plugin["xep_0045"].join_muc_wait(
                JID(room),
                self.nick,
                password=password,
                maxstanzas=0,
                timeout=self.join_timeout,
            )
        except PresenceError as exc:
            LOGGER.warning("Could not join %s: %s", room, exc.condition)
            return classify_join_error(exc.condition)
        except TimeoutError:
            LOGGER.warning("Timed out joining %s", room)
            return "retry"
        except Exception:
            LOGGER.exception("Unexpected error joining %s", room)
            return "retry"

        presence = result[0]
        occupant = presence["from"]
        self._occupants[room] = occupant
        try:
            self.xmpp.plugin["xep_0410"].enable_self_ping(occupant)
        except Exception:
            LOGGER.exception("Could not enable MUC self-ping for %s", room)
        return "ok"

    def _schedule_retry(self, room: str) -> None:
        if self._shutdown or not self._should_rejoin(room):
            return
        existing = self._retry_tasks.get(room)
        if existing is not None and not existing.done():
            return
        self._retry_tasks[room] = asyncio.create_task(
            self._retry_loop(room), name=f"muc-retry-{room}"
        )

    async def _retry_loop(self, room: str) -> None:
        try:
            for delay in self.retry_delays:
                await asyncio.sleep(delay)
                if self._shutdown or not self._should_rejoin(room):
                    return
                outcome = await self.join_room(room, persist=False)
                if outcome != "retry":
                    return
            while not self._shutdown and self._should_rejoin(room):
                await asyncio.sleep(self.retry_delays[-1])
                if self._shutdown or not self._should_rejoin(room):
                    return
                outcome = await self.join_room(room, persist=False)
                if outcome != "retry":
                    return
        except asyncio.CancelledError:
            return
        finally:
            self._retry_tasks.pop(room, None)

    async def _forget(self, room: str, *, unbookmark: bool) -> None:
        self._cancel_retry(room)
        self._disable_room_ping(room)
        self.passwords.pop(room, None)
        self._occupants.pop(room, None)
        if room in self.config_rooms:
            self.session_held.add(room)
        else:
            self.invited_rooms.discard(room)
            if unbookmark and self.invite.persist:
                await self._retract_bookmark(room)
        if self._is_joined(room):
            try:
                self.xmpp.plugin["xep_0045"].leave_muc(JID(room), self.nick)
            except KeyError:
                pass

    async def _fetch_bookmarks(self) -> dict[str, str | None]:
        try:
            iq = await self.xmpp.plugin["xep_0060"].get_items(
                jid=None, node=BOOKMARK_NODE
            )
        except IqError as exc:
            if exc.condition == "item-not-found":
                return {}
            LOGGER.warning("Could not load MUC bookmarks: %s", exc.condition)
            return {}
        except IqTimeout:
            LOGGER.warning("Timed out loading MUC bookmarks")
            return {}
        except Exception:
            LOGGER.exception("Could not load MUC bookmarks")
            return {}

        bookmarks: dict[str, str | None] = {}
        for item in iq["pubsub"]["items"]:
            item_id = item["id"]
            if not item_id:
                continue
            conference = item.get_plugin("conference", check=True)
            if conference is None or not conference["autojoin"]:
                continue
            room = bare_jid(item_id)
            password = conference["password"] or None
            bookmarks[room] = password
        return bookmarks

    async def _publish_bookmark(self, room: str) -> None:
        conference = Conference()
        conference["autojoin"] = True
        conference["nick"] = self.nick
        password = self.passwords.get(room)
        if password:
            conference["password"] = password
        try:
            await self.xmpp.plugin["xep_0223"].store(
                conference, node=BOOKMARK_NODE, id=room
            )
        except (IqError, IqTimeout) as exc:
            LOGGER.warning("Could not bookmark %s: %s", room, exc)
        except Exception:
            LOGGER.exception("Could not bookmark %s", room)

    async def _retract_bookmark(self, room: str) -> None:
        try:
            await self.xmpp.plugin["xep_0060"].retract(
                jid=None, node=BOOKMARK_NODE, id=room, notify=True
            )
        except IqError as exc:
            if exc.condition != "item-not-found":
                LOGGER.warning("Could not unbookmark %s: %s", room, exc.condition)
        except IqTimeout:
            LOGGER.warning("Timed out unbookmarking %s", room)
        except Exception:
            LOGGER.exception("Could not unbookmark %s", room)

    def _disable_room_ping(self, room: str) -> None:
        occupant = self._occupants.get(room)
        if occupant is not None:
            self._disable_ping(occupant)

    def _disable_ping(self, occupant: JID) -> None:
        try:
            self.xmpp.plugin["xep_0410"].disable_self_ping(occupant)
        except Exception:
            LOGGER.exception("Could not disable MUC self-ping for %s", occupant)

    def _cancel_retry(self, room: str) -> None:
        task = self._retry_tasks.pop(room, None)
        if task is not None:
            task.cancel()

    def _cancel_retries(self) -> None:
        for room in list(self._retry_tasks):
            self._cancel_retry(room)
