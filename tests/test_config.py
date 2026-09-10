import tempfile
import unittest
from pathlib import Path

from xmpp_utilities.__main__ import (
    DEFAULT_NICK,
    AppConfig,
    parse_args,
    resolve_config_path,
)
from xmpp_utilities.muc import InviteConfig

MISSING_DEFAULT = Path("/nonexistent/xmpp-utilities.toml")


def load_config(
    path: Path | None = None,
    environ: dict[str, str] | None = None,
    default_path: Path = MISSING_DEFAULT,
) -> AppConfig:
    return AppConfig.load(path, default_path=default_path, environ=environ or {})


def write_toml(directory: Path, contents: str, name: str = "config.toml") -> Path:
    path = directory / name
    path.write_text(contents, encoding="utf-8")
    return path


class ParseArgsTests(unittest.TestCase):
    def test_parses_config_path(self) -> None:
        args = parse_args(["--config", "/tmp/bot.toml"])
        self.assertEqual(args.config, Path("/tmp/bot.toml"))

    def test_parses_short_config_path(self) -> None:
        args = parse_args(["-c", "xmpp-utilities.toml"])
        self.assertEqual(args.config, Path("xmpp-utilities.toml"))

    def test_config_is_optional(self) -> None:
        args = parse_args([])
        self.assertIsNone(args.config)


class ResolveConfigPathTests(unittest.TestCase):
    def test_explicit_path_wins(self) -> None:
        resolved = resolve_config_path(
            Path("~/bot.toml"),
            environ={"XMPP_UTILS_CONFIG": "/from-env.toml"},
        )
        self.assertEqual(resolved, Path("~/bot.toml").expanduser())

    def test_env_path_is_used_when_no_explicit_path(self) -> None:
        resolved = resolve_config_path(
            environ={"XMPP_UTILS_CONFIG": "~/from-env.toml"},
            default_path=MISSING_DEFAULT,
        )
        self.assertEqual(resolved, Path("~/from-env.toml").expanduser())

    def test_default_file_is_used_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            default_path = write_toml(Path(tmp), "jid = 'bot@example.org'\n")
            resolved = resolve_config_path(default_path=default_path, environ={})
            self.assertEqual(resolved, default_path)

    def test_missing_default_returns_none(self) -> None:
        resolved = resolve_config_path(default_path=MISSING_DEFAULT, environ={})
        self.assertIsNone(resolved)


class AppConfigLoadTests(unittest.TestCase):
    def test_load_from_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "bot@example.org"',
                        'password = "secret"',
                        'nick = "Bot"',
                        "mucs = [",
                        '  "room@muc.example.org",',
                        '  " lobby@muc.example.org ",',
                        '  "",',
                        "]",
                    ]
                ),
            )
            config = load_config(path)
            self.assertEqual(config.jid, "bot@example.org")
            self.assertEqual(config.password, "secret")
            self.assertEqual(config.nick, "Bot")
            self.assertEqual(
                config.muc_jids,
                ("room@muc.example.org", "lobby@muc.example.org"),
            )

    def test_load_from_env(self) -> None:
        config = load_config(
            environ={
                "XMPP_UTILS_JID": "bot@example.org",
                "XMPP_UTILS_PASSWORD": "secret",
                "XMPP_UTILS_NICK": "Bot",
                "XMPP_UTILS_MUCS": "a@muc.example.org, b@muc.example.org, ",
            }
        )
        self.assertEqual(config.jid, "bot@example.org")
        self.assertEqual(config.password, "secret")
        self.assertEqual(config.nick, "Bot")
        self.assertEqual(
            config.muc_jids, ("a@muc.example.org", "b@muc.example.org")
        )

    def test_env_overrides_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "file@example.org"',
                        'password = "file-secret"',
                        'nick = "File"',
                        'mucs = ["file@muc.example.org"]',
                    ]
                ),
            )
            config = load_config(
                path,
                environ={
                    "XMPP_UTILS_JID": "env@example.org",
                    "XMPP_UTILS_PASSWORD": "env-secret",
                    "XMPP_UTILS_NICK": "Env",
                    "XMPP_UTILS_MUCS": "env@muc.example.org",
                },
            )
            self.assertEqual(config.jid, "env@example.org")
            self.assertEqual(config.password, "env-secret")
            self.assertEqual(config.nick, "Env")
            self.assertEqual(config.muc_jids, ("env@muc.example.org",))

    def test_unset_env_does_not_override_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "file@example.org"',
                        'password = "file-secret"',
                        'nick = "File"',
                        'mucs = ["file@muc.example.org"]',
                    ]
                ),
            )
            config = load_config(
                path, environ={"XMPP_UTILS_NICK": "Env"}
            )
            self.assertEqual(config.jid, "file@example.org")
            self.assertEqual(config.password, "file-secret")
            self.assertEqual(config.nick, "Env")
            self.assertEqual(config.muc_jids, ("file@muc.example.org",))

    def test_password_can_come_from_env_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                'jid = "bot@example.org"\nmucs = ["room@muc.example.org"]\n',
            )
            config = load_config(
                path, environ={"XMPP_UTILS_PASSWORD": "env-secret"}
            )
            self.assertEqual(config.password, "env-secret")
            self.assertEqual(config.nick, DEFAULT_NICK)

    def test_empty_nick_uses_default(self) -> None:
        config = load_config(
            environ={
                "XMPP_UTILS_JID": "bot@example.org",
                "XMPP_UTILS_PASSWORD": "secret",
                "XMPP_UTILS_NICK": "  ",
            }
        )
        self.assertEqual(config.nick, DEFAULT_NICK)

    def test_ignores_unknown_toml_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "bot@example.org"',
                        'password = "secret"',
                        "[other]",
                        "enabled = true",
                    ]
                ),
            )
            config = load_config(path)
            self.assertEqual(config.jid, "bot@example.org")

    def test_missing_required_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "jid, password"):
            load_config(environ={})

        with self.assertRaisesRegex(ValueError, "password"):
            load_config(environ={"XMPP_UTILS_JID": "bot@example.org"})

    def test_missing_config_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "Config file not found"):
            load_config(Path("/nonexistent/bot.toml"))

    def test_invalid_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(Path(tmp), "jid = [\n")
            with self.assertRaisesRegex(ValueError, "Invalid TOML"):
                load_config(path)

    def test_mucs_must_be_an_array_of_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                'jid = "bot@example.org"\npassword = "secret"\nmucs = "room@muc.example.org"\n',
            )
            with self.assertRaisesRegex(ValueError, "mucs must be an array"):
                load_config(path)

    def test_jid_must_be_a_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(Path(tmp), "jid = 1\npassword = 'secret'\n")
            with self.assertRaisesRegex(ValueError, "jid must be a string"):
                load_config(path)

    def test_loads_default_path_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            default_path = write_toml(
                Path(tmp),
                'jid = "bot@example.org"\npassword = "secret"\n',
                name="xmpp-utilities.toml",
            )
            config = load_config(default_path=default_path)
            self.assertEqual(config.jid, "bot@example.org")

    def test_invite_defaults_are_disabled_and_unlimited(self) -> None:
        config = load_config(
            environ={
                "XMPP_UTILS_JID": "bot@example.org",
                "XMPP_UTILS_PASSWORD": "secret",
            }
        )
        self.assertEqual(config.invite, InviteConfig())

    def test_load_invite_table_from_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "bot@example.org"',
                        'password = "secret"',
                        "[invite]",
                        "enabled = true",
                        "persist = false",
                        "max_rooms = 8",
                        'allow_from = [" alice@example.org "]',
                        'allow_domains = ["trusted.example.org"]',
                        'deny_from = ["spammer@example.org"]',
                        'allow_muc_hosts = ["muc.example.org"]',
                    ]
                ),
            )
            config = load_config(path)
            self.assertEqual(
                config.invite,
                InviteConfig(
                    enabled=True,
                    persist=False,
                    max_rooms=8,
                    allow_from=("alice@example.org",),
                    allow_domains=("trusted.example.org",),
                    deny_from=("spammer@example.org",),
                    allow_muc_hosts=("muc.example.org",),
                ),
            )

    def test_invite_env_overlays_individual_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                "\n".join(
                    [
                        'jid = "bot@example.org"',
                        'password = "secret"',
                        "[invite]",
                        "enabled = false",
                        'allow_from = ["alice@example.org"]',
                    ]
                ),
            )
            config = load_config(
                path,
                environ={"XMPP_UTILS_INVITE_ENABLED": "true"},
            )
            self.assertTrue(config.invite.enabled)
            self.assertEqual(config.invite.allow_from, ("alice@example.org",))

    def test_invite_env_parses_lists_and_max_rooms(self) -> None:
        config = load_config(
            environ={
                "XMPP_UTILS_JID": "bot@example.org",
                "XMPP_UTILS_PASSWORD": "secret",
                "XMPP_UTILS_INVITE_ENABLED": "yes",
                "XMPP_UTILS_INVITE_PERSIST": "0",
                "XMPP_UTILS_INVITE_MAX_ROOMS": "3",
                "XMPP_UTILS_INVITE_ALLOW_FROM": "a@example.org, b@example.org",
                "XMPP_UTILS_INVITE_ALLOW_DOMAINS": "example.org",
                "XMPP_UTILS_INVITE_DENY_FROM": "bad@example.org",
                "XMPP_UTILS_INVITE_ALLOW_MUC_HOSTS": "muc.example.org",
            }
        )
        self.assertEqual(
            config.invite,
            InviteConfig(
                enabled=True,
                persist=False,
                max_rooms=3,
                allow_from=("a@example.org", "b@example.org"),
                allow_domains=("example.org",),
                deny_from=("bad@example.org",),
                allow_muc_hosts=("muc.example.org",),
            ),
        )

    def test_invite_max_rooms_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                'jid = "bot@example.org"\npassword = "secret"\n[invite]\nmax_rooms = 0\n',
            )
            with self.assertRaisesRegex(ValueError, "invite.max_rooms"):
                load_config(path)

    def test_invite_must_be_a_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_toml(
                Path(tmp),
                'jid = "bot@example.org"\npassword = "secret"\ninvite = true\n',
            )
            with self.assertRaisesRegex(ValueError, "invite must be a table"):
                load_config(path)
