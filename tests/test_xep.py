import unittest
from unittest.mock import patch

from xmpp_utilities.__main__ import (
    XEPInfo,
    XMPPUtilities,
    format_xep_response,
    normalize_xep_number,
    parse_xep_document,
)


class NormalizeXEPNumberTests(unittest.TestCase):
    def test_accepts_common_spellings(self) -> None:
        spellings = (
            "XEP-0516",
            "XEP-516",
            "XEP0516",
            "XEP516",
            "xep 516",
            "XEP_516",
            "XEP #516",
            "XEP–516",
            "0516",
            "516",
            "https://xmpp.org/extensions/xep-0516.html",
        )

        for spelling in spellings:
            with self.subTest(spelling=spelling):
                self.assertEqual(normalize_xep_number(spelling), "0516")

    def test_rejects_invalid_values(self) -> None:
        for value in ("", "XEP", "0", "XEP-0000", "XEP-12345", "XEP-51six"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_xep_number(value))


class ParseXEPDocumentTests(unittest.TestCase):
    def test_parses_header_metadata_and_inline_abstract_text(self) -> None:
        document = b"""\
<xep>
  <header>
    <title>Example &amp; Test</title>
    <abstract>This defines <link url="https://example.com">useful things</link>.</abstract>
    <number>42</number>
    <status>Experimental</status>
    <type>Standards Track</type>
    <author><firstname>Alice</firstname><surname>Example</surname></author>
    <author><firstname>Bob</firstname><surname>Tester</surname></author>
  </header>
</xep>
"""

        xep = parse_xep_document(document, "0042")

        self.assertEqual(xep.number, "0042")
        self.assertEqual(xep.title, "Example & Test")
        self.assertEqual(xep.abstract, "This defines useful things.")
        self.assertEqual(xep.authors, ("Alice Example", "Bob Tester"))
        self.assertEqual(xep.status, "Experimental")
        self.assertEqual(xep.type, "Standards Track")

    def test_rejects_a_document_without_required_metadata(self) -> None:
        with self.assertRaises(ValueError):
            parse_xep_document(b"<xep><header><number>42</number></header></xep>", "0042")


class FormatXEPResponseTests(unittest.TestCase):
    def test_formats_with_xep_0393_strong_emphasis(self) -> None:
        response = format_xep_response(
            XEPInfo(
                number="0042",
                title="Tea & Biscuits",
                abstract="An <excellent> example.",
                authors=("Alice Example", "Bob Tester"),
                status="Final",
                type="Standards Track",
            )
        )

        self.assertIn("*XEP-0042: Tea & Biscuits*", response)
        self.assertIn("Authors: Alice Example, Bob Tester", response)
        self.assertIn("https://xmpp.org/extensions/xep-0042.html", response)
        self.assertNotIn("**XEP-0042", response)


class CommandParsingTests(unittest.TestCase):
    def test_parses_xep_shortcut(self) -> None:
        self.assertEqual(
            XMPPUtilities.parse_command("!xep XEP-0516"),
            ("xep", "XEP-0516"),
        )

    def test_parses_xep_subcommand(self) -> None:
        self.assertEqual(
            XMPPUtilities.parse_command("!xmpp xep 516"),
            ("xep", "516"),
        )


class XEPCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_help_uses_xmpp_xep_as_the_primary_command(self) -> None:
        response = await XMPPUtilities.cmd_help(None, None)

        self.assertIn("!xmpp xep <number>", response)
        self.assertIn("alias: !xep <number>", response)

    async def test_usage_uses_xmpp_xep_as_the_primary_command(self) -> None:
        response = await XMPPUtilities.cmd_xep(None, None)

        self.assertIn("Usage: !xmpp xep <number>", response)
        self.assertIn("alias: !xep <number>", response)

    async def test_returns_formatted_lookup_result(self) -> None:
        xep = XEPInfo(
            number="0516",
            title="XMPP Decentralized ID (XID)",
            abstract="A short abstract.",
            authors=("Jérôme Poisson",),
            status="Experimental",
            type="Standards Track",
        )

        with patch("xmpp_utilities.__main__.fetch_xep", return_value=xep) as fetch:
            response = await XMPPUtilities.cmd_xep(None, "XEP-516")

        self.assertIsInstance(response, str)
        self.assertIn("XEP-0516", response)
        fetch.assert_called_once_with("0516")

    async def test_rejects_an_invalid_number_without_fetching(self) -> None:
        with patch("xmpp_utilities.__main__.fetch_xep") as fetch:
            response = await XMPPUtilities.cmd_xep(None, "not-a-xep")

        self.assertIn("Invalid XEP number", response)
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
