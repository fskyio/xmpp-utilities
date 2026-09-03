import asyncio
import datetime
import hashlib
import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import dns.flags
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from xmpp_utilities.__main__ import XMPPUtilities
from xmpp_utilities.dane import (
    XMPP_SERVICES,
    DANEReport,
    EndpointResult,
    ResolvedAddress,
    ServiceResult,
    TLSALookup,
    TLSARecord,
    _verify_dane_ta,
    certificate_association_matches,
    discover_dane,
    format_dane_report,
    normalize_domain,
    parse_dane_argument,
    validate_dane,
)


class FakeAnswer(list):
    def __init__(self, records: list[object], authenticated: bool = False) -> None:
        super().__init__(records)
        flags = dns.flags.AD if authenticated else 0
        self.response = SimpleNamespace(flags=flags)


class FakeResolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    async def resolve(
        self, name: str, rdtype: str, lifetime: float | None = None
    ) -> object:
        del lifetime
        self.calls.append((name, rdtype))
        result = self.answers.get((name, rdtype), dns.resolver.NoAnswer())
        if isinstance(result, BaseException):
            raise result
        return result


def make_certificate() -> tuple[bytes, bytes]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "example.org")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.org")]),
            critical=False,
        )
        .sign(private_key, algorithm=None)
    )
    der = certificate.public_bytes(Encoding.DER)
    spki = certificate.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return der, spki


def make_ca_chain() -> tuple[bytes, bytes]:
    now = datetime.datetime.now(datetime.UTC)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.org")])
        )
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.org")]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return leaf.public_bytes(Encoding.DER), root.public_bytes(Encoding.DER)


class DomainParsingTests(unittest.TestCase):
    def test_normalizes_ascii_unicode_and_trailing_dot(self) -> None:
        self.assertEqual(normalize_domain("Example.ORG."), "example.org")
        self.assertEqual(normalize_domain("täst.example"), "xn--tst-qla.example")

    def test_rejects_invalid_domains(self) -> None:
        for value in ("", ".", "-example.org", "example..org", "example.org/path"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_domain(value))

    def test_parses_optional_validation_disable_flag(self) -> None:
        self.assertEqual(
            parse_dane_argument("Example.org --no-validate"),
            ("example.org", False),
        )
        self.assertEqual(parse_dane_argument("example.org"), ("example.org", True))
        self.assertIsNone(parse_dane_argument("example.org --validate"))
        self.assertIsNone(parse_dane_argument("example.org unexpected"))


class TLSARecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate, cls.spki = make_certificate()

    def test_matches_full_certificate_and_spki_digest(self) -> None:
        full = TLSARecord(3, 0, 0, self.certificate)
        spki = TLSARecord(3, 1, 1, hashlib.sha256(self.spki).digest())

        self.assertTrue(certificate_association_matches(full, self.certificate))
        self.assertTrue(certificate_association_matches(spki, self.certificate))

    def test_describes_and_rejects_bad_parameters(self) -> None:
        record = TLSARecord(3, 1, 1, b"x" * 32)
        self.assertEqual(record.parameters, "DANE-EE, SPKI, SHA-256")
        self.assertIsNone(record.usability_error)
        self.assertIn("digest length", TLSARecord(3, 1, 1, b"short").usability_error)
        self.assertIn("unsupported", TLSARecord(9, 1, 1, b"x" * 32).usability_error)

    def test_validates_dane_ta_chain(self) -> None:
        leaf, root = make_ca_chain()
        record = TLSARecord(2, 0, 1, hashlib.sha256(root).digest())

        valid, error = _verify_dane_ta(
            record,
            (leaf, root),
            "example.org",
            "xmpp.example.org",
            XMPP_SERVICES[1],
            True,
        )

        self.assertTrue(valid)
        self.assertIsNone(error)

        full_record = TLSARecord(2, 0, 0, root)
        valid, error = _verify_dane_ta(
            full_record,
            (leaf,),
            "example.org",
            "xmpp.example.org",
            XMPP_SERVICES[1],
            True,
        )

        self.assertTrue(valid)
        self.assertIsNone(error)


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_derives_tlsa_name_from_srv_target_and_port(self) -> None:
        resolver = FakeResolver(
            {
                ("_xmpp-client._tcp.example.org", "SRV"): FakeAnswer(
                    [
                        SimpleNamespace(
                            target="xmpp.host.example.",
                            port=7443,
                            priority=10,
                            weight=20,
                        )
                    ],
                    authenticated=True,
                ),
                ("_7443._tcp.xmpp.host.example.", "TLSA"): FakeAnswer(
                    [
                        SimpleNamespace(
                            usage=3,
                            selector=1,
                            mtype=1,
                            cert=b"x" * 32,
                        )
                    ],
                    authenticated=True,
                ),
            }
        )

        report = await discover_dane(resolver, "example.org")

        endpoint = report.services[0].endpoints[0]
        self.assertEqual(endpoint.target, "xmpp.host.example")
        self.assertEqual(endpoint.tlsa_name, "_7443._tcp.xmpp.host.example.")
        self.assertTrue(endpoint.srv_authenticated)
        self.assertTrue(endpoint.tlsa.authenticated)
        self.assertIn(("_7443._tcp.xmpp.host.example.", "TLSA"), resolver.calls)

    async def test_reports_explicitly_unavailable_service(self) -> None:
        resolver = FakeResolver(
            {
                ("_xmpp-client._tcp.example.org", "SRV"): FakeAnswer(
                    [SimpleNamespace(target=".", port=0, priority=0, weight=0)]
                )
            }
        )

        report = await discover_dane(resolver, "example.org")

        self.assertTrue(report.services[0].unavailable)
        self.assertIn("Service explicitly unavailable", format_dane_report(report))

    async def test_limits_endpoints_per_service(self) -> None:
        records = [
            SimpleNamespace(
                target=f"xmpp{number}.example.org.",
                port=5222,
                priority=number,
                weight=0,
            )
            for number in range(3)
        ]
        resolver = FakeResolver(
            {
                ("_xmpp-client._tcp.example.org", "SRV"): FakeAnswer(records),
            }
        )

        report = await discover_dane(resolver, "example.org")

        self.assertEqual(len(report.services[0].endpoints), 2)
        self.assertEqual(report.omitted_endpoints, 1)


class ValidationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate, cls.spki = make_certificate()

    def make_report(self) -> DANEReport:
        record = TLSARecord(3, 1, 1, hashlib.sha256(self.spki).digest())
        service = XMPP_SERVICES[1]
        endpoint = EndpointResult(
            service=service,
            target="xmpp.example.org",
            port=443,
            priority=0,
            weight=0,
            srv_authenticated=True,
            tlsa_name="_443._tcp.xmpp.example.org.",
            tlsa=TLSALookup(records=(record,), authenticated=True),
        )
        return DANEReport(
            domain="example.org",
            services=(ServiceResult(service=service, endpoints=(endpoint,)),),
        )

    async def test_validates_authenticated_dane_ee_match(self) -> None:
        resolver = FakeResolver(
            {
                ("xmpp.example.org", "A"): FakeAnswer(
                    ["93.184.216.34"], authenticated=True
                )
            }
        )
        probe = AsyncMock(return_value=(self.certificate,))

        report = await validate_dane(resolver, self.make_report(), probe_function=probe)

        endpoint = report.services[0].endpoints[0]
        self.assertEqual(endpoint.validations[0].result, "VALID")
        self.assertTrue(report.validation_requested)
        probe.assert_awaited_once()

    async def test_match_without_authenticated_address_is_not_dane_valid(self) -> None:
        resolver = FakeResolver(
            {("xmpp.example.org", "A"): FakeAnswer(["93.184.216.34"])}
        )
        probe = AsyncMock(return_value=(self.certificate,))

        report = await validate_dane(resolver, self.make_report(), probe_function=probe)

        result = report.services[0].endpoints[0].validations[0].result
        self.assertIn("MATCH, but not DANE-valid", result)
        self.assertIn("address", result)

    async def test_refuses_to_probe_non_public_addresses(self) -> None:
        resolver = FakeResolver(
            {("xmpp.example.org", "A"): FakeAnswer(["127.0.0.1"], authenticated=True)}
        )
        probe = AsyncMock(return_value=(self.certificate,))

        report = await validate_dane(resolver, self.make_report(), probe_function=probe)

        endpoint = report.services[0].endpoints[0]
        self.assertIn("no public addresses", endpoint.probe_error)
        probe.assert_not_awaited()

    async def test_probe_receives_resolved_address_without_reresolving(self) -> None:
        resolver = FakeResolver(
            {
                ("xmpp.example.org", "A"): FakeAnswer(
                    ["93.184.216.34"], authenticated=True
                )
            }
        )
        seen: list[ResolvedAddress] = []

        async def probe(
            endpoint: EndpointResult,
            domain: str,
            address: ResolvedAddress,
            verify_pkix: bool,
        ) -> tuple[bytes, ...]:
            del endpoint, domain, verify_pkix
            seen.append(address)
            return (self.certificate,)

        await validate_dane(resolver, self.make_report(), probe_function=probe)

        self.assertEqual(seen[0].address, ipaddress.ip_address("93.184.216.34"))


class DANECommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_help_lists_tlsa_and_dane_alias(self) -> None:
        response = await XMPPUtilities.cmd_help(None, None)

        self.assertIn("!xmpp tlsa <domain> [--no-validate]", response)
        self.assertIn("alias: dane", response)

    def test_tlsa_and_dane_are_aliases(self) -> None:
        xmpp = XMPPUtilities("bot@example.org", "password", (), "Bot")

        self.assertIs(xmpp.commands["tlsa"].__func__, xmpp.commands["dane"].__func__)

    async def test_command_validates_by_default(self) -> None:
        resolver = FakeResolver({})
        command_target = SimpleNamespace(
            _resolver=resolver,
            _dane_validation_lock=asyncio.Lock(),
        )

        with patch(
            "xmpp_utilities.__main__.validate_dane",
            new=AsyncMock(wraps=validate_dane),
        ) as validate:
            response = await XMPPUtilities.cmd_tlsa(command_target, "Example.org")

        self.assertIn("TLSA records for example.org", response)
        self.assertNotIn("DNSSEC status is asserted", response)
        validate.assert_awaited_once()

    async def test_command_can_disable_validation(self) -> None:
        command_target = SimpleNamespace(_resolver=FakeResolver({}))

        with patch(
            "xmpp_utilities.__main__.validate_dane",
            new_callable=AsyncMock,
        ) as validate:
            response = await XMPPUtilities.cmd_tlsa(
                command_target, "example.org --no-validate"
            )

        self.assertIn("TLSA records for example.org", response)
        validate.assert_not_awaited()

    async def test_command_rejects_invalid_arguments(self) -> None:
        response = await XMPPUtilities.cmd_tlsa(None, "example.org extra")

        self.assertIn("Invalid TLSA lookup arguments", response)

    async def test_rejects_concurrent_active_validation(self) -> None:
        lock = asyncio.Lock()
        await lock.acquire()
        command_target = SimpleNamespace(
            _resolver=FakeResolver({}),
            _dane_validation_lock=lock,
        )

        response = await XMPPUtilities.cmd_tlsa(command_target, "example.org")

        self.assertIn("already running", response)


if __name__ == "__main__":
    unittest.main()
