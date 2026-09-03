"""DANE TLSA discovery and certificate association checks for XMPP."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import ssl
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace

import dns.exception
import dns.flags
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.verification import (
    DNSName,
    PolicyBuilder,
    Store,
    VerificationError,
)

DNS_TIMEOUT = 5.0
PROBE_TIMEOUT = 5.0
MAX_ENDPOINTS_PER_SERVICE = 2
MAX_ADDRESSES_PER_ENDPOINT = 2
MAX_STREAM_PREAMBLE = 64 * 1024
MAX_CONCURRENT_PROBES = 4

TLS_NAMESPACE = b"urn:ietf:params:xml:ns:xmpp-tls"
FEATURES_END = re.compile(rb"</(?:[A-Za-z0-9_.-]+:)?features\s*>", re.IGNORECASE)
FEATURES_EMPTY = re.compile(rb"<(?:[A-Za-z0-9_.-]+:)?features\b[^>]*/>", re.IGNORECASE)
PROCEED = re.compile(
    rb"<(?:[A-Za-z0-9_.-]+:)?proceed(?:\s[^>]*)?(?:/>|>.*?</(?:[A-Za-z0-9_.-]+:)?proceed\s*>)",
    re.IGNORECASE | re.DOTALL,
)
TLS_FAILURE = re.compile(rb"<(?:[A-Za-z0-9_.-]+:)?failure\b", re.IGNORECASE)

USAGE_NAMES = {
    0: "PKIX-TA",
    1: "PKIX-EE",
    2: "DANE-TA",
    3: "DANE-EE",
}
SELECTOR_NAMES = {0: "Cert", 1: "SPKI"}
MATCHING_TYPE_NAMES = {0: "Full", 1: "SHA-256", 2: "SHA-512"}

XMPP_ADDR_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.5")
SRV_NAME_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.8.7")


@dataclass(frozen=True)
class XMPPService:
    label: str
    prefix: str
    direct_tls: bool
    stream_namespace: str
    alpn: str


XMPP_SERVICES = (
    XMPPService(
        "Client-to-Server",
        "_xmpp-client._tcp",
        False,
        "jabber:client",
        "xmpp-client",
    ),
    XMPPService(
        "Client-to-Server (Direct TLS)",
        "_xmpps-client._tcp",
        True,
        "jabber:client",
        "xmpp-client",
    ),
    XMPPService(
        "Server-to-Server",
        "_xmpp-server._tcp",
        False,
        "jabber:server",
        "xmpp-server",
    ),
    XMPPService(
        "Server-to-Server (Direct TLS)",
        "_xmpps-server._tcp",
        True,
        "jabber:server",
        "xmpp-server",
    ),
)


@dataclass(frozen=True)
class TLSARecord:
    usage: int
    selector: int
    matching_type: int
    association_data: bytes

    @property
    def parameters(self) -> str:
        usage = USAGE_NAMES.get(self.usage, f"unknown usage {self.usage}")
        selector = SELECTOR_NAMES.get(
            self.selector, f"unknown selector {self.selector}"
        )
        matching = MATCHING_TYPE_NAMES.get(
            self.matching_type, f"unknown matching type {self.matching_type}"
        )
        return f"{usage}, {selector}, {matching}"

    @property
    def text(self) -> str:
        data = self.association_data.hex().upper()
        return f"{self.usage} {self.selector} {self.matching_type} {data}"

    @property
    def usability_error(self) -> str | None:
        if self.usage not in USAGE_NAMES:
            return "unsupported certificate usage"
        if self.selector not in SELECTOR_NAMES:
            return "unsupported selector"
        if self.matching_type not in MATCHING_TYPE_NAMES:
            return "unsupported matching type"
        expected_length = {1: 32, 2: 64}.get(self.matching_type)
        if (
            expected_length is not None
            and len(self.association_data) != expected_length
        ):
            return f"invalid {MATCHING_TYPE_NAMES[self.matching_type]} digest length"
        if not self.association_data:
            return "empty certificate association data"
        return None


@dataclass(frozen=True)
class TLSALookup:
    records: tuple[TLSARecord, ...] = ()
    authenticated: bool = False
    error: str | None = None


@dataclass(frozen=True)
class RecordValidation:
    result: str


@dataclass(frozen=True)
class EndpointResult:
    service: XMPPService
    target: str
    port: int
    priority: int
    weight: int
    srv_authenticated: bool
    tlsa_name: str
    tlsa: TLSALookup = TLSALookup()
    validations: tuple[RecordValidation, ...] = ()
    probe_error: str | None = None


@dataclass(frozen=True)
class ServiceResult:
    service: XMPPService
    endpoints: tuple[EndpointResult, ...] = ()
    authenticated: bool = False
    unavailable: bool = False
    error: str | None = None


@dataclass(frozen=True)
class DANEReport:
    domain: str
    services: tuple[ServiceResult, ...]
    validation_requested: bool = False
    omitted_endpoints: int = 0


@dataclass(frozen=True)
class ResolvedAddress:
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    authenticated: bool


@dataclass(frozen=True)
class AddressLookup:
    addresses: tuple[ResolvedAddress, ...]
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CertificateProbe:
    chain: tuple[bytes, ...]
    address: ResolvedAddress


ProbeFunction = Callable[
    [EndpointResult, str, ResolvedAddress, bool], Awaitable[tuple[bytes, ...]]
]


def normalize_domain(value: str) -> str | None:
    """Return a lowercase ASCII domain, or ``None`` for invalid input."""
    candidate = value.strip().rstrip(".")
    if not candidate:
        return None
    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(domain) > 253:
        return None
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return domain


def parse_dane_argument(argument: str) -> tuple[str, bool] | None:
    """Parse ``<domain> [--no-validate]`` without accepting extra arguments."""
    parts = argument.split()
    validate = "--no-validate" not in parts
    if not validate:
        parts.remove("--no-validate")
    if len(parts) != 1 or any(part.startswith("--") for part in parts):
        return None
    domain = normalize_domain(parts[0])
    if domain is None:
        return None
    return domain, validate


def dnssec_authenticated(answer: object) -> bool:
    response = getattr(answer, "response", None)
    flags = getattr(response, "flags", 0)
    return bool(flags & dns.flags.AD)


def dnssec_label(authenticated: bool) -> str:
    if authenticated:
        return "secure"
    return "not authenticated"


def _lookup_error(exc: BaseException) -> str:
    if isinstance(exc, (dns.exception.Timeout, dns.resolver.LifetimeTimeout)):
        return "query timed out"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "resolver failure"
    return str(exc) or type(exc).__name__


def _probe_error(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "timed out"
    return str(exc) or type(exc).__name__


async def _lookup_service(
    resolver: object, service: XMPPService, domain: str
) -> ServiceResult:
    query_name = f"{service.prefix}.{domain}"
    try:
        answers = await resolver.resolve(query_name, "SRV", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ServiceResult(service=service)
    except dns.exception.DNSException as exc:
        return ServiceResult(service=service, error=_lookup_error(exc))

    authenticated = dnssec_authenticated(answers)
    endpoints: list[EndpointResult] = []
    unavailable = False
    for answer in answers:
        target = str(answer.target).rstrip(".")
        if not target:
            unavailable = True
            continue
        port = int(answer.port)
        endpoints.append(
            EndpointResult(
                service=service,
                target=target,
                port=port,
                priority=int(answer.priority),
                weight=int(answer.weight),
                srv_authenticated=authenticated,
                tlsa_name=f"_{port}._tcp.{target}.",
            )
        )

    endpoints.sort(
        key=lambda item: (item.priority, -item.weight, item.target, item.port)
    )
    return ServiceResult(
        service=service,
        endpoints=tuple(endpoints),
        authenticated=authenticated,
        unavailable=unavailable and not endpoints,
    )


async def _lookup_tlsa(resolver: object, name: str) -> TLSALookup:
    try:
        answers = await resolver.resolve(name, "TLSA", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return TLSALookup()
    except dns.exception.DNSException as exc:
        return TLSALookup(error=_lookup_error(exc))

    records = tuple(
        sorted(
            (
                TLSARecord(
                    usage=int(answer.usage),
                    selector=int(answer.selector),
                    matching_type=int(answer.mtype),
                    association_data=bytes(answer.cert),
                )
                for answer in answers
            ),
            key=lambda item: (
                item.usage,
                item.selector,
                item.matching_type,
                item.association_data,
            ),
        )
    )
    return TLSALookup(
        records=records,
        authenticated=dnssec_authenticated(answers),
    )


async def discover_dane(resolver: object, domain: str) -> DANEReport:
    """Discover XMPP SRV endpoints and their correctly derived TLSA records."""
    services = list(
        await asyncio.gather(
            *(_lookup_service(resolver, service, domain) for service in XMPP_SERVICES)
        )
    )

    omitted = sum(
        max(0, len(result.endpoints) - MAX_ENDPOINTS_PER_SERVICE) for result in services
    )
    services = [
        replace(
            result,
            endpoints=result.endpoints[:MAX_ENDPOINTS_PER_SERVICE],
        )
        for result in services
    ]
    all_endpoints = [endpoint for result in services for endpoint in result.endpoints]

    tlsa_tasks: dict[str, asyncio.Task[TLSALookup]] = {}
    for endpoint in all_endpoints:
        if endpoint.tlsa_name not in tlsa_tasks:
            tlsa_tasks[endpoint.tlsa_name] = asyncio.create_task(
                _lookup_tlsa(resolver, endpoint.tlsa_name)
            )
    if tlsa_tasks:
        await asyncio.gather(*tlsa_tasks.values())

    updated_services: list[ServiceResult] = []
    for service_result in services:
        endpoints = []
        for endpoint in service_result.endpoints:
            endpoints.append(
                replace(endpoint, tlsa=tlsa_tasks[endpoint.tlsa_name].result())
            )
        updated_services.append(replace(service_result, endpoints=tuple(endpoints)))

    return DANEReport(
        domain=domain,
        services=tuple(updated_services),
        omitted_endpoints=omitted,
    )


async def _resolve_addresses(resolver: object, target: str) -> AddressLookup:
    async def resolve_type(
        rdtype: str,
    ) -> tuple[tuple[ResolvedAddress, ...], str | None]:
        try:
            answers = await resolver.resolve(target, rdtype, lifetime=DNS_TIMEOUT)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return (), None
        except dns.exception.DNSException as exc:
            return (), f"{rdtype}: {_lookup_error(exc)}"
        authenticated = dnssec_authenticated(answers)
        return (
            tuple(
                ResolvedAddress(ipaddress.ip_address(str(answer)), authenticated)
                for answer in answers
            ),
            None,
        )

    ipv4, ipv6 = await asyncio.gather(resolve_type("A"), resolve_type("AAAA"))
    unique: dict[str, ResolvedAddress] = {}
    for address in (*ipv4[0], *ipv6[0]):
        unique.setdefault(str(address.address), address)
    return AddressLookup(
        addresses=tuple(unique.values()),
        errors=tuple(error for _, error in (ipv4, ipv6) if error),
    )


def _tls_context(service: XMPPService, verify_pkix: bool) -> ssl.SSLContext:
    if verify_pkix:
        context = ssl.create_default_context()
        context.check_hostname = False
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if service.direct_tls:
        context.set_alpn_protocols([service.alpn])
    return context


async def _read_limited_until(
    reader: asyncio.StreamReader,
    complete: Callable[[bytes], bool],
) -> bytes:
    data = bytearray()
    while len(data) < MAX_STREAM_PREAMBLE:
        chunk = await reader.read(min(4096, MAX_STREAM_PREAMBLE - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if complete(bytes(data)):
            return bytes(data)
    raise RuntimeError("incomplete or oversized XMPP stream response")


def _certificate_chain(
    writer: asyncio.StreamWriter, verified: bool = False
) -> tuple[bytes, ...]:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        raise RuntimeError("TLS handshake did not produce a TLS session")
    get_chain = (
        ssl_object.get_verified_chain if verified else ssl_object.get_unverified_chain
    )
    chain = tuple(get_chain())
    if not chain:
        leaf = ssl_object.getpeercert(binary_form=True)
        chain = (leaf,) if leaf else ()
    if not chain:
        raise RuntimeError("server did not present a certificate")
    return chain


async def probe_endpoint(
    endpoint: EndpointResult,
    domain: str,
    address: ResolvedAddress,
    verify_pkix: bool = False,
) -> tuple[bytes, ...]:
    """Fetch a peer certificate chain using direct TLS or XMPP STARTTLS."""
    context = _tls_context(endpoint.service, verify_pkix)
    writer: asyncio.StreamWriter | None = None
    try:
        if endpoint.service.direct_tls:
            _, writer = await asyncio.open_connection(
                str(address.address),
                endpoint.port,
                ssl=context,
                server_hostname=domain,
                ssl_handshake_timeout=PROBE_TIMEOUT,
                ssl_shutdown_timeout=1.0,
            )
        else:
            reader, writer = await asyncio.open_connection(
                str(address.address), endpoint.port
            )
            stream = (
                "<?xml version='1.0'?>"
                f"<stream:stream to='{domain}' version='1.0' "
                f"xmlns='{endpoint.service.stream_namespace}' "
                "xmlns:stream='http://etherx.jabber.org/streams'>"
            )
            writer.write(stream.encode("ascii"))
            await writer.drain()

            features = await _read_limited_until(
                reader,
                lambda data: bool(
                    FEATURES_END.search(data) or FEATURES_EMPTY.search(data)
                ),
            )
            if TLS_NAMESPACE not in features or b"starttls" not in features.lower():
                raise RuntimeError("server did not offer XMPP STARTTLS")

            writer.write(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            await writer.drain()
            response = await _read_limited_until(
                reader,
                lambda data: bool(PROCEED.search(data) or TLS_FAILURE.search(data)),
            )
            if TLS_FAILURE.search(response) or not PROCEED.search(response):
                raise RuntimeError("server rejected XMPP STARTTLS")
            await writer.start_tls(
                context,
                server_hostname=domain,
                ssl_handshake_timeout=PROBE_TIMEOUT,
                ssl_shutdown_timeout=1.0,
            )
        return _certificate_chain(writer, verified=verify_pkix)
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.25)
            except Exception:  # noqa: BLE001 - best-effort cleanup after any failure
                transport = writer.transport
                transport.abort()


def _selected_data(certificate: bytes, selector: int) -> bytes:
    if selector == 0:
        return certificate
    parsed = x509.load_der_x509_certificate(certificate)
    return parsed.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def certificate_association_matches(record: TLSARecord, certificate: bytes) -> bool:
    selected = _selected_data(certificate, record.selector)
    if record.matching_type == 1:
        selected = hashlib.sha256(selected).digest()
    elif record.matching_type == 2:
        selected = hashlib.sha512(selected).digest()
    return selected == record.association_data


def _matching_certificates(
    record: TLSARecord, certificates: Sequence[bytes]
) -> tuple[bytes, ...]:
    return tuple(
        certificate
        for certificate in certificates
        if certificate_association_matches(record, certificate)
    )


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    hostname = hostname.rstrip(".").lower()
    if pattern.startswith("*."):
        return (
            len(pattern.split(".")) == len(hostname.split("."))
            and pattern[2:] == hostname.split(".", 1)[1]
        )
    return pattern == hostname


def _decode_other_name(value: bytes) -> str | None:
    if len(value) < 2 or value[0] not in (0x0C, 0x16):
        return None
    length = value[1]
    offset = 2
    if length & 0x80:
        width = length & 0x7F
        if width == 0 or len(value) < 2 + width:
            return None
        length = int.from_bytes(value[2 : 2 + width], "big")
        offset += width
    if offset + length != len(value):
        return None
    try:
        return value[offset:].decode("utf-8")
    except UnicodeDecodeError:
        return None


def certificate_identity_matches(
    certificate: bytes,
    domain: str,
    target: str,
    service: XMPPService,
    srv_authenticated: bool,
) -> bool:
    """Check the DNS-ID, SRV-ID, or XmppAddr identities used by XMPP."""
    parsed = x509.load_der_x509_certificate(certificate)
    reference_dns_names = [domain]
    if srv_authenticated and target not in reference_dns_names:
        reference_dns_names.append(target)
    expected_srv_names = {f"_{service.alpn}.{domain}"}

    try:
        san = parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        san = None

    if san is not None:
        if any(
            _dns_name_matches(name, reference)
            for name in san.get_values_for_type(x509.DNSName)
            for reference in reference_dns_names
        ):
            return True
        for other_name in san.get_values_for_type(x509.OtherName):
            value = _decode_other_name(other_name.value)
            if value is None:
                continue
            value = value.rstrip(".").lower()
            if other_name.type_id == XMPP_ADDR_OID and value == domain:
                return True
            if other_name.type_id == SRV_NAME_OID and value in expected_srv_names:
                return True
        return False

    common_names = parsed.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return any(
        _dns_name_matches(common_name.value, reference)
        for common_name in common_names
        for reference in reference_dns_names
    )


def _verify_dane_ta(
    record: TLSARecord,
    chain: tuple[bytes, ...],
    domain: str,
    target: str,
    service: XMPPService,
    srv_authenticated: bool,
) -> tuple[bool, str | None]:
    try:
        if record.selector == 0 and record.matching_type == 0:
            anchor_der = record.association_data
        else:
            matches = _matching_certificates(record, chain[1:])
            if not matches:
                return False, "trust anchor association does not match the server chain"
            anchor_der = matches[0]

        anchor = x509.load_der_x509_certificate(anchor_der)
        leaf = x509.load_der_x509_certificate(chain[0])
        if not certificate_identity_matches(
            chain[0], domain, target, service, srv_authenticated
        ):
            return False, "certificate identity does not match the XMPP service"
        intermediates = [
            x509.load_der_x509_certificate(item)
            for item in chain[1:]
            if item != anchor_der
        ]
        try:
            san = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_names = san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            dns_names = []
        if not dns_names:
            return (
                False,
                "validation unavailable for a DANE-TA certificate without a DNS-ID",
            )
        verification_name = dns_names[0]
        if verification_name.startswith("*."):
            verification_name = f"dane-probe.{verification_name[2:]}"
        try:
            verifier = (
                PolicyBuilder()
                .store(Store([anchor]))
                .build_server_verifier(DNSName(verification_name))
            )
            verifier.verify(leaf, intermediates)
            return True, None
        except VerificationError:
            pass
        return (
            False,
            "certificate chain did not validate to the DANE trust anchor",
        )
    except (ValueError, TypeError):
        return (
            False,
            "invalid certificate data in the DANE trust anchor or server chain",
        )


def _missing_dnssec(endpoint: EndpointResult, address: ResolvedAddress) -> str:
    missing = []
    if not endpoint.srv_authenticated:
        missing.append("SRV")
    if not address.authenticated:
        missing.append("address")
    if not endpoint.tlsa.authenticated:
        missing.append("TLSA")
    return ", ".join(missing)


def _record_validation(
    record: TLSARecord,
    endpoint: EndpointResult,
    domain: str,
    probe: CertificateProbe,
    pkix_chain: tuple[bytes, ...] | None,
    pkix_error: str | None,
) -> RecordValidation:
    usability_error = record.usability_error
    if usability_error:
        return RecordValidation(f"NOT USABLE: {usability_error}")

    chain = probe.chain
    try:
        if record.usage == 3:
            valid = certificate_association_matches(record, chain[0])
            failure = "leaf certificate association does not match"
        elif record.usage == 2:
            valid, failure = _verify_dane_ta(
                record,
                chain,
                domain,
                endpoint.target,
                endpoint.service,
                endpoint.srv_authenticated,
            )
            if failure and failure.startswith("validation unavailable"):
                return RecordValidation(f"NOT VALIDATED: {failure}")
        elif record.usage == 1:
            verified_leaf = pkix_chain[0] if pkix_chain else chain[0]
            association_matches = certificate_association_matches(record, verified_leaf)
            identity_matches = certificate_identity_matches(
                verified_leaf,
                domain,
                endpoint.target,
                endpoint.service,
                endpoint.srv_authenticated,
            )
            valid = association_matches and pkix_chain is not None and identity_matches
            if not association_matches:
                failure = "leaf certificate association does not match"
            elif pkix_chain is None:
                failure = f"PKIX validation failed: {pkix_error or 'unknown error'}"
            else:
                failure = "certificate identity does not match the XMPP service"
        else:
            verified_leaf = pkix_chain[0] if pkix_chain else chain[0]
            identity_matches = certificate_identity_matches(
                verified_leaf,
                domain,
                endpoint.target,
                endpoint.service,
                endpoint.srv_authenticated,
            )
            matches = _matching_certificates(record, (pkix_chain or ())[1:])
            valid = pkix_chain is not None and bool(matches) and identity_matches
            if pkix_chain is None:
                failure = f"PKIX validation failed: {pkix_error or 'unknown error'}"
            elif not matches:
                failure = "trust anchor association does not match the PKIX chain"
            else:
                failure = "certificate identity does not match the XMPP service"
    except (ValueError, TypeError):
        return RecordValidation("ERROR: server presented invalid certificate data")

    if not valid:
        return RecordValidation(f"MISMATCH: {failure}")

    missing = _missing_dnssec(endpoint, probe.address)
    if missing:
        return RecordValidation(
            f"MATCH, but not DANE-valid; DNSSEC not authenticated for {missing}"
        )
    return RecordValidation("VALID")


async def _validate_endpoint(
    resolver: object,
    endpoint: EndpointResult,
    domain: str,
    probe_function: ProbeFunction,
) -> EndpointResult:
    if not endpoint.tlsa.records:
        return endpoint
    if not any(record.usability_error is None for record in endpoint.tlsa.records):
        return replace(
            endpoint,
            validations=tuple(
                RecordValidation(f"NOT USABLE: {record.usability_error}")
                for record in endpoint.tlsa.records
            ),
        )

    address_lookup = await _resolve_addresses(resolver, endpoint.target)
    public_addresses = [
        address for address in address_lookup.addresses if address.address.is_global
    ]
    if not public_addresses:
        if address_lookup.errors and not address_lookup.addresses:
            reason = "address lookup failed (" + "; ".join(address_lookup.errors) + ")"
        elif not address_lookup.addresses:
            reason = "endpoint has no addresses"
        else:
            reason = "probe refused because the endpoint has no public addresses"
        return replace(endpoint, probe_error=reason)

    certificate_probe: CertificateProbe | None = None
    errors = []
    for address in public_addresses[:MAX_ADDRESSES_PER_ENDPOINT]:
        try:
            chain = await asyncio.wait_for(
                probe_function(endpoint, domain, address, False),
                timeout=PROBE_TIMEOUT,
            )
            certificate_probe = CertificateProbe(chain=chain, address=address)
            break
        except (OSError, TimeoutError, ssl.SSLError, RuntimeError, ValueError) as exc:
            errors.append(f"{address.address}: {_probe_error(exc)}")
    if certificate_probe is None:
        return replace(
            endpoint,
            probe_error="TLS probe failed (" + "; ".join(errors) + ")",
        )

    pkix_chain: tuple[bytes, ...] | None = None
    pkix_error: str | None = None
    if any(record.usage in (0, 1) for record in endpoint.tlsa.records):
        try:
            pkix_chain = await asyncio.wait_for(
                probe_function(endpoint, domain, certificate_probe.address, True),
                timeout=PROBE_TIMEOUT,
            )
        except (OSError, TimeoutError, ssl.SSLError, RuntimeError, ValueError) as exc:
            pkix_error = _probe_error(exc)

    validations = tuple(
        _record_validation(
            record,
            endpoint,
            domain,
            certificate_probe,
            pkix_chain,
            pkix_error,
        )
        for record in endpoint.tlsa.records
    )
    return replace(endpoint, validations=validations)


async def validate_dane(
    resolver: object,
    report: DANEReport,
    probe_function: ProbeFunction = probe_endpoint,
) -> DANEReport:
    """Actively check usable TLSA records against XMPP endpoint certificates."""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

    async def bounded(endpoint: EndpointResult) -> EndpointResult:
        async with semaphore:
            return await _validate_endpoint(
                resolver, endpoint, report.domain, probe_function
            )

    endpoints = [
        endpoint for service in report.services for endpoint in service.endpoints
    ]
    validated = iter(
        await asyncio.gather(*(bounded(endpoint) for endpoint in endpoints))
    )
    services = tuple(
        replace(
            service,
            endpoints=tuple(next(validated) for _ in service.endpoints),
        )
        for service in report.services
    )
    return replace(report, services=services, validation_requested=True)


def format_dane_report(report: DANEReport) -> str:
    lines = [f"TLSA records for {report.domain}:"]
    for service_result in report.services:
        service = service_result.service
        lines.append(f"\n{service.label} ({service.prefix}):")
        if service_result.error:
            lines.append(f"  - SRV lookup failed: {service_result.error}")
            continue
        if service_result.unavailable:
            lines.append("  - Service explicitly unavailable")
            continue
        if not service_result.endpoints:
            lines.append("  - No SRV records found")
            continue

        for endpoint in service_result.endpoints:
            lines.append(
                f"  {endpoint.target}:{endpoint.port} "
                f"(priority {endpoint.priority}, weight {endpoint.weight}; "
                f"SRV DNSSEC: {dnssec_label(endpoint.srv_authenticated)})"
            )
            lines.append(
                f"    {endpoint.tlsa_name} "
                f"(TLSA DNSSEC: {dnssec_label(endpoint.tlsa.authenticated)})"
            )
            if endpoint.tlsa.error:
                lines.append(f"    - TLSA lookup failed: {endpoint.tlsa.error}")
                continue
            if not endpoint.tlsa.records:
                lines.append("    - No TLSA records found")
                continue
            for index, record in enumerate(endpoint.tlsa.records):
                lines.append(f"    - {record.text} ({record.parameters})")
                if report.validation_requested:
                    if endpoint.probe_error:
                        lines.append(f"      Validation: ERROR: {endpoint.probe_error}")
                    elif index < len(endpoint.validations):
                        lines.append(
                            f"      Validation: {endpoint.validations[index].result}"
                        )

    if report.omitted_endpoints:
        lines.append(
            f"\n{report.omitted_endpoints} additional endpoint(s) omitted for safety."
        )
    return "\n".join(lines)
