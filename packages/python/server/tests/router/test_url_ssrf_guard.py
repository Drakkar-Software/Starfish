"""Cross-language parity probe for the public SSRF guard ``validate_url_not_private``.

The library exports ``validate_url_not_private`` / ``validateUrlNotPrivate`` so
consumers can gate outbound (webhook / replica) URLs against private/loopback
targets. The two implementations take different routes — Python uses
``urllib.parse.urlparse`` + the ``ipaddress`` module; TypeScript uses WHATWG
``new URL`` + hand-rolled checks — and they disagree on two classes of loopback
spelling, each leaving the OTHER runtime's consumers exposed:

* Alternate IPv4 notations (decimal / hex / octal / short) for ``127.0.0.1``:
  ``urlparse`` keeps the raw host string and ``ipaddress.ip_address()`` rejects
  the non-dotted-quad form, so this guard used to fall through to "public" and
  ALLOW them. TypeScript's ``new URL`` normalises ``2130706433`` / ``0x7f000001``
  / ``127.1`` to ``"127.0.0.1"`` and blocks them. **Fixed:** Python now
  canonicalises via ``socket.inet_aton`` before the ``ipaddress`` check.

* IPv4-mapped IPv6 loopback ``::ffff:127.0.0.1``: ``ipaddress`` flags it private
  and this guard blocks it; TypeScript's ``new URL`` compresses it to
  ``::ffff:7f00:1`` (hex), which its dotted-quad regex missed, so TS used to
  ALLOW it. **Fixed** in the TypeScript twin ``url-ssrf-guard.test.ts`` (a hex
  IPv4-mapped branch was added).

Both bypasses are now closed: EVERY loopback spelling is blocked on both runtimes.
"""

import pytest

from starfish_server.router.helpers import (
    validate_url_not_private,
    validate_url_not_private_async,
)

# Private / loopback / link-local targets the guard correctly blocks (False).
# ``[::ffff:127.0.0.1]`` is included: ipaddress flags the IPv4-mapped form as
# private, so Python — unlike TypeScript — blocks it.
_BLOCKED = [
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://localhost/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://0.0.0.0/",
    "http://[::ffff:127.0.0.1]/",
    # Reserved / special-use ranges. ipaddress already blocks these via is_private;
    # 100.64.0.0/10 (CGNAT) is NOT flagged by is_private, so validate_url_not_private
    # now blocks it explicitly for parity with the TS classifier.
    "http://100.64.0.1/",       # 100.64.0.0/10 CGNAT (RFC 6598)
    "http://100.127.255.255/",  # top of CGNAT
    "http://192.0.2.1/",        # 192.0.2.0/24 TEST-NET-1
    "http://198.18.0.1/",       # 198.18.0.0/15 benchmarking
    "http://198.51.100.5/",     # 198.51.100.0/24 TEST-NET-2
    "http://203.0.113.5/",      # 203.0.113.0/24 TEST-NET-3
    "http://192.0.0.1/",        # 192.0.0.0/24 IETF protocol assignments
    "http://240.0.0.1/",        # 240.0.0.0/4 reserved
    "http://255.255.255.255/",  # limited broadcast (within 240.0.0.0/4)
]

# Addresses just OUTSIDE the newly-blocked ranges must stay public (no over-blocking).
_PUBLIC = [
    "http://example.com/",
    "http://8.8.8.8/",
    "http://100.63.255.255/",  # just below CGNAT
    "http://100.128.0.1/",     # just above CGNAT
    "http://199.0.0.1/",       # just above 198.18.0.0/15
]

# Alternate spellings of 127.0.0.1 that resolve to loopback in common HTTP
# clients but parse to a host string ``ipaddress`` rejects as non-canonical.
_LOOPBACK_ALIASES = [
    "http://2130706433/",  # decimal
    "http://0x7f000001/",  # hex
    "http://0177.0.0.1/",  # octal first octet
    "http://127.1/",  # short form
]


@pytest.mark.parametrize("url", _BLOCKED)
def test_blocks_private_and_loopback_targets(url: str) -> None:
    assert validate_url_not_private(url) is False


@pytest.mark.parametrize("url", _PUBLIC)
def test_allows_public_targets(url: str) -> None:
    assert validate_url_not_private(url) is True


@pytest.mark.parametrize("url", _LOOPBACK_ALIASES)
def test_blocks_alternate_ipv4_loopback_notations(url: str) -> None:
    # Fixed: validate_url_not_private now canonicalises alternate IPv4 spellings
    # via socket.inet_aton before the ipaddress check, so these loopback aliases
    # are blocked — matching the TypeScript guard (which `new URL` normalises).
    assert validate_url_not_private(url) is False


# ── DNS-resolving guard (validate_url_not_private_async) ──
# The string-only guard cannot see that a public-looking HOSTNAME resolves to an
# internal address. The async guard resolves the name and rejects if ANY resolved
# address is private. A resolver is injected for deterministic, offline tests.


@pytest.mark.asyncio
async def test_async_rejects_literal_private_host_without_resolving() -> None:
    called = False

    async def resolver(_host: str) -> list[str]:
        nonlocal called
        called = True
        return ["8.8.8.8"]

    assert await validate_url_not_private_async("http://127.0.0.1/", resolver) is False
    assert called is False  # short-circuited by the synchronous pre-filter


@pytest.mark.asyncio
async def test_async_rejects_hostname_resolving_to_private() -> None:
    async def to_private(_host: str) -> list[str]:
        return ["10.0.0.5"]

    async def to_loopback(_host: str) -> list[str]:
        return ["127.0.0.1"]

    async def mixed(_host: str) -> list[str]:
        return ["8.8.8.8", "192.168.1.1"]

    async def to_cgnat(_host: str) -> list[str]:
        return ["100.64.0.1"]

    assert await validate_url_not_private_async("http://internal.example.com/", to_private) is False
    assert await validate_url_not_private_async("http://rebind.example.com/", to_loopback) is False
    assert await validate_url_not_private_async("http://mixed.example.com/", mixed) is False
    assert await validate_url_not_private_async("http://cg.example.com/", to_cgnat) is False


@pytest.mark.asyncio
async def test_async_allows_hostname_resolving_to_public() -> None:
    async def to_public(_host: str) -> list[str]:
        return ["8.8.8.8", "1.1.1.1"]

    assert await validate_url_not_private_async("http://ok.example.com/", to_public) is True


@pytest.mark.asyncio
async def test_async_degrades_when_resolution_empty_or_fails() -> None:
    async def empty(_host: str) -> list[str]:
        return []

    async def fails(_host: str) -> list[str]:
        raise OSError("NXDOMAIN")

    assert await validate_url_not_private_async("http://ok.example.com/", empty) is True
    assert await validate_url_not_private_async("http://ok.example.com/", fails) is True
