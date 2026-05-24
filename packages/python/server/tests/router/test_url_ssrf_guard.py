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

from starfish_server.router.helpers import validate_url_not_private

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
]

_PUBLIC = ["http://example.com/", "http://8.8.8.8/"]

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
