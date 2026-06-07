"""Tests for the CORS allow-headers aggregate constant."""

from starfish_protocol.constants import (
    CORS_ALLOW_HEADERS,
    HEADER_AUTHORIZATION,
    HEADER_CONTENT_TYPE,
    HEADER_SIG,
    HEADER_TS,
    HEADER_NONCE,
    HEADER_PUB,
)


def test_cors_allow_headers_exact_entries():
    assert list(CORS_ALLOW_HEADERS) == [
        "Authorization",
        "Content-Type",
        "X-Starfish-Sig",
        "X-Starfish-Ts",
        "X-Starfish-Nonce",
        "X-Starfish-Pub",
        "X-Requested-With",
    ]


def test_cors_allow_headers_built_from_constants():
    for header in (
        HEADER_AUTHORIZATION,
        HEADER_CONTENT_TYPE,
        HEADER_SIG,
        HEADER_TS,
        HEADER_NONCE,
        HEADER_PUB,
    ):
        assert header in CORS_ALLOW_HEADERS


def test_x_starfish_names_aligned_with_constants():
    assert HEADER_SIG == "X-Starfish-Sig"
    assert HEADER_TS == "X-Starfish-Ts"
    assert HEADER_NONCE == "X-Starfish-Nonce"
    assert HEADER_PUB == "X-Starfish-Pub"
