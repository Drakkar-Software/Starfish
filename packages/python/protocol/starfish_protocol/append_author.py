"""Author proof for stored writes (v3.0).

Both append-only elements and merge documents can carry an Ed25519 signature
over their payload, binding the stored write to the key that produced it.
The signed input binds the author to BOTH the payload AND the document::

    <domain> + stable_stringify({"k": document_key, "d": data})
"""

from __future__ import annotations

import base64
from typing import Any, TypedDict

from starfish_protocol.constants import AUTHOR_PUBKEY_FIELD, AUTHOR_SIGNATURE_FIELD
from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import ed25519 as ed25519_suite


APPEND_AUTHOR_DOMAIN = "starfish-append-author-v1\n"
DOC_AUTHOR_DOMAIN = "starfish-doc-author-v1\n"


class AppendAuthor(TypedDict):
    authorPubkey: str
    authorSignature: str


def _author_canonical_input(domain: str, document_key: str, data: dict[str, Any]) -> str:
    return domain + stable_stringify({"k": document_key, "d": data})


def _sign(
    domain: str,
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_priv_hex: str,
) -> AppendAuthor:
    canon = _author_canonical_input(domain, document_key, data).encode("utf-8")
    sig_bytes = ed25519_suite.sign(canon, author_priv_hex)
    return {
        AUTHOR_PUBKEY_FIELD: author_pub_hex,
        AUTHOR_SIGNATURE_FIELD: base64.b64encode(sig_bytes).decode("ascii"),
    }


def _verify(
    domain: str,
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_signature: str,
) -> bool:
    try:
        canon = _author_canonical_input(domain, document_key, data).encode("utf-8")
        sig_bytes = base64.b64decode(author_signature)
        return ed25519_suite.verify(sig_bytes, canon, author_pub_hex)
    except Exception:
        return False


def append_author_canonical_input(document_key: str, data: dict[str, Any]) -> str:
    """Canonical input for an append ELEMENT's author signature."""
    return _author_canonical_input(APPEND_AUTHOR_DOMAIN, document_key, data)


def sign_append_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_priv_hex: str,
) -> AppendAuthor:
    """Sign an append element's ``data`` (bound to ``document_key``) with Ed25519."""
    return _sign(APPEND_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_priv_hex)


def verify_append_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_signature: str,
) -> bool:
    """Verify an append element's author signature."""
    return _verify(APPEND_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_signature)


def doc_author_canonical_input(document_key: str, data: dict[str, Any]) -> str:
    """Canonical input for a merge DOCUMENT's author signature."""
    return _author_canonical_input(DOC_AUTHOR_DOMAIN, document_key, data)


def sign_doc_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_priv_hex: str,
) -> AppendAuthor:
    """Sign a merge document's ``data`` (bound to ``document_key``) with Ed25519."""
    return _sign(DOC_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_priv_hex)


def verify_doc_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_signature: str,
) -> bool:
    """Verify a merge document's author signature."""
    return _verify(DOC_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_signature)


__all__ = [
    "APPEND_AUTHOR_DOMAIN",
    "DOC_AUTHOR_DOMAIN",
    "AppendAuthor",
    "append_author_canonical_input",
    "sign_append_author",
    "verify_append_author",
    "doc_author_canonical_input",
    "sign_doc_author",
    "verify_doc_author",
]
