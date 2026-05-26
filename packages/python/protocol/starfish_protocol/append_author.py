"""Author proof for stored writes (v3.0).

Both append-only elements and merge documents can carry a signature over their
payload, binding the stored write to the key that produced it. Unlike a
per-request signature (which authorizes ONE HTTP call and is then discarded), the
author signature is stored WITH the write, so any later reader can verify who
wrote it without trusting a self-declared ``authorId`` field.

The signed input binds the author to BOTH the payload AND the document::

    <domain> + stable_stringify({"k": document_key, "d": data})

``document_key`` is the collection storage path (the server's resolved document
key — e.g. ``spaces/abc/streams/xyz``; the client derives it by stripping the
``/push/`` action prefix, the reader by stripping ``/pull/``). Binding it stops
an authorized writer from lifting another author's signed element and re-appending
it under a different key — the signature would no longer match.

Two distinct domain tags keep append-element and merge-document signatures from
ever cross-verifying, by construction. The canonical input is identical
byte-for-byte across TypeScript and Python — locked by the
``tests/test-vectors/append-author.json`` conformance vector (the doc-author input
is the same construction under the ``DOC_AUTHOR_DOMAIN`` tag). Mirrors
``packages/ts/protocol/src/append-author.ts``.
"""

from __future__ import annotations

import base64
from typing import Any, TypedDict

from starfish_protocol.constants import AUTHOR_PUBKEY_FIELD, AUTHOR_SIGNATURE_FIELD
from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import Alg, DEFAULT_ALG, get_suite


# Domain tag for an append-only ELEMENT's author signature.
APPEND_AUTHOR_DOMAIN = "starfish-append-author-v1\n"

# Domain tag for a merge-DOCUMENT's author signature. Distinct from
# APPEND_AUTHOR_DOMAIN so an element signature can never verify as a document
# signature (or vice versa).
DOC_AUTHOR_DOMAIN = "starfish-doc-author-v1\n"


class AppendAuthor(TypedDict):
    """Author-proof fields attached to a write body and stored with it. Wire
    field names are camelCase to match the TypeScript client/server and the
    stored document JSON."""

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
    alg: Alg,
) -> AppendAuthor:
    canon = _author_canonical_input(domain, document_key, data).encode("utf-8")
    sig_bytes = get_suite(alg).sign(canon, author_priv_hex)
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
    alg: Alg,
) -> bool:
    try:
        canon = _author_canonical_input(domain, document_key, data).encode("utf-8")
        sig_bytes = base64.b64decode(author_signature)
        return get_suite(alg).verify(sig_bytes, canon, author_pub_hex)
    except Exception:
        return False


# ── Append-only element author proof ────────────────────────────────────────────


def append_author_canonical_input(document_key: str, data: dict[str, Any]) -> str:
    """Canonical input for an append ELEMENT's author signature (see module docs)."""
    return _author_canonical_input(APPEND_AUTHOR_DOMAIN, document_key, data)


def sign_append_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_priv_hex: str,
    alg: Alg = DEFAULT_ALG,
) -> AppendAuthor:
    """Sign an append element's ``data`` (bound to ``document_key``) under ``alg``.

    ``author_pub_hex`` MUST be the public key matching ``author_priv_hex``
    (typically the same key that signs the HTTP request).
    """
    return _sign(APPEND_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_priv_hex, alg)


def verify_append_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_signature: str,
    alg: Alg = DEFAULT_ALG,
) -> bool:
    """Verify an append element's author signature. Returns ``False`` on any
    cryptographic or decoding error (never raises)."""
    return _verify(APPEND_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_signature, alg)


# ── Merge-document author proof ──────────────────────────────────────────────────


def doc_author_canonical_input(document_key: str, data: dict[str, Any]) -> str:
    """Canonical input for a merge DOCUMENT's author signature (see module docs)."""
    return _author_canonical_input(DOC_AUTHOR_DOMAIN, document_key, data)


def sign_doc_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_priv_hex: str,
    alg: Alg = DEFAULT_ALG,
) -> AppendAuthor:
    """Sign a merge document's ``data`` (bound to ``document_key``) under ``alg``."""
    return _sign(DOC_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_priv_hex, alg)


def verify_doc_author(
    document_key: str,
    data: dict[str, Any],
    author_pub_hex: str,
    author_signature: str,
    alg: Alg = DEFAULT_ALG,
) -> bool:
    """Verify a merge document's author signature. Returns ``False`` on any
    cryptographic or decoding error (never raises)."""
    return _verify(DOC_AUTHOR_DOMAIN, document_key, data, author_pub_hex, author_signature, alg)


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
