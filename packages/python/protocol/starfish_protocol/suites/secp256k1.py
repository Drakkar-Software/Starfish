"""``secp256k1-schnorr`` suite — the "Nostr" identity model: BIP-340 Schnorr
signing + secp256k1 ECDH (the KEM half), over one secp256k1 key. (npub/nsec
bech32 encoding lands in a later phase.)

Compatibility note: this shares Nostr's *key type* (secp256k1 x-only) and the
ECDH *primitive*, but is NOT Nostr/NIP-44 wire-interoperable. Signatures are over
``sha256(canonical Starfish bytes)``, not a NIP-01 event id, and the keyring wrap
uses Starfish's own HKDF (``salt="starfish-wrap"``, suite-tagged info) — not
NIP-44's ``conversation_key`` / per-message nonce. A stock Nostr client can
neither verify these signatures nor unwrap these keys.

Mirrors ``packages/ts/protocol/src/suites/secp256k1.ts``. Three choices keep the
TypeScript (``@noble/curves``) and Python (``coincurve``) sides byte-identical:

1. **Hash-then-sign** — both sign ``sha256(message)`` (32 bytes). libsecp256k1's
   ``schnorrsig_sign32`` (wrapped by coincurve) takes exactly 32 bytes, while
   ``@noble`` accepts arbitrary length; signing the digest makes them agree.
2. **Deterministic ``aux_rand = 0``** (32 zero bytes) — BIP-340 §3 permits it,
   yielding reproducible signatures for cross-language test vectors. It forgoes
   the side-channel hardening random aux would add (accepted trade, matches the
   deterministic ``ed25519`` suite).
3. **ECDH = x-coordinate of the shared point, x-only keys lifted even-y.** Public
   keys are 32-byte BIP-340 x-only (no parity). For ECDH we lift the peer to its
   even-y point (``0x02‖x``), multiply by our scalar, and take the
   **x-coordinate**. This is parity-free (``k·P`` and ``k·(−P)`` share an x), so
   it is symmetric without storing parity. This is the same ECDH *primitive*
   shape Nostr/NIP-44 uses; the wrap KDF on top differs (see the compatibility
   note above). Byte-identical to ``@noble``'s
   ``getSharedSecret(priv, "02"+x).subarray(1, 33)``.

``coincurve`` is imported lazily inside the methods so that ed25519-only
deployments (and merely importing this package) do not require the libsecp256k1
C extension — relevant for edge/serverless Python targets.
"""

from __future__ import annotations

import hashlib

from starfish_protocol.suites._kem import assert_usable_shared_secret

# Deterministic auxiliary randomness — 32 zero bytes (BIP-340 permits this).
_ZERO_AUX = b"\x00" * 32


class Secp256k1SchnorrSuite:
    alg = "secp256k1-schnorr"

    def sign(self, message: bytes, priv_hex: str) -> bytes:
        from coincurve import PrivateKey

        priv = PrivateKey(bytes.fromhex(priv_hex))
        return priv.sign_schnorr(hashlib.sha256(message).digest(), _ZERO_AUX)

    def verify(self, sig: bytes, message: bytes, pub_hex: str) -> bool:
        # Catch *every* exception: the CryptoSuite contract is "verify never
        # raises". This includes ImportError when the optional `coincurve` C
        # extension is absent (ed25519-only edge deployments) — a secp256k1
        # signature there must fail closed, not crash the request with a 500
        # and a logged traceback (an unauthenticated log-amplification DoS).
        try:
            from coincurve import PublicKeyXOnly

            pub = PublicKeyXOnly(bytes.fromhex(pub_hex))
            return pub.verify(sig, hashlib.sha256(message).digest())
        except Exception:
            return False

    def derive_shared_secret(self, priv_hex: str, peer_pub_hex: str) -> bytes:
        from coincurve import PublicKey

        # Lift the x-only peer to even-y (0x02 prefix), multiply by our scalar,
        # take the x-coordinate of the shared point.
        peer = PublicKey(b"\x02" + bytes.fromhex(peer_pub_hex))
        shared = peer.multiply(bytes.fromhex(priv_hex)).format(compressed=True)[1:]
        assert_usable_shared_secret(shared)
        return shared

    def generate_kem_keypair(self) -> tuple[str, str]:
        from coincurve import PrivateKey

        priv = PrivateKey()
        priv_hex = priv.secret.hex()
        pub_hex = priv.public_key.format(compressed=True)[1:].hex()
        return (priv_hex, pub_hex)

    def kem_public(self, priv_hex: str) -> str:
        from coincurve import PrivateKey

        return PrivateKey(bytes.fromhex(priv_hex)).public_key.format(compressed=True)[1:].hex()
