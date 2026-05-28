# Test-vector generators

Python scripts that produce the JSON files in `tests/test-vectors/`. Each
generator is **deterministic** — every key, nonce, IV, and signature is
derived (HKDF / fixed seed) so running a script reproduces the existing
vector byte-for-byte.

The vectors lock canonical encodings and signatures so the TypeScript and
Python implementations stay in lockstep. If you change a generator, you are
implicitly changing the wire format — re-run every vector and update both
implementations together.

## Install dependencies

```bash
pip install 'cryptography>=41.0' 'argon2-cffi>=21.0' 'coincurve>=19.0'
```

`cryptography` supplies HKDF / Ed25519 / X25519 / AES-GCM; `argon2-cffi` the
root-passphrase Argon2id stretch; `coincurve` the BIP-340 Schnorr +
secp256k1 ECDH used by `identity_derivation_secp256k1.py` (the external-root
bootstrap derivation — Starfish itself speaks ed25519 only on the wire).

## Run a generator

From the repository root (or any directory — the scripts resolve paths via
`__file__`):

```bash
python3 tests/test-vectors/_generators/identity_derivation.py
python3 tests/test-vectors/_generators/identity_derivation_secp256k1.py
python3 tests/test-vectors/_generators/cap_cert.py
python3 tests/test-vectors/_generators/multi_recipient_wrap.py
python3 tests/test-vectors/_generators/pairing_bundle.py
python3 tests/test-vectors/_generators/request_signature.py
python3 tests/test-vectors/_generators/revocation_list.py
```

Each script writes a sibling file inside `tests/test-vectors/`:

| Generator                              | Output vector                            |
| -------------------------------------- | ---------------------------------------- |
| `identity_derivation.py`               | `identity-derivation.json`               |
| `identity_derivation_secp256k1.py`     | `identity-derivation-secp256k1.json`     |
| `cap_cert.py`                          | `cap-cert.json`                          |
| `multi_recipient_wrap.py`              | `multi-recipient-wrap.json`              |
| `pairing_bundle.py`                    | `pairing-bundle.json`                    |
| `request_signature.py`                 | `request-signature.json`                 |
| `revocation_list.py`                   | `revocation-list.json`                   |

## Shared module: `_common.py`

`_common.py` is **not a runnable script**. It is the module every generator
imports for fixtures, HKDF parameters, the `stable_stringify` reference,
and Ed25519 / X25519 / AES-GCM helpers. Each script adds its parent
directory to `sys.path` and imports `_common` as a sibling module.

## Fixture chain

All generators share a small cast of identities defined in `_common.FIXTURES`:

| Name          | Kind   | Derivation                                                                 |
| ------------- | ------ | -------------------------------------------------------------------------- |
| `alice_root`  | root   | `derive_root("alice-root-passphrase", "alice-root")`                       |
| `alice_dev_1` | device | `derive_device("alice-root-passphrase", "alice-laptop")`                   |
| `alice_dev_2` | device | `derive_device("alice-root-passphrase", "alice-phone")`                    |
| `bob_root`    | root   | `derive_root("bob-root-passphrase", "bob-root")`                           |
| `bob_dev_1`   | device | `derive_device("bob-root-passphrase", "bob-laptop")`                       |

Root identities use HKDF parameters
`(ROOT_ED_SALT="starfish-root-sign"/ROOT_ED_INFO="ed25519")` and
`(ROOT_KEM_SALT="starfish-root-kem"/ROOT_KEM_INFO="x25519")` — matching the
production v3 `deriveRootIdentity` derivation byte-for-byte. Device
identities are random in production; the generators use a separate
HKDF salt/info pair (`DEVICE_ED_SALT="starfish-device-sign-test-vector"`,
etc.) so vector keys never collide with real device keys.

The same fixture appears in multiple vectors so they cross-reference
(e.g. the `alice_dev_1` whose key derivation lives in
`identity-derivation.json` is the same `alice_dev_1` whose cap-cert
appears in `cap-cert.json` and whose revocation entry lives in
`revocation-list.json`).
