"""Starfish v3.0 — public links (audience caps). Mirror of public-link.ts.

Alice owns a plaintext (``encryption: "none"``) ``broadcast`` collection and
shares a link to it. Two flavors:

  1. OPEN link      — anyone holding a Starfish identity may redeem; each signs
                      with their OWN key (attributable, no embedded private key).
  2. RESTRICTED link — only a listed set of identities may redeem; the server
                      enforces the allow-list (the cap's ``aud``), 403 otherwise.

Both are minted with ``create_public_link`` (an ``audience`` cap-cert packed
into a URL ``#fragment``). A redeemer calls ``parse_public_link`` +
``redeem_public_link`` to produce request headers (incl. ``X-Starfish-Pub``).

Run:
    python examples/python/public_link.py
"""

import time

from starfish_identities import bootstrap_root_identity
from starfish_sharing import (
    create_public_link,
    parse_public_link,
    redeem_public_link,
    scopes,
)


def main() -> None:
    alice = bootstrap_root_identity("alice-passphrase")
    bob = bootstrap_root_identity("bob-passphrase")
    carol = bootstrap_root_identity("carol-passphrase")
    stranger = bootstrap_root_identity("stranger-passphrase")

    # ── 1. OPEN link: any identity may redeem, expires in 7 days. ────────────
    open_link = create_public_link(
        alice.device["edPriv"],
        alice.device["edPub"],
        "broadcast",
        scopes.read_only("broadcast"),
        ttl_sec=7 * 24 * 3600,
    )
    print("open link    :", f"https://app.example/#{open_link.fragment[:24]}…")
    print("  aud        :", open_link.cap.get("aud", "(none → anyone)"))

    # ── 2. RESTRICTED link: only Bob and Carol may redeem. ───────────────────
    restricted = create_public_link(
        alice.device["edPriv"],
        alice.device["edPub"],
        "broadcast",
        scopes.read_only("broadcast"),
        allowed_identities=[bob.device["edPub"], carol.device["edPub"]],
        expires_at=int(time.time()) + 3600,  # absolute expiry, 1h
    )
    print("restricted   :", f"https://app.example/#{restricted.fragment[:24]}…")
    print("  aud        :", restricted.cap["aud"])

    # ── 3. Bob redeems the restricted link, signing as himself. ──────────────
    parsed = parse_public_link(restricted.fragment)
    bob_headers = redeem_public_link(
        parsed,
        redeemer_ed_priv_hex=bob.device["edPriv"],
        redeemer_ed_pub_hex=bob.device["edPub"],
        method="GET",
        path_and_query="/pull/broadcast/post-1",
        host="api.example.com",
    )
    print("\nBob's request headers (in aud → server authorizes):")
    print("  X-Starfish-Pub:", bob_headers["X-Starfish-Pub"])

    print("\nStranger's pubkey:", stranger.device["edPub"], "→ NOT in aud → 403 server-side")

    # Revocation: no single subject — revoke the whole link by its nonce
    # (signed RevocationList entry with sub="" + restricted.cap["nonce"]), or
    # re-mint with a trimmed allowed_identities.


if __name__ == "__main__":
    main()
