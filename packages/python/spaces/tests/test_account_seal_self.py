"""Tests for account_seal self-sealed enforcement."""

from __future__ import annotations

import json

import pytest
from starfish_identities import generate_device_keys

from starfish_spaces.account_seal import (
    seal_to_recipient,
    seal_to_self,
    unseal_from_self,
)


def test_seal_to_self_round_trips():
    keys = generate_device_keys()
    blob = seal_to_self({"keys": keys}, json.dumps({"secret": 42}))
    assert unseal_from_self({"keys": keys}, blob) == json.dumps({"secret": 42})


def test_unseal_from_self_rejects_blob_signed_by_other_key():
    me = generate_device_keys()
    other = generate_device_keys()

    # A validly-signed blob, decryptable by `me`, but sealed (addedBy) by `other`.
    blob = seal_to_recipient(other, "", me["kemPub"], json.dumps({"secret": 1}))
    assert blob["entry"]["addedBy"] == other["edPub"]

    with pytest.raises(ValueError):
        unseal_from_self({"keys": me}, blob)
