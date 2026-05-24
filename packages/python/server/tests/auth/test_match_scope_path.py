"""Unit tests for ``match_scope_path`` deny-rule semantics.

Regression coverage for the deny-evasion gap: an owner-only deny such as
``!col/_keyring`` must not be bypassable with a superstring request path —
a trailing slash, an extra path segment, a ``.`` segment, or a double slash.
A deny also covers descendants of the denied path.
"""

from starfish_server.router.cap_resolver import match_scope_path

WRITER = ["col/**", "!col/_keyring", "!col/_members"]


def test_allows_normal_document():
    assert match_scope_path("col/doc", WRITER) is True


def test_denies_exact_keyring():
    assert match_scope_path("col/_keyring", WRITER) is False


def test_denies_keyring_trailing_slash():
    assert match_scope_path("col/_keyring/", WRITER) is False


def test_denies_keyring_extra_segment():
    assert match_scope_path("col/_keyring/x", WRITER) is False


def test_denies_keyring_dot_segment():
    assert match_scope_path("col/./_keyring", WRITER) is False


def test_denies_keyring_double_slash():
    assert match_scope_path("col//_keyring", WRITER) is False


def test_denies_members_descendant():
    assert match_scope_path("col/_members/anything", WRITER) is False


def test_does_not_overdeny_similar_prefix():
    # A different document whose name merely starts with the denied name is allowed —
    # the deny covers ``col/_keyring`` and ``col/_keyring/...``, not ``col/_keyring_x``.
    assert match_scope_path("col/_keyring_public", WRITER) is True
    assert match_scope_path("col/_memberslist", WRITER) is True


def test_no_scope_means_unrestricted():
    assert match_scope_path("anything/at/all", None) is True
    assert match_scope_path("anything", []) is True


def test_denied_when_no_allow_matches():
    assert match_scope_path("other/doc", WRITER) is False
