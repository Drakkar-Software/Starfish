---
sidebar_position: 8
---

# Root-Only Collections

A **root-only** collection can be accessed only by the user's **root device** — the
device whose cap is self-signed (`iss === sub`), produced by `bootstrapRootIdentity`.
Every other credential the same user holds — a paired/provisioned device cap (minted by
the root, so `iss !== sub`) or a member cap shared with another user — is rejected with
`403`, on top of the collection's normal `readRoles` / `writeRoles` checks.

Because the server gatekeeps every `pull` / `push` / `list` (and bundle pull), rejecting
there fully blocks access regardless of which keys or caps a device already holds — no
keyring rotation or cap revocation is required.

## When to use

- A collection that should never leave the primary device — recovery secrets, a device's
  master configuration, an export/escrow blob.
- Paired devices are convenient for day-to-day data but must not reach a privileged
  collection, even though they share the same root identity.

## Configuration

```ts
// TypeScript server
{
  name: "recovery",
  storagePath: "recovery/{slot}",
  readRoles: ["cap:read:recovery"],
  writeRoles: ["cap:write:recovery"],
  encryption: "none",
  maxBodyBytes: 65536,
  rootOnly: true,
}
```

```python
# Python server
CollectionConfig(
    name="recovery",
    storage_path="recovery/{slot}",
    read_roles=["cap:read:recovery"],
    write_roles=["cap:write:recovery"],
    encryption="none",
    max_body_bytes=65536,
    root_only=True,
)
```

## Behavior

- The cap-resolver synthesizes a `device:root` role (`ROLE_ROOT_DEVICE`) for a self-signed
  device cap. A root-only collection requires that role in addition to its configured
  `readRoles` / `writeRoles`.
- Paired devices typically share the root's scope, so the role check alone would admit
  them — the root-only gate is what distinguishes the root device from its delegates.
- Bundle pulls enforce the same rule: a root-only member is silently omitted from the
  bundle for a non-root caller and included for the root device.
- A root-only collection is never public: combining `rootOnly` with a `"public"` entry in
  `readRoles` / `writeRoles` is rejected at config load.

## Soundness boundary

`rootOnly` distinguishes the **root device from the user's own delegated devices/members**
— the intended threat model. It is purely additive: it can only *deny* access the normal
checks would otherwise grant. The predicate identifies a self-signed device cap; it does
not by itself prove the cap belongs to a particular root identity. Cross-user isolation
continues to come from the existing `{identity}` URL-param binding and identity-scoped
storage paths, exactly as for non-root-only collections.

## Scope

`rootOnly` governs **data access** (pull / push / list / bundle). It does not change the
opt-in `GET /config` discovery endpoint, which lists collection definitions (not data)
according to its own `auth` mode.
