/**
 * Frontend end-to-end regression test (TypeScript library side).
 *
 * Drives the real chat app in a browser across two tabs, exercising the
 * identities → keyring → sharing → queuing → entitlements chain through the
 * `@drakkar.software/*` packages as a user would, against the redesigned
 * ("tidepool") UI: rooms sidebar, message bubbles, profile modal, and the
 * invite / devices / premium / activity drawers.
 *
 * Prerequisites — the backend and frontend must already be running:
 *   1. cd examples/app/backend && uv run uvicorn server:app --port 8000
 *   2. cd examples/app/frontend && pnpm dev          # http://localhost:5173
 *
 * Run:
 *   cd examples/app/frontend
 *   pnpm add -D @playwright/test && npx playwright install chromium
 *   npx playwright test
 */
import { test, expect, type Page } from "@playwright/test"

const APP = "http://localhost:5173"

async function freshLoad(page: Page) {
  await page.goto(APP)
  await page.evaluate(() => localStorage.clear())
  await page.goto(APP)
}

/** Sign in on the "Open a room" tab as the owner of `room`. */
async function loginOwner(page: Page, name: string, passphrase: string, room = "general") {
  await freshLoad(page)
  await page.getByRole("button", { name: "Open a room" }).click()
  await page.getByLabel("Display name").fill(name)
  await page.getByLabel("Passphrase").fill(passphrase)
  await page.getByLabel("Room", { exact: true }).fill(room)
  await page.getByRole("button", { name: "Open room" }).click()
  await expect(page.getByRole("button", { name: "Invite" })).toBeVisible()
}

/** Sign in on the "Join" tab — lands on the "Join a room" activation screen. */
async function loginMember(page: Page, name: string, passphrase: string) {
  await freshLoad(page)
  await page.getByRole("button", { name: "Join", exact: true }).click()
  await page.getByLabel("Display name").fill(name)
  await page.getByLabel("Passphrase").fill(passphrase)
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByLabel("Member cap")).toBeVisible() // the "Join a room" activation screen
}

const inviteCode = (p: Page) => p.getByLabel("Your invite code").inputValue()

test("owner + read/write member share an encrypted room", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const memberCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const member = await memberCtx.newPage()

  // Owner opens "general" and sets a profile pseudo via the profile modal.
  await loginOwner(owner, "Alice", "alice-pw-" + Date.now())
  await owner.getByRole("button", { name: "Open profile" }).click()
  await owner.getByLabel("Pseudo").fill("AliceStar")
  await owner.getByRole("button", { name: "Save pseudo" }).click()
  await expect(owner.getByText("Saved ✓")).toBeVisible()
  await owner.getByRole("button", { name: "Close" }).click()

  await owner.getByPlaceholder("Type a message…").fill("Hello from Alice!")
  await owner.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("Hello from Alice!")).toBeVisible()

  // Member signs in and shares its invite code.
  await loginMember(member, "Bob", "bob-pw-" + Date.now())
  const bobInvite = await inviteCode(member)

  // Owner opens the invite drawer, mints a read/write member cap.
  await owner.getByRole("button", { name: "Invite" }).click()
  await owner.getByLabel("Invite info").fill(bobInvite)
  await owner.getByRole("button", { name: "Read & write" }).click()
  await owner.getByRole("button", { name: "Mint member cap" }).click()
  const memberCap = await owner.getByLabel("Member cap output").inputValue()
  expect(memberCap).toContain('"kind":"member"')
  // The member directory now lists Bob with a read/write tag (CSS uppercases it).
  await expect(owner.getByText("read/write")).toBeVisible()
  await owner.getByRole("button", { name: "Close" }).click()

  // Member activates → decrypts history (keyring) and sees the author's pseudo.
  await member.getByLabel("Member cap").fill(memberCap)
  await member.getByRole("button", { name: "Activate invite" }).click()
  await expect(member.getByText("Hello from Alice!")).toBeVisible() // decrypted
  await expect(member.getByText("AliceStar")).toBeVisible() // public profile pseudo

  // Member posts; owner sees it live (queuing → SSE → pull).
  await member.getByPlaceholder("Type a message…").fill("Hi Alice, Bob here!")
  await member.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("Hi Alice, Bob here!")).toBeVisible({ timeout: 5000 })

  await ownerCtx.close()
  await memberCtx.close()
})

test("read-only member can read but not post", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const memberCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const member = await memberCtx.newPage()

  await loginOwner(owner, "Alice", "alice-ro-" + Date.now())
  await owner.getByPlaceholder("Type a message…").fill("read only test")
  await owner.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("read only test")).toBeVisible()

  await loginMember(member, "Carol", "carol-ro-" + Date.now())
  const carolInvite = await inviteCode(member)

  await owner.getByRole("button", { name: "Invite" }).click()
  await owner.getByLabel("Invite info").fill(carolInvite)
  // leave the default "Read-only" segment selected
  await owner.getByRole("button", { name: "Mint member cap" }).click()
  const cap = await owner.getByLabel("Member cap output").inputValue()
  await owner.getByRole("button", { name: "Close" }).click()

  await member.getByLabel("Member cap").fill(cap)
  await member.getByRole("button", { name: "Activate invite" }).click()
  await expect(member.getByText("read only test")).toBeVisible() // can decrypt + read
  await expect(member.getByText(/invited read-only/)).toBeVisible() // lock note
  await expect(member.getByRole("button", { name: "Send" })).toBeDisabled() // cannot post

  await ownerCtx.close()
  await memberCtx.close()
})

test("owner can create and switch between isolated rooms", async ({ page }) => {
  await loginOwner(page, "Dana", "dana-pw-" + Date.now())
  await page.getByPlaceholder("Type a message…").fill("hello in general")
  await page.getByRole("button", { name: "Send" }).click()
  await expect(page.getByText("hello in general")).toBeVisible()

  // Create a second room from the sidebar.
  await page.getByRole("button", { name: "New room" }).click()
  await page.getByLabel("New room id").fill("random")
  await page.getByRole("button", { name: "Add", exact: true }).click()

  // The new room is empty — general's messages do not leak in (isolation).
  await expect(page.getByText("No messages yet")).toBeVisible()
  await expect(page.getByText("hello in general")).toHaveCount(0)

  // Switching back shows the original message again.
  await page.getByRole("button", { name: "general" }).click()
  await expect(page.getByText("hello in general")).toBeVisible()
})

test("opening a room owned by another identity shows a clear membership error", async ({ browser }) => {
  const room = "owned-" + Date.now()

  // First identity opens the room — creates its keyring (recipient = itself).
  const ctxA = await browser.newContext()
  const a = await ctxA.newPage()
  await loginOwner(a, "First", "first-pw-" + Date.now(), room)
  await ctxA.close()

  // A different passphrase opening the SAME room id is not a keyring recipient.
  // The raw "No wrapped key for recipient … in current epoch N" is translated
  // into an actionable message that names the room and the real cause.
  const ctxB = await browser.newContext()
  const b = await ctxB.newPage()
  await freshLoad(b)
  await b.getByRole("button", { name: "Open a room" }).click()
  await b.getByLabel("Display name").fill("Second")
  await b.getByLabel("Passphrase").fill("second-pw-" + Date.now())
  await b.getByLabel("Room", { exact: true }).fill(room)
  await b.getByRole("button", { name: "Open room" }).click()

  await expect(b.getByText(/isn't a member of room/)).toBeVisible()
  await expect(b.getByText(new RegExp(`"${room}"`))).toBeVisible() // names the room
  await expect(b.getByText(/No wrapped key for recipient/)).toHaveCount(0) // raw error hidden
  await ctxB.close()
})

test("owner can revoke a member's access", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const memberCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const member = await memberCtx.newPage()

  await loginOwner(owner, "Olivia", "olivia-rev-" + Date.now())
  await owner.getByPlaceholder("Type a message…").fill("before revoke")
  await owner.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("before revoke")).toBeVisible()

  await loginMember(member, "Mallory", "mallory-rev-" + Date.now())
  const inv = await inviteCode(member)

  await owner.getByRole("button", { name: "Invite" }).click()
  await owner.getByLabel("Invite info").fill(inv)
  await owner.getByRole("button", { name: "Read & write" }).click()
  await owner.getByRole("button", { name: "Mint member cap" }).click()
  const cap = await owner.getByLabel("Member cap output").inputValue()
  await owner.getByRole("button", { name: "Close" }).click()

  await member.getByLabel("Member cap").fill(cap)
  await member.getByRole("button", { name: "Activate invite" }).click()
  await member.getByPlaceholder("Type a message…").fill("member is here")
  await member.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("member is here")).toBeVisible({ timeout: 5000 })

  // Owner revokes the member: cap revoked (401), keyring epoch rotated, entry removed.
  await owner.getByRole("button", { name: "Invite" }).click()
  await expect(owner.getByText("read/write")).toBeVisible()
  await owner.getByRole("button", { name: "Revoke" }).click()
  await expect(owner.getByText("read/write")).toHaveCount(0) // dropped from the member list

  // The revoked member's next post no longer reaches the owner (cap → 401).
  await member.getByPlaceholder("Type a message…").fill("after revoke")
  await member.getByRole("button", { name: "Send" }).click()
  await owner.waitForTimeout(2500)
  await expect(owner.getByText("after revoke")).toHaveCount(0)

  await ownerCtx.close()
  await memberCtx.close()
})

test("owner can list and revoke a linked device", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const devCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const device = await devCtx.newPage()

  await loginOwner(owner, "Devon", "devon-dev-" + Date.now(), "general")

  // The owner's own device is recorded and listed.
  await owner.getByRole("button", { name: "Devices" }).click()
  await expect(owner.getByText("this device")).toBeVisible()

  // A brand-new device generates a pairing request for "general" (two-way flow).
  await freshLoad(device)
  await device.getByRole("button", { name: "Pair device" }).click()
  await device.getByRole("button", { name: "Request / response" }).click()
  await device.getByLabel("Device name").fill("Laptop")
  await device.getByLabel("Room to join").fill("general")
  await device.getByRole("button", { name: "Generate pairing request" }).click()
  const request = await device.getByLabel("Pairing request").inputValue()

  // Owner authorises it — records the paired device, which gains a Revoke button.
  await owner.getByLabel("Pairing request input").fill(request)
  await owner.getByRole("button", { name: "Authorise device" }).click()
  const bundle = await owner.getByLabel("Pairing bundle output").inputValue()
  await expect(owner.getByRole("button", { name: /^Revoke/ })).toBeVisible()

  // Device installs the bundle and joins as the same account.
  await device.getByLabel("Pairing bundle").fill(bundle)
  await device.getByRole("button", { name: /^Install & join/ }).click()
  await expect(device.getByLabel("Message")).toBeVisible()

  // Owner revokes the paired device → it disappears from the list.
  await owner.getByRole("button", { name: /^Revoke/ }).click()
  await expect(owner.getByRole("button", { name: /^Revoke/ })).toHaveCount(0)

  await ownerCtx.close()
  await devCtx.close()
})

test("owner can provision a new device with a single setup code", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const devCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const device = await devCtx.newPage()

  await loginOwner(owner, "Pat", "pat-prov-" + Date.now(), "general")

  // Owner posts a message first, so we can prove the new device decrypts existing history.
  await owner.getByPlaceholder("Type a message…").fill("hi from Pat")
  await owner.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("hi from Pat")).toBeVisible()

  // Owner generates one self-contained setup code (it carries the new device's keys);
  // the provisioned device is recorded in the directory.
  await owner.getByRole("button", { name: "Devices" }).click()
  await owner.getByRole("button", { name: "Provision a new device" }).click()
  const code = await owner.getByLabel("Provisioning code output").inputValue()
  expect(code).toContain('"roomId":"general"')
  await expect(owner.getByText("provisioned device")).toBeVisible()

  // The new device installs it in one step — nothing to send back ("Setup code" is the default mode).
  await freshLoad(device)
  await device.getByRole("button", { name: "Pair device" }).click()
  await device.getByLabel("Provisioning code").fill(code)
  await device.getByRole("button", { name: /^Install & join/ }).click()
  await expect(device.getByLabel("Message")).toBeVisible()
  // It authenticates as the same account and decrypts the room history.
  await expect(device.getByText("hi from Pat")).toBeVisible()

  await ownerCtx.close()
  await devCtx.close()
})

test("a PIN-protected setup code needs the right PIN to install", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const devCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const device = await devCtx.newPage()

  await loginOwner(owner, "Pat", "pat-pin-" + Date.now(), "general")

  await owner.getByPlaceholder("Type a message…").fill("secret history")
  await owner.getByRole("button", { name: "Send" }).click()
  await expect(owner.getByText("secret history")).toBeVisible()

  // Owner seals the setup code with a PIN before generating it.
  await owner.getByRole("button", { name: "Devices" }).click()
  await owner.getByLabel("Provisioning PIN").fill("correct horse battery staple")
  await owner.getByRole("button", { name: "Provision a new device" }).click()
  const code = await owner.getByLabel("Provisioning code output").inputValue()
  // Sealed: the cleartext no longer carries the roomId — it's a passphrase envelope.
  expect(code).not.toContain('"roomId"')
  expect(code).toContain('"enc":"passphrase"')

  await freshLoad(device)
  await device.getByRole("button", { name: "Pair device" }).click()
  await device.getByLabel("Provisioning code").fill(code)

  // No PIN → the device asks for one rather than failing the shape check.
  await device.getByRole("button", { name: /^Install & join/ }).click()
  await expect(device.getByText(/PIN-protected/)).toBeVisible()

  // Wrong PIN → one generic failure (no leak of whether it was tamper vs. wrong PIN).
  await device.getByLabel("Setup PIN").fill("wrong pin")
  await device.getByRole("button", { name: /^Install & join/ }).click()
  await expect(device.getByText(/Incorrect PIN/)).toBeVisible()

  // Right PIN → installs and decrypts the room history.
  await device.getByLabel("Setup PIN").fill("correct horse battery staple")
  await device.getByRole("button", { name: /^Install & join/ }).click()
  await expect(device.getByLabel("Message")).toBeVisible()
  await expect(device.getByText("secret history")).toBeVisible()

  await ownerCtx.close()
  await devCtx.close()
})

test("a member can leave a room (local forget)", async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const memberCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const member = await memberCtx.newPage()

  await loginOwner(owner, "Quinn", "quinn-leave-" + Date.now())
  await loginMember(member, "Riley", "riley-leave-" + Date.now())
  const inv = await inviteCode(member)

  await owner.getByRole("button", { name: "Invite" }).click()
  await owner.getByLabel("Invite info").fill(inv)
  await owner.getByRole("button", { name: "Read & write" }).click()
  await owner.getByRole("button", { name: "Mint member cap" }).click()
  const cap = await owner.getByLabel("Member cap output").inputValue()

  await member.getByLabel("Member cap").fill(cap)
  await member.getByRole("button", { name: "Activate invite" }).click()
  await expect(member.getByLabel("Message")).toBeVisible()

  // Leave room → inline confirm → back at the sign-in screen (no server removal).
  await member.getByRole("button", { name: "Leave room" }).click()
  await member.getByRole("button", { name: "Confirm leave" }).click()
  await expect(member.getByRole("button", { name: "Open a room" })).toBeVisible()

  await ownerCtx.close()
  await memberCtx.close()
})

test("entitlements unlock a paid feature client-side", async ({ page }) => {
  await loginOwner(page, "Eve", "eve-pw-" + Date.now())
  await page.getByRole("button", { name: "Premium" }).click()
  await expect(page.getByText("Premium is locked")).toBeVisible()
  await page.getByRole("button", { name: "Unlock premium (demo grant)" }).click()
  await expect(page.getByText("Premium unlocked!")).toBeVisible()
  await expect(page.getByText("premium", { exact: true })).toBeVisible() // slug chip
})

test("a markup pseudo renders as inert text (XSS is a rendering responsibility, met)", async ({ page }) => {
  // The server stores values verbatim (see backend `test_profile_pseudo_is_stored_verbatim…`);
  // safety against XSS is the frontend's job. React/JSX escapes by default — pin that here.
  await loginOwner(page, "Mallory", "xss-pw-" + Date.now())
  await page.evaluate(() => {
    ;(window as unknown as { __xssFired?: boolean }).__xssFired = false
  })
  const payload = `<img src=x onerror="window.__xssFired=true">`
  await page.getByRole("button", { name: "Open profile" }).click()
  await page.getByLabel("Pseudo").fill(payload)
  await page.getByRole("button", { name: "Save pseudo" }).click()
  await expect(page.getByText("Saved ✓")).toBeVisible()
  await page.getByRole("button", { name: "Close" }).click()
  // The pseudo is shown as LITERAL text (escaped), and the injected onerror never ran.
  await expect(page.getByText(payload).first()).toBeVisible()
  expect(await page.evaluate(() => (window as unknown as { __xssFired?: boolean }).__xssFired)).toBe(false)
})

test("camera-free pairing requires the root-key pin before joining (anti-MITM)", async ({ page }) => {
  // The rendezvous slot is public + anonymously overwritable, so the new device MUST pin
  // the first device's root key (the lib throws without it). The UI gates the join button
  // on it so the user can't submit an unpinned install.
  await freshLoad(page)
  await page.getByRole("button", { name: "Pair device" }).click()
  await page.getByRole("button", { name: "Phone scans" }).click()
  await page.getByRole("button", { name: "Show pairing QR" }).click()
  const join = page.getByRole("button", { name: /Added from first device/ })
  await expect(join).toBeDisabled() // empty root pin → cannot finish
  await page.getByLabel("Expected root public key").fill("a".repeat(64))
  await expect(join).toBeEnabled() // pin provided → enabled
})
