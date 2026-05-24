import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import type { CSSProperties, FormEvent, ReactNode } from "react"
import { createUnionMerge } from "@drakkar.software/starfish-client"
import {
  useConnectivity,
  useStarfish,
  useStarfishData,
  useSyncInit,
  useSyncStatus,
} from "@drakkar.software/starfish-client/zustand"
import type { SyncInitConfig } from "@drakkar.software/starfish-client/zustand"
import { pullEntitlements } from "@drakkar.software/starfish-entitlements"
import {
  API_BASE,
  DEFAULT_ROOM,
  SYNC_BASE,
  authorizeDeviceViaRendezvous,
  buildProvisionedDeviceSession,
  capProviderFor,
  demoGrant,
  demoRevoke,
  fetchAndBuildDeviceSession,
  fetchAudit,
  friendlyRoomError,
  leaveRoomLocal,
  listOwnDevices,
  provisionRoomDevice,
  readMembers,
  readPseudo,
  recordDevice,
  revokeDevice,
  revokeMember,
  roomPull,
  roomPush,
  startQrInPairing,
  writePseudo,
} from "./starfish.js"
import type { AuditRow, DeviceCapPreset, DeviceEntry, DeviceKeys, MemberRow } from "./starfish.js"
import {
  activateMember,
  authorizeDevice,
  buildDeviceSession,
  buildMemberSession,
  buildOwnerSession,
  invite,
  startPairing,
  switchRoom,
} from "./session.js"
import type { InviteInfo, Session } from "./session.js"

interface ChatMessage {
  id: string
  from: string
  name: string
  text: string
  ts: number
}

type DrawerKey = "invite" | "devices" | "premium" | "activity"

/**
 * Rough PIN/passphrase strength for the provisioning UI. A short numeric PIN is
 * weak (offline-brute-forceable even through Argon2id); length + character
 * variety push it toward "strong". This only hints — the library accepts any
 * non-empty passphrase.
 */
function pinStrength(s: string): "" | "weak" | "fair" | "strong" {
  if (!s) return ""
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(s)).length
  if (/^\d+$/.test(s) && s.length < 8) return "weak"
  if (s.length >= 12 && classes >= 2) return "strong"
  if (s.length >= 8 || classes >= 2) return "fair"
  return "weak"
}

const DRAWER_TITLE: Record<DrawerKey, string> = {
  invite: "Invite & members",
  devices: "Devices",
  premium: "Premium",
  activity: "Activity",
}

// ── Icons (inline, stroke = currentColor) ────────────────────────────────────
function Svg({
  size = 18,
  className,
  style,
  children,
}: {
  size?: number
  className?: string
  style?: CSSProperties
  children: ReactNode
}) {
  return (
    <svg
      className={className}
      style={style}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {children}
    </svg>
  )
}
type IconProps = { size?: number; className?: string; style?: CSSProperties }
const IconSend = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 19V5" />
    <path d="m5 12 7-7 7 7" />
  </Svg>
)
const IconPlus = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
)
const IconGem = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3v3M12 18v3M3 12h3M18 12h3" />
    <path d="m12 7 1.7 3.3L17 12l-3.3 1.7L12 17l-1.7-3.3L7 12l3.3-1.7z" />
  </Svg>
)
const IconActivity = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 12h4l3 8 4-16 3 8h4" />
  </Svg>
)
const IconLogout = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <path d="m16 17 5-5-5-5M21 12H9" />
  </Svg>
)
const IconClose = (p: IconProps) => (
  <Svg {...p}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Svg>
)
const IconInvite = (p: IconProps) => (
  <Svg {...p}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M19 8v6M22 11h-6" />
  </Svg>
)
const IconDevice = (p: IconProps) => (
  <Svg {...p}>
    <rect x="2" y="4" width="20" height="14" rx="2" />
    <path d="M8 20h8M12 18v2" />
  </Svg>
)
const IconCopy = (p: IconProps) => (
  <Svg {...p}>
    <rect x="9" y="9" width="13" height="13" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </Svg>
)
const IconCheck = (p: IconProps) => (
  <Svg {...p}>
    <path d="M20 6 9 17l-5-5" />
  </Svg>
)
const IconLock = (p: IconProps) => (
  <Svg {...p}>
    <rect x="4" y="11" width="16" height="9" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </Svg>
)

// ── Avatar ────────────────────────────────────────────────────────────────────
function hashHue(seed: string): number {
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0
  return h % 360
}
function avatarStyle(seed: string): CSSProperties {
  const hue = hashHue(seed)
  return { background: `linear-gradient(135deg, hsl(${hue} 64% 56%), hsl(${(hue + 38) % 360} 66% 44%))` }
}
function initials(label: string): string {
  const t = label.trim()
  return (t ? t[0]! : "?").toUpperCase()
}
function Avatar({ seed, label, size = "md" }: { seed: string; label: string; size?: "sm" | "md" | "lg" }) {
  return (
    <div className={`avatar ${size}`} style={avatarStyle(seed)} aria-hidden>
      {initials(label)}
    </div>
  )
}

// ── Copyable read-only field ────────────────────────────────────────────────
function CopyField({
  label,
  value,
  rows = 3,
  ariaLabel,
}: {
  label: string
  value: string
  rows?: number
  ariaLabel?: string
}) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      /* clipboard blocked — the textarea is still selectable */
    }
    setDone(true)
    setTimeout(() => setDone(false), 1400)
  }
  return (
    <div className="field copy-field">
      <span className="lbl">{label}</span>
      <textarea className="textarea" rows={rows} readOnly value={value} aria-label={ariaLabel ?? label} />
      {value && (
        <button type="button" className={`copy-btn ${done ? "done" : ""}`} onClick={copy}>
          {done ? (
            <>
              <IconCheck size={13} /> Copied
            </>
          ) : (
            <>
              <IconCopy size={13} /> Copy
            </>
          )}
        </button>
      )}
    </div>
  )
}

/** Resolve author pseudos from their public `profile` documents (cached). */
function usePseudos(userIds: string[]): Record<string, string> {
  const [pseudos, setPseudos] = useState<Record<string, string>>({})
  const key = userIds.join(",")
  useEffect(() => {
    const missing = userIds.filter((id) => !(id in pseudos))
    if (missing.length === 0) return
    let cancelled = false
    Promise.all(missing.map(async (id) => [id, await readPseudo(id)] as const)).then((pairs) => {
      if (cancelled) return
      setPseudos((prev) => {
        const next = { ...prev }
        for (const [id, p] of pairs) next[id] = p ?? id.slice(0, 8)
        return next
      })
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  return pseudos
}

/** Member directory for the owner UI (a member cap can't read it → `[]`). */
function useMembers(session: Session, refresh: number): MemberRow[] {
  const [members, setMembers] = useState<MemberRow[]>([])
  const canRead = session.role === "owner" || session.role === "device"
  useEffect(() => {
    if (!canRead || !session.chatClient || !session.roomId) {
      setMembers([])
      return
    }
    let cancel = false
    readMembers(session.chatClient, session.roomId).then((m) => {
      if (!cancel) setMembers(m)
    })
    return () => {
      cancel = true
    }
  }, [canRead, session.chatClient, session.roomId, refresh])
  return members
}

// ── Root ───────────────────────────────────────────────────────────────────
export function App() {
  const [session, setSession] = useState<Session | null>(null)
  if (!session) return <AuthScreen onLogin={setSession} />
  return <ChatApp session={session} setSession={setSession} />
}

// ── Auth screen ──────────────────────────────────────────────────────────────
function AuthScreen({ onLogin }: { onLogin: (s: Session) => void }) {
  const [tab, setTab] = useState<"owner" | "member" | "device">("owner")
  const [name, setName] = useState("")
  const [pass, setPass] = useState("")
  const [room, setRoom] = useState(DEFAULT_ROOM)
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const [pairMode, setPairMode] = useState<"provision" | "request" | "rendezvous">("provision")
  const [setupCode, setSetupCode] = useState("")
  const [setupPin, setSetupPin] = useState("")
  const [pairKeys, setPairKeys] = useState<DeviceKeys | null>(null)
  const [qr, setQr] = useState("")
  const [bundle, setBundle] = useState("")
  const [qrNonce, setQrNonce] = useState("")
  const [expectedRoot, setExpectedRoot] = useState("")
  const [notReady, setNotReady] = useState(false)

  const run = (fn: () => Promise<Session>) => async () => {
    setErr("")
    setBusy(true)
    try {
      onLogin(await fn())
    } catch (e) {
      setErr(friendlyRoomError(e, roomId))
    } finally {
      setBusy(false)
    }
  }
  const roomId = room.trim() || DEFAULT_ROOM

  // Rendezvous fetch: a SINGLE pull on the "Added from root" click (no polling).
  // A null result means the first device hasn't pushed the bundle yet → prompt
  // the user to finish there and click again.
  const fetchFromRendezvous = async () => {
    if (!pairKeys) return
    setErr("")
    setNotReady(false)
    setBusy(true)
    try {
      const s = await fetchAndBuildDeviceSession(
        name || "Device",
        pairKeys,
        qrNonce,
        roomId,
        expectedRoot.trim(), // required: the builder throws if empty (anti-MITM pin)
      )
      if (!s) {
        setNotReady(true)
        return
      }
      onLogin(s)
    } catch (e) {
      setErr(friendlyRoomError(e, roomId))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-stage">
      <div className="auth-card">
        <div className="auth-hero">
          <div className="ah-mark">🐟</div>
          <h1>Starfish</h1>
          <p>End-to-end encrypted chat — your identity is a passphrase, your messages never leave your device in the clear.</p>
        </div>
        <div className="auth-body">
          <div className="seg" role="group" aria-label="Sign-in mode">
            <button type="button" className={tab === "owner" ? "on" : ""} onClick={() => setTab("owner")}>
              Open a room
            </button>
            <button type="button" className={tab === "member" ? "on" : ""} onClick={() => setTab("member")}>
              Join
            </button>
            <button type="button" className={tab === "device" ? "on" : ""} onClick={() => setTab("device")}>
              Pair device
            </button>
          </div>

          {tab === "owner" && (
            <>
              <label className="field">
                <span className="lbl">Display name</span>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Alice" />
              </label>
              <label className="field">
                <span className="lbl">Passphrase</span>
                <input
                  className="input"
                  type="password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder="correct horse battery staple"
                />
              </label>
              <label className="field">
                <span className="lbl">Room</span>
                <input className="input" value={room} onChange={(e) => setRoom(e.target.value)} placeholder="general" />
              </label>
              <button
                className="btn btn-primary btn-block"
                disabled={busy || !pass}
                onClick={run(() => buildOwnerSession(pass, name || "Owner", roomId))}
              >
                Open room
              </button>
            </>
          )}

          {tab === "member" && (
            <>
              <label className="field">
                <span className="lbl">Display name</span>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Bob" />
              </label>
              <label className="field">
                <span className="lbl">Passphrase</span>
                <input
                  className="input"
                  type="password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder="another passphrase"
                />
              </label>
              <button
                className="btn btn-primary btn-block"
                disabled={busy || !pass}
                onClick={run(() => buildMemberSession(pass, name || "Member"))}
              >
                Continue
              </button>
              <p className="auth-foot">After signing in, paste the invite a room owner sends you to join their room.</p>
            </>
          )}

          {tab === "device" && (
            <>
              <div className="seg seg-sub" role="group" aria-label="Pairing method">
                <button
                  type="button"
                  className={pairMode === "provision" ? "on" : ""}
                  onClick={() => setPairMode("provision")}
                >
                  Setup code
                </button>
                <button
                  type="button"
                  className={pairMode === "request" ? "on" : ""}
                  onClick={() => setPairMode("request")}
                >
                  Request / response
                </button>
                <button
                  type="button"
                  className={pairMode === "rendezvous" ? "on" : ""}
                  onClick={() => setPairMode("rendezvous")}
                >
                  Phone scans
                </button>
              </div>
              <label className="field">
                <span className="lbl">Device name</span>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Laptop" />
              </label>

              {pairMode === "provision" ? (
                <>
                  <label className="field">
                    <span className="lbl">Paste the setup code from your first device</span>
                    <textarea
                      className="textarea"
                      rows={3}
                      value={setupCode}
                      onChange={(e) => setSetupCode(e.target.value)}
                      placeholder="paste setup code"
                      aria-label="Provisioning code"
                    />
                  </label>
                  <label className="field">
                    <span className="lbl">PIN (only if your first device protected the code)</span>
                    <input
                      className="input"
                      type="password"
                      value={setupPin}
                      onChange={(e) => setSetupPin(e.target.value)}
                      placeholder="leave blank if the code has no PIN"
                      aria-label="Setup PIN"
                    />
                  </label>
                  <button
                    className="btn btn-primary btn-block"
                    disabled={busy || !setupCode.trim()}
                    onClick={run(() =>
                      buildProvisionedDeviceSession(name || "Device", setupCode, setupPin || undefined),
                    )}
                  >
                    Install &amp; join
                  </button>
                  <p className="auth-foot">
                    Your first device generates the whole identity and hands you one code — this device just installs it.
                  </p>
                </>
              ) : pairMode === "request" ? (
                <>
                  <label className="field">
                    <span className="lbl">Room to join</span>
                    <input className="input" value={room} onChange={(e) => setRoom(e.target.value)} placeholder="general" />
                  </label>
                  {!pairKeys ? (
                    <button
                      className="btn btn-primary btn-block"
                      onClick={() => {
                        const p = startPairing()
                        setPairKeys(p.keys)
                        setQr(p.qr)
                      }}
                    >
                      Generate pairing request
                    </button>
                  ) : (
                    <>
                      <CopyField label="1 · Send this request to your first device" value={qr} rows={3} ariaLabel="Pairing request" />
                      <label className="field">
                        <span className="lbl">2 · Paste the bundle it returns</span>
                        <textarea
                          className="textarea"
                          rows={3}
                          value={bundle}
                          onChange={(e) => setBundle(e.target.value)}
                          placeholder="paste bundle JSON"
                          aria-label="Pairing bundle"
                        />
                      </label>
                      <button
                        className="btn btn-primary btn-block"
                        disabled={busy || !bundle.trim()}
                        onClick={run(() => buildDeviceSession(name || "Device", pairKeys, bundle, roomId))}
                      >
                        Install &amp; join #{roomId}
                      </button>
                    </>
                  )}
                  <p className="auth-foot">
                    No passphrase needed — this device makes its own keypair (private keys never leave it) and your first device authorises it.
                  </p>
                </>
              ) : (
                <>
                  <label className="field">
                    <span className="lbl">Room to join</span>
                    <input className="input" value={room} onChange={(e) => setRoom(e.target.value)} placeholder="general" />
                  </label>
                  {!pairKeys ? (
                    <button
                      className="btn btn-primary btn-block"
                      onClick={() => {
                        const p = startQrInPairing()
                        setPairKeys(p.keys)
                        setQr(p.qr)
                        setQrNonce(p.qrNonce)
                        setNotReady(false)
                      }}
                    >
                      Show pairing QR
                    </button>
                  ) : (
                    <>
                      <CopyField
                        label="1 · Show this QR to your first device (it scans / pastes it)"
                        value={qr}
                        rows={3}
                        ariaLabel="Pairing QR"
                      />
                      <label className="field">
                        <span className="lbl">First device's root key (required — paste it to verify it's yours)</span>
                        <input
                          className="input"
                          value={expectedRoot}
                          onChange={(e) => setExpectedRoot(e.target.value)}
                          placeholder="paste the root key shown on your first device"
                          aria-label="Expected root public key"
                        />
                      </label>
                      <button
                        className="btn btn-primary btn-block"
                        disabled={busy || !expectedRoot.trim()}
                        onClick={fetchFromRendezvous}
                      >
                        2 · Added from first device — finish &amp; join #{roomId}
                      </button>
                      {notReady && (
                        <p className="auth-foot">
                          Not there yet — scan the QR on your first device and tap “authorise”, then click the button again.
                        </p>
                      )}
                    </>
                  )}
                  <p className="auth-foot">
                    Camera-free: this device shows a QR, your first device scans it and sends the bundle back through the
                    server automatically — no copy-paste back, no polling. Private keys never leave this device.
                  </p>
                </>
              )}
            </>
          )}

          {err && <p className="err">{err}</p>}
        </div>
      </div>
    </div>
  )
}

// ── App shell ──────────────────────────────────────────────────────────────
interface RoomsApi {
  rooms: string[]
  active: string
  switchTo: (id: string) => Promise<void>
  addRoom: (id: string) => Promise<void>
  canManage: boolean
  roomError: string
}
function useRooms(session: Session, setSession: (s: Session) => void): RoomsApi {
  const canManage = session.role === "owner" || session.role === "device"
  const storeKey = `starfish-rooms-${session.userId}`
  const [rooms, setRooms] = useState<string[]>(() => {
    if (!canManage) return session.roomId ? [session.roomId] : []
    try {
      const saved = JSON.parse(localStorage.getItem(storeKey) || "[]")
      const list: string[] = Array.isArray(saved) ? saved.filter((x) => typeof x === "string") : []
      return list.includes(session.roomId) ? list : [session.roomId, ...list]
    } catch {
      return session.roomId ? [session.roomId] : []
    }
  })
  const [roomError, setRoomError] = useState("")

  useEffect(() => {
    if (canManage) localStorage.setItem(storeKey, JSON.stringify(rooms))
  }, [rooms, canManage, storeKey])

  useEffect(() => {
    if (!session.roomId) return
    setRooms((list) => (list.includes(session.roomId) ? list : canManage ? [...list, session.roomId] : [session.roomId]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.roomId])

  const switchTo = async (id: string) => {
    if (id === session.roomId) return
    setRoomError("")
    try {
      setSession(await switchRoom(session, id))
    } catch (e) {
      setRoomError(friendlyRoomError(e, id))
    }
  }
  const addRoom = async (id: string) => {
    setRoomError("")
    try {
      const next = await switchRoom(session, id)
      setRooms((list) => (list.includes(id) ? list : [...list, id]))
      setSession(next)
    } catch (e) {
      setRoomError(friendlyRoomError(e, id))
    }
  }
  return { rooms, active: session.roomId, switchTo, addRoom, canManage, roomError }
}

function ChatApp({ session, setSession }: { session: Session; setSession: (s: Session | null) => void }) {
  const [drawer, setDrawer] = useState<DrawerKey | null>(null)
  const [profileOpen, setProfileOpen] = useState(false)
  const [pseudo, setPseudo] = useState(session.name)
  const [memberRefresh, setMemberRefresh] = useState(0)
  const rooms = useRooms(session, setSession)

  useEffect(() => {
    let cancel = false
    readPseudo(session.userId).then((p) => {
      if (!cancel && p) setPseudo(p)
    })
    return () => {
      cancel = true
    }
  }, [session.userId])

  const inRoom = !!session.chatCap && !!session.roomId

  return (
    <div className="stage">
      <div className="app-shell">
        <Sidebar
          session={session}
          pseudo={pseudo}
          rooms={rooms}
          onOpenDrawer={setDrawer}
          onProfile={() => setProfileOpen(true)}
          onLogout={() => setSession(null)}
        />
        <main className="main">
          {inRoom ? (
            <RoomColumn
              session={session}
              onOpenDrawer={setDrawer}
              memberRefresh={memberRefresh}
              onLeave={() => {
                leaveRoomLocal(session.userId, session.roomId)
                setSession(null)
              }}
            />
          ) : (
            <ActivateScreen session={session} setSession={setSession} />
          )}
        </main>
        {drawer && (
          <DrawerHost
            drawer={drawer}
            session={session}
            setSession={setSession}
            memberRefresh={memberRefresh}
            bumpMembers={() => setMemberRefresh((n) => n + 1)}
            onClose={() => setDrawer(null)}
          />
        )}
      </div>
      {profileOpen && (
        <ProfileModal session={session} pseudo={pseudo} setPseudo={setPseudo} onClose={() => setProfileOpen(false)} />
      )}
    </div>
  )
}

// ── Sidebar ────────────────────────────────────────────────────────────────
function Sidebar({
  session,
  pseudo,
  rooms,
  onOpenDrawer,
  onProfile,
  onLogout,
}: {
  session: Session
  pseudo: string
  rooms: RoomsApi
  onOpenDrawer: (k: DrawerKey) => void
  onProfile: () => void
  onLogout: () => void
}) {
  const [adding, setAdding] = useState(false)
  const [newRoom, setNewRoom] = useState("")
  const submitAdd = async (e: FormEvent) => {
    e.preventDefault()
    const id = newRoom.trim()
    if (!id) return
    await rooms.addRoom(id)
    setNewRoom("")
    setAdding(false)
  }
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="mark">🐟</div>
        <div>
          <div className="title">Starfish</div>
          <div className="sub">tidepool chat</div>
        </div>
      </div>

      <div className="side-label">Rooms</div>
      <div className="rooms">
        {rooms.rooms.map((id, i) => (
          <button
            key={id}
            className={`room-item ${id === rooms.active ? "active" : ""}`}
            style={{ animationDelay: `${i * 40}ms` }}
            onClick={() => rooms.switchTo(id)}
          >
            <span className="hash">#</span>
            {id}
          </button>
        ))}
        {rooms.rooms.length === 0 && (
          <div className="note" style={{ padding: "8px 11px" }}>
            No room yet — activate an invite.
          </div>
        )}
        {rooms.canManage &&
          (adding ? (
            <form className="room-add-form" onSubmit={submitAdd}>
              <input
                className="input sm"
                autoFocus
                placeholder="new-room-id"
                value={newRoom}
                onChange={(e) => setNewRoom(e.target.value)}
                aria-label="New room id"
              />
              <button type="submit" className="btn btn-primary btn-sm">
                Add
              </button>
            </form>
          ) : (
            <button className="room-add" onClick={() => setAdding(true)}>
              <IconPlus size={15} /> New room
            </button>
          ))}
        {rooms.roomError && <div className="side-err">{rooms.roomError}</div>}
      </div>

      <div className="side-foot">
        <button className="profile-chip" onClick={onProfile} aria-label="Open profile">
          <Avatar seed={session.userId} label={pseudo} size="sm" />
          <div className="pc-body">
            <div className="pc-name">{pseudo}</div>
            <div className="pc-role">{session.role}</div>
          </div>
        </button>
        <div className="side-actions">
          {session.accountClient && (
            <button className="icon-btn" title="Premium" aria-label="Premium" onClick={() => onOpenDrawer("premium")}>
              <IconGem />
            </button>
          )}
          <button className="icon-btn" title="Activity" aria-label="Activity" onClick={() => onOpenDrawer("activity")}>
            <IconActivity />
          </button>
          <button className="icon-btn" title="Log out" aria-label="Log out" style={{ marginLeft: "auto" }} onClick={onLogout}>
            <IconLogout />
          </button>
        </div>
      </div>
    </aside>
  )
}

// ── Room column (zustand-backed, persisted, per-room) ────────────────────────
function RoomColumn({
  session,
  onOpenDrawer,
  memberRefresh,
  onLeave,
}: {
  session: Session
  onOpenDrawer: (k: DrawerKey) => void
  memberRefresh: number
  onLeave: () => void
}) {
  const config: SyncInitConfig | null = useMemo(() => {
    if (!session.chatCap || !session.encryptor || !session.roomId) return null
    return {
      serverUrl: SYNC_BASE,
      capProvider: capProviderFor(session.chatCap, session.keys.edPriv),
      pullPath: roomPull(session.roomId),
      pushPath: roomPush(session.roomId),
      encryptor: session.encryptor,
      onConflict: createUnionMerge(), // union chat messages by `id`
      storeName: `chat-${session.userId}-${session.roomId}`, // per-identity, per-room key
      storage: window.localStorage, // browser-side persistence (offline-first)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.chatCap, session.encryptor, session.userId, session.roomId])

  const store = useSyncInit(config)
  if (!store) {
    return (
      <div className="empty" style={{ margin: "auto" }}>
        <div className="glyph">🌊</div>
        <div className="big">Setting up the encrypted room…</div>
      </div>
    )
  }
  return (
    <RoomChat
      key={session.roomId}
      store={store}
      session={session}
      onOpenDrawer={onOpenDrawer}
      memberRefresh={memberRefresh}
      onLeave={onLeave}
    />
  )
}

function StatusPill({ status }: { status: string }) {
  const ok = status === "synced"
  return (
    <span className={`pill-status ${ok ? "ok" : "warn"}`}>
      <span className="dot" />
      {status}
    </span>
  )
}

function RoomChat({
  store,
  session,
  onOpenDrawer,
  memberRefresh,
  onLeave,
}: {
  store: NonNullable<ReturnType<typeof useSyncInit>>
  session: Session
  onOpenDrawer: (k: DrawerKey) => void
  memberRefresh: number
  onLeave: () => void
}) {
  // Select the raw value (stable reference) — defaulting to `[]` inside the
  // selector would return a new array each render and loop forever.
  const rawMessages = useStarfishData(store, (d) => d.messages as ChatMessage[] | undefined)
  const messages = rawMessages ?? []
  const status = useSyncStatus(store)
  const error = useStarfish(store).error
  useConnectivity(store)
  const [text, setText] = useState("")
  const [confirmLeave, setConfirmLeave] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  const authorIds = useMemo(() => [...new Set(messages.map((m) => m.from))], [messages])
  const pseudos = usePseudos(authorIds)
  const members = useMembers(session, memberRefresh)
  const isOwner = session.role === "owner"

  // queuing → SSE → pull (only for THIS room's events)
  useEffect(() => {
    const es = new EventSource(`${API_BASE}/events`)
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data)
        if (data?.params?.roomId && data.params.roomId !== session.roomId) return
      } catch {
        /* keep-alive comment or unparsable — fall through and pull */
      }
      store.getState().pull().catch(() => {})
    }
    return () => es.close()
  }, [store, session.roomId])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" })
  }, [messages.length])

  const onSend = (e: FormEvent) => {
    e.preventDefault()
    const t = text.trim()
    if (!t || !session.canWrite) return
    setText("")
    store.getState().set((d) => {
      const msgs = (d.messages as ChatMessage[] | undefined) ?? []
      return {
        ...d,
        messages: [
          ...msgs,
          { id: crypto.randomUUID(), from: session.userId, name: session.name, text: t, ts: Date.now() },
        ],
      }
    })
  }

  const meta =
    members.length > 0 ? `end-to-end encrypted · ${members.length + 1} member${members.length ? "s" : ""}` : "end-to-end encrypted"

  return (
    <>
      <header className="room-head">
        <div>
          <div className="rh-title">
            <span className="hash">#</span>
            {session.roomId}
          </div>
          <div className="rh-meta">{meta}</div>
        </div>
        <div className="spacer" />
        <StatusPill status={status} />
        {isOwner && (
          <div className="head-actions">
            <button className="chip" onClick={() => onOpenDrawer("invite")}>
              <IconInvite size={16} /> Invite
            </button>
            <button className="chip" onClick={() => onOpenDrawer("devices")}>
              <IconDevice size={16} /> Devices
            </button>
          </div>
        )}
        {session.role === "member" && (
          <div className="head-actions">
            {confirmLeave ? (
              <>
                <span className="note leave-q">Leave this room?</span>
                <button className="chip danger" onClick={onLeave}>
                  Confirm leave
                </button>
                <button className="chip" onClick={() => setConfirmLeave(false)}>
                  Cancel
                </button>
              </>
            ) : (
              <button className="chip" onClick={() => setConfirmLeave(true)}>
                Leave room
              </button>
            )}
          </div>
        )}
      </header>

      <div className="messages">
        {messages.length === 0 ? (
          <div className="empty">
            <div className="glyph">🐚</div>
            <div className="big">No messages yet</div>
            <div className="note">{session.canWrite ? "Say hello 👋" : "Waiting for the room to fill up."}</div>
          </div>
        ) : (
          [...messages]
            .sort((a, b) => a.ts - b.ts)
            .map((m) => {
              const me = m.from === session.userId
              const who = pseudos[m.from] ?? m.name
              return (
                <div key={m.id} className={`msg ${me ? "me" : ""}`}>
                  {!me && <Avatar seed={m.from} label={who} size="sm" />}
                  <div className="stack">
                    <div className="meta">
                      {!me && <span className="who">{who}</span>}
                      <span className="when">
                        {new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                    <div className="bubble">{m.text}</div>
                  </div>
                </div>
              )
            })
        )}
        <div ref={endRef} />
      </div>

      {!session.canWrite && (
        <div className="lock-note">
          <IconLock size={15} /> You were invited read-only — sending is disabled.
        </div>
      )}
      <form className="composer" onSubmit={onSend}>
        <div className={`pill ${session.canWrite ? "" : "locked"}`}>
          {!session.canWrite && <IconLock size={15} style={{ color: "var(--muted)" }} />}
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={session.canWrite ? "Type a message…" : "Read-only — you can't post here"}
            disabled={!session.canWrite}
            aria-label="Message"
          />
        </div>
        <button type="submit" className="send" disabled={!session.canWrite || !text.trim()} aria-label="Send">
          <IconSend size={18} />
        </button>
      </form>
      {error && <p className="err" style={{ margin: "0 22px 14px" }}>{error}</p>}
    </>
  )
}

// ── Member: activate an invite (no room yet) ─────────────────────────────────
function ActivateScreen({ session, setSession }: { session: Session; setSession: (s: Session) => void }) {
  const [cap, setCap] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const inviteCode = JSON.stringify({ edPub: session.keys.edPub, kemPub: session.keys.kemPub, userId: session.userId })
  const activate = async () => {
    setErr("")
    setBusy(true)
    try {
      setSession(await activateMember(session, cap))
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div style={{ margin: "auto", width: "100%", maxWidth: 460, padding: 24 }}>
      <div className="empty" style={{ marginBottom: 4 }}>
        <div className="glyph">🤝</div>
        <div className="big">Join a room</div>
        <div className="note">Paste the member invite a room owner sent you. The room comes from the invite itself.</div>
      </div>
      <label className="field">
        <span className="lbl">Member invite</span>
        <textarea
          className="textarea"
          rows={4}
          value={cap}
          onChange={(e) => setCap(e.target.value)}
          placeholder="paste member cap JSON"
          aria-label="Member cap"
        />
      </label>
      <button className="btn btn-primary btn-block" onClick={activate} disabled={busy || !cap.trim()}>
        Activate invite
      </button>
      {err && <p className="err">{err}</p>}
      <CopyField label="Your invite code — send this to the room owner" value={inviteCode} rows={3} ariaLabel="Your invite code" />
    </div>
  )
}

// ── Drawer ────────────────────────────────────────────────────────────────
function DrawerHost({
  drawer,
  session,
  setSession,
  memberRefresh,
  bumpMembers,
  onClose,
}: {
  drawer: DrawerKey
  session: Session
  setSession: (s: Session) => void
  memberRefresh: number
  bumpMembers: () => void
  onClose: () => void
}) {
  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={DRAWER_TITLE[drawer]}>
        <div className="drawer-head">
          <h3>{DRAWER_TITLE[drawer]}</h3>
          <button className="icon-btn" aria-label="Close" onClick={onClose}>
            <IconClose size={16} />
          </button>
        </div>
        <div className="drawer-body">
          {drawer === "invite" && (
            <InvitePanel session={session} setSession={setSession} memberRefresh={memberRefresh} bumpMembers={bumpMembers} />
          )}
          {drawer === "devices" && <DevicesPanel session={session} setSession={setSession} />}
          {drawer === "premium" && <PremiumPanel session={session} />}
          {drawer === "activity" && <ActivityPanel />}
        </div>
      </aside>
    </>
  )
}

// ── Invite + member management ────────────────────────────────────────────────
function InvitePanel({
  session,
  setSession,
  memberRefresh,
  bumpMembers,
}: {
  session: Session
  setSession: (s: Session) => void
  memberRefresh: number
  bumpMembers: () => void
}) {
  const [info, setInfo] = useState("")
  const [perm, setPerm] = useState<"read" | "write">("read")
  const [out, setOut] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)
  const members = useMembers(session, memberRefresh)
  const memberIds = useMemo(() => members.map((m) => m.userId), [members])
  const pseudos = usePseudos(memberIds)

  const doRevoke = async (m: MemberRow) => {
    if (!session.chatClient) return
    setErr("")
    setRevoking(m.nonce || m.userId)
    try {
      // Revokes the cap (401), rotates the keyring epoch, removes the directory
      // entry, and returns a fresh encryptor for the new epoch.
      const enc = await revokeMember(session.chatClient, session.keys, session.userId, session.roomId, m)
      setSession({ ...session, encryptor: enc ?? session.encryptor })
      bumpMembers()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setRevoking(null)
    }
  }

  const doInvite = async () => {
    setErr("")
    setBusy(true)
    try {
      const parsed = JSON.parse(info) as InviteInfo
      setOut(await invite(session, parsed, perm === "write"))
      bumpMembers()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <h4>Invite to #{session.roomId}</h4>
      <label className="field">
        <span className="lbl">Their invite code</span>
        <textarea
          className="textarea"
          rows={3}
          value={info}
          onChange={(e) => setInfo(e.target.value)}
          placeholder="paste invite info JSON"
          aria-label="Invite info"
        />
      </label>
      <div className="seg block" role="group" aria-label="Permission">
        <button type="button" className={perm === "read" ? "on" : ""} onClick={() => setPerm("read")}>
          Read-only
        </button>
        <button type="button" className={perm === "write" ? "on" : ""} onClick={() => setPerm("write")}>
          Read &amp; write
        </button>
      </div>
      <button className="btn btn-primary btn-block" style={{ marginTop: 12 }} onClick={doInvite} disabled={busy || !info.trim()}>
        Mint member cap
      </button>
      {err && <p className="err">{err}</p>}
      {out && <CopyField label="Member cap — send this back to them" value={out} rows={4} ariaLabel="Member cap output" />}

      <h4>Members</h4>
      {members.length === 0 ? (
        <p className="note">No members invited yet.</p>
      ) : (
        <div>
          {members.map((m) => (
            <div className="member-row" key={m.userId}>
              <Avatar seed={m.userId} label={pseudos[m.userId] ?? m.label} size="sm" />
              <span className="m-name">{pseudos[m.userId] ?? m.label}</span>
              <span className={`tag ${m.canWrite ? "rw" : "ro"}`}>{m.canWrite ? "read/write" : "read-only"}</span>
              <button
                className="revoke-btn"
                aria-label={`Revoke ${pseudos[m.userId] ?? m.label}`}
                disabled={!m.nonce || revoking !== null}
                onClick={() => doRevoke(m)}
              >
                {revoking === (m.nonce || m.userId) ? "Revoking…" : "Revoke"}
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

// ── Devices (pairing authorisation + linked-device management) ──────────────────
function DevicesPanel({ session, setSession }: { session: Session; setSession: (s: Session) => void }) {
  const [req, setReq] = useState("")
  const [out, setOut] = useState("")
  const [rzReq, setRzReq] = useState("")
  const [rzDone, setRzDone] = useState(false)
  const [prov, setProv] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const [devices, setDevices] = useState<DeviceEntry[]>([])
  const [revoking, setRevoking] = useState<string | null>(null)
  const [provPreset, setProvPreset] = useState<DeviceCapPreset>("owner")
  const [provTtlDays, setProvTtlDays] = useState(30)
  const [provPin, setProvPin] = useState("")

  const refreshDevices = useCallback(async () => {
    if (!session.accountClient) return
    setDevices(await listOwnDevices(session.accountClient, session.userId))
  }, [session.accountClient, session.userId])

  // Record THIS device in the directory (idempotent upsert by nonce), then list.
  useEffect(() => {
    let cancel = false
    void (async () => {
      if (session.accountClient && session.chatCap) {
        await recordDevice(
          session.accountClient,
          session.userId,
          session.chatCap as Parameters<typeof recordDevice>[2],
          "this device",
        )
      }
      if (!cancel) await refreshDevices()
    })()
    return () => {
      cancel = true
    }
  }, [refreshDevices, session.accountClient, session.chatCap, session.userId])

  const doProvision = async () => {
    setErr("")
    setBusy(true)
    try {
      // Provision records the device itself; just refresh the list afterwards.
      setProv(await provisionRoomDevice(session, provPreset, provTtlDays * 24 * 3600, provPin || undefined))
      await refreshDevices()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  const doPair = async () => {
    setErr("")
    setBusy(true)
    try {
      const bundleStr = await authorizeDevice(session, req)
      setOut(bundleStr)
      // Record the newly-paired device so it appears in the list (best-effort).
      try {
        const bundle = JSON.parse(bundleStr) as { capCert?: Parameters<typeof recordDevice>[2] }
        if (session.accountClient && bundle.capCert) {
          await recordDevice(session.accountClient, session.userId, bundle.capCert, "paired device")
        }
      } catch {
        /* bundle parse / record is best-effort metadata */
      }
      await refreshDevices()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  const doPairRendezvous = async () => {
    setErr("")
    setRzDone(false)
    setBusy(true)
    try {
      // Assembles the bundle, adds the device to the keyring, and PUSHES the
      // bundle to the rendezvous slot — the new device fetches it itself, so
      // there's nothing to copy back here.
      await authorizeDeviceViaRendezvous(session, rzReq)
      setRzReq("")
      setRzDone(true)
      await refreshDevices()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setBusy(false)
    }
  }

  const doRevokeDevice = async (d: DeviceEntry) => {
    if (!session.chatClient || !session.accountClient) return
    setErr("")
    setRevoking(d.nonce)
    try {
      const enc = await revokeDevice(
        session.chatClient,
        session.accountClient,
        session.keys,
        session.userId,
        session.roomId,
        d,
      )
      setSession({ ...session, encryptor: enc ?? session.encryptor })
      await refreshDevices()
    } catch (e) {
      setErr(String((e as Error)?.message ?? e))
    } finally {
      setRevoking(null)
    }
  }

  return (
    <>
      {/* Only the account owner holds the root key, so only the owner can mint device caps
          that resolve to the *same* userId. A device cap would sign with its own key and
          spin up a divergent identity — so the add-device controls are owner-only. */}
      {session.role === "owner" ? (
        <>
          <h4>Provision a new device</h4>
          <p className="note">
            Generate a complete setup code here — the new device installs it in one step, with nothing to send back. Pick
            the access it gets and when its cap expires. The code carries the new device's private keys, so only share it
            over a channel you'd trust with the room key itself — or set a PIN below to seal it, so the code alone is
            useless without the PIN.
          </p>
          <label className="field">
            <span className="lbl">Device access (cap scope)</span>
            <div className="seg seg-sub block" role="group" aria-label="Device cap scope">
              <button
                type="button"
                className={provPreset === "owner" ? "on" : ""}
                onClick={() => setProvPreset("owner")}
              >
                Full account
              </button>
              <button
                type="button"
                className={provPreset === "room-write" ? "on" : ""}
                onClick={() => setProvPreset("room-write")}
              >
                #{session.roomId} · read & write
              </button>
              <button
                type="button"
                className={provPreset === "room-read" ? "on" : ""}
                onClick={() => setProvPreset("room-read")}
              >
                #{session.roomId} · read only
              </button>
            </div>
          </label>
          <label className="field">
            <span className="lbl">Cap expires in</span>
            <select
              className="input"
              value={provTtlDays}
              onChange={(e) => setProvTtlDays(Number(e.target.value))}
              aria-label="Device cap expiry"
            >
              <option value={1}>1 day</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
          </label>
          <label className="field">
            <span className="lbl">Protect with a PIN / passphrase (optional)</span>
            <input
              className="input"
              type="password"
              value={provPin}
              onChange={(e) => setProvPin(e.target.value)}
              placeholder="leave blank for an unprotected code"
              aria-label="Provisioning PIN"
            />
            {provPin && (
              <span className={`pin-strength ${pinStrength(provPin)}`}>
                Strength: {pinStrength(provPin)}
                {pinStrength(provPin) === "weak" && " — a short numeric PIN can be brute-forced; prefer a passphrase"}
              </span>
            )}
          </label>
          <button className="btn btn-primary btn-block" onClick={doProvision} disabled={busy}>
            Provision a new device
          </button>
          {prov && (
            <>
              <CopyField label="Setup code — paste into the new device" value={prov} rows={4} ariaLabel="Provisioning code output" />
              {provPin && (
                <p className="note">
                  This code is sealed with your PIN. Send the PIN over a <strong>different channel</strong> than the code
                  (e.g. say it aloud) — together they grant a full device, so neither alone should be enough.
                </p>
              )}
            </>
          )}

          <h4>Authorise a device</h4>
          <p className="note">
            Or, for the no-key-exposure path: your other device generates a pairing request on its sign-in screen. Paste
            it here — it joins as the same account and is added to #{session.roomId}'s keyring.
          </p>
          <label className="field">
            <span className="lbl">Pairing request</span>
            <textarea
              className="textarea"
              rows={3}
              value={req}
              onChange={(e) => setReq(e.target.value)}
              placeholder="paste pairing request"
              aria-label="Pairing request input"
            />
          </label>
          <button className="btn btn-primary btn-block" onClick={doPair} disabled={busy || !req.trim()}>
            Authorise device
          </button>
          {out && <CopyField label="Bundle — send this back to the new device" value={out} rows={4} ariaLabel="Pairing bundle output" />}

          <h4>Authorise via QR (camera-free)</h4>
          <p className="note">
            For a device that can't scan (e.g. a laptop): it shows a QR on its “Phone scans” sign-in tab. Scan / paste it
            here — this device sends the bundle back through the server automatically, so there's <strong>nothing to copy
            back</strong>. The new device just clicks “Added from first device” to finish.
          </p>
          <CopyField
            label="Your root key — the new device needs this: paste it into its “Phone scans” tab to pin this account"
            value={session.keys.edPub}
            rows={2}
            ariaLabel="Root public key"
          />
          <label className="field">
            <span className="lbl">New device's pairing QR</span>
            <textarea
              className="textarea"
              rows={3}
              value={rzReq}
              onChange={(e) => {
                setRzReq(e.target.value)
                setRzDone(false)
              }}
              placeholder="paste the QR from the new device"
              aria-label="Pairing QR input"
            />
          </label>
          <button className="btn btn-primary btn-block" onClick={doPairRendezvous} disabled={busy || !rzReq.trim()}>
            Authorise &amp; send to device
          </button>
          {rzDone && (
            <p className="note">
              ✓ Sent. On the new device, click “Added from first device” to finish joining #{session.roomId}.
            </p>
          )}
        </>
      ) : (
        <p className="note">
          Only the account owner (the passphrase holder) can add devices — a device's cap can't mint identities for
          others, so adding from here would create a separate account.
        </p>
      )}
      {err && <p className="err">{err}</p>}

      <h4>Linked devices</h4>
      {devices.length === 0 ? (
        <p className="note">No devices recorded yet.</p>
      ) : (
        <div>
          {devices.map((d) => {
            const isCurrent = d.sub === session.keys.edPub
            const name = d.label ?? d.sub.slice(0, 8)
            return (
              <div className="member-row" key={d.nonce}>
                <Avatar seed={d.sub} label={name} size="sm" />
                <span className="m-name">{name}</span>
                {isCurrent ? (
                  <span className="tag rw">this device</span>
                ) : (
                  <button
                    className="revoke-btn"
                    aria-label={`Revoke ${name}`}
                    disabled={revoking !== null}
                    onClick={() => doRevokeDevice(d)}
                  >
                    {revoking === d.nonce ? "Revoking…" : "Revoke"}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </>
  )
}

// ── Premium (client-side entitlement unlock) ──────────────────────────────────
function PremiumPanel({ session }: { session: Session }) {
  const [features, setFeatures] = useState<string[]>([])
  const refresh = useCallback(async () => {
    if (!session.accountClient) return
    setFeatures(await pullEntitlements(session.accountClient, session.userId))
  }, [session.accountClient, session.userId])
  useEffect(() => {
    void refresh()
  }, [refresh])
  const premium = features.includes("premium")
  return (
    <>
      <p className="note">
        <code>pullEntitlements</code> reads your slugs from <code>users/&lt;id&gt;/entitlements</code> and unlocks paid
        features client-side.
      </p>
      <div className={`premium-card ${premium ? "on" : ""}`}>
        {premium ? (
          <>
            <div className="pc-title">
              <IconGem size={18} /> Premium unlocked!
            </div>
            <div className="perk">
              <IconCheck size={15} className="ck" /> Unlimited history
            </div>
            <div className="perk">
              <IconCheck size={15} className="ck" /> Priority sync
            </div>
            <div className="perk">
              <IconCheck size={15} className="ck" /> Custom themes
            </div>
            <button
              className="btn btn-ghost btn-sm"
              style={{ marginTop: 12 }}
              onClick={async () => {
                await demoRevoke(session.userId)
                await refresh()
              }}
            >
              Revoke premium
            </button>
          </>
        ) : (
          <>
            <div className="pc-title">
              <IconLock size={17} /> Premium is locked
            </div>
            <p className="note">Unlock priority sync, unlimited history, and custom themes.</p>
            <button
              className="btn btn-coral btn-block"
              style={{ marginTop: 10 }}
              onClick={async () => {
                await demoGrant(session.userId)
                await refresh()
              }}
            >
              Unlock premium (demo grant)
            </button>
          </>
        )}
      </div>
      <div className="slug-list">
        {features.length === 0 ? (
          <span className="note">no slugs yet</span>
        ) : (
          features.map((f) => (
            <span key={f} className="slug">
              {f}
            </span>
          ))
        )}
      </div>
    </>
  )
}

// ── Activity (audit feed) ─────────────────────────────────────────────────────
function ActivityPanel() {
  const [rows, setRows] = useState<AuditRow[]>([])
  useEffect(() => {
    const tick = () => void fetchAudit().then(setRows)
    tick()
    const t = setInterval(tick, 3000)
    return () => clearInterval(t)
  }, [])
  const recent = [...rows].slice(-25).reverse()
  return (
    <>
      <p className="note">
        Every sync push is recorded server-side by the <code>audit</code> logger.
      </p>
      <div className="feed">
        {recent.length === 0 ? (
          <p className="note">No activity yet.</p>
        ) : (
          recent.map((r, i) => (
            <div className="feed-row" key={i}>
              <span className={`fr-dot ${r.success ? "ok" : "fail"}`} />
              <span className="fr-action">{r.action}</span>
              <span className="fr-col">{r.collection}</span>
              <span className="fr-id">{r.identity ? r.identity.slice(0, 8) : "—"}</span>
              <span className={`fr-code ${r.success ? "ok" : "fail"}`}>{r.statusCode}</span>
            </div>
          ))
        )}
      </div>
    </>
  )
}

// ── Profile modal (public read, owner/device-restricted write) ────────────────
function ProfileModal({
  session,
  pseudo,
  setPseudo,
  onClose,
}: {
  session: Session
  pseudo: string
  setPseudo: (p: string) => void
  onClose: () => void
}) {
  const [draft, setDraft] = useState(pseudo)
  const [status, setStatus] = useState("")
  const [busy, setBusy] = useState(false)
  const canEdit = !!session.accountClient
  const inviteCode =
    session.role === "device"
      ? ""
      : JSON.stringify({ edPub: session.keys.edPub, kemPub: session.keys.kemPub, userId: session.userId })

  const save = async () => {
    if (!session.accountClient) return
    setBusy(true)
    setStatus("")
    try {
      await writePseudo(session.accountClient, session.userId, draft.trim())
      setPseudo(draft.trim())
      setStatus("Saved ✓")
    } catch (e) {
      setStatus(`Error: ${(e as Error)?.message ?? e}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" role="dialog" aria-label="Profile" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>Profile</h3>
          <button className="icon-btn" aria-label="Close" onClick={onClose}>
            <IconClose size={16} />
          </button>
        </div>
        <div className="modal-body">
          <div className="profile-hero">
            <Avatar seed={session.userId} label={draft || pseudo} size="lg" />
            <div className="ph-meta">
              <div className="ph-name">{draft || pseudo}</div>
              <div className="ph-role">{session.role}</div>
            </div>
          </div>
          {canEdit ? (
            <>
              <label className="field">
                <span className="lbl">Display pseudo</span>
                <input
                  className="input"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="pseudo"
                  aria-label="Pseudo"
                />
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <button className="btn btn-primary" onClick={save} disabled={busy || !draft.trim()}>
                  Save pseudo
                </button>
                {status && <span className="saved-flash">{status}</span>}
              </div>
              <p className="note" style={{ marginTop: 10 }}>
                Stored at <code>user/&lt;id&gt;/profile</code> — public read, writable only by you.
              </p>
            </>
          ) : (
            <p className="note">Paired devices share the root account's profile; edit it from the first device.</p>
          )}
          <div className="kv" style={{ marginTop: 14 }}>
            <span className="k">User ID</span>
            <span className="v mono">{session.userId}</span>
          </div>
          {inviteCode && <CopyField label="Your invite code" value={inviteCode} rows={3} ariaLabel="Your invite code" />}
        </div>
      </div>
    </div>
  )
}
