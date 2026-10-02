# NovaTalk v2.0 Backend

NovaTalk v2.0 is an anonymous, real-time communication backend: stranger matchmaking (text and video), end-to-end encrypted direct and group messaging, WebRTC-signaled voice/video calls, peer-to-peer file transfer negotiation, temporary rooms, blocking, reporting, client-driven NSFW moderation, and an abuse/ban system — all anonymous, with no email, phone, password, or account registration.

The server is a **signaling, identity, metadata, matchmaking, moderation-event, quota and policy server**. It is not a media server: it never stores images, video, audio, voice messages, documents, call recordings, or thumbnails, and it never sees plaintext message content.

```
                 NOVATALK WEB
                      │
                      │ REST + Socket.IO
                      ▼
              ┌─────────────────┐
              │ NovaTalk Server │   Express · Socket.IO · MongoDB (metadata only)
              └────────┬────────┘
                       │
              ┌────────┴────────┐
        NOVATALK WEB       NOVATALK MOBILE
              │                 │
              └───────┬─────────┘
                    WebRTC
          ┌───────────┴───────────┐
       Audio/Video             Files
       P2P stream          P2P DataChannel
```

This repository contains **only the backend**. NovaTalk Web and NovaTalk Mobile are separate client applications that consume this server's REST API and Socket.IO events. No HTML, CSS, or client framework code is included here.

## Project layout

```
novatalk-server/
├── server.js        All backend logic: Express app, Socket.IO, and every Mongoose model
├── package.json
├── .env.example
└── README.md
```

Everything — every REST route, every Socket.IO event, and every Mongoose schema/model — is defined inside the single `server.js` file, organized into clearly delimited sections (config & utilities, models, runtime state, identity & conversations, rooms/blocking/reporting/moderation, matchmaking/calls/transfers, REST routes, Socket.IO wiring & lifecycle).

## Requirements

- Node.js 18 or later
- MongoDB 5.0 or later (a single standalone instance is sufficient; replica set not required, though recommended in production for resilience)

## Installation

```bash
npm install
cp .env.example .env
```

Edit `.env` and set at minimum:

- `MONGODB_URI` — your MongoDB connection string
- `SESSION_SECRET`, `IP_HASH_SECRET` — random strings, at least 16 characters (32+ recommended); in production the process refuses to start without these
- `ADMIN_SECRET` — random string of at least 16 characters, required to use the `/api/v1/admin/*` routes
- `ALLOWED_ORIGINS` — comma-separated list of origins your Web and Mobile clients connect from

## Running locally

```bash
npm start
```

The server listens on `PORT` (default `3000`). `NODE_ENV=development` relaxes the CORS check to also allow `localhost`/`127.0.0.1` origins and enables verbose error logging with stack traces.

## Production deployment

- Set `NODE_ENV=production`. In production, the process will refuse to start if `SESSION_SECRET` or `IP_HASH_SECRET` are missing or too short, and CORS will only allow origins listed in `ALLOWED_ORIGINS`.
- Run behind a reverse proxy (nginx, an ALB, etc.) that terminates TLS. If the proxy sets `X-Forwarded-For`, set `TRUST_PROXY` to the number of hops so the correct client IP is used for rate limiting and IP-based bans.
- MongoDB should be reachable and ideally backed by a replica set for automatic failover. TTL indexes handle expiry of sessions, identities, ephemeral conversations, messages, reactions, rooms, room memberships, matches, reports, moderation events, and old bans — no external cron job is required.
- Deploy multiple instances behind a load balancer for horizontal scaling. **Note:** matchmaking queues, active calls, active transfers, and peer requests are held in each process's memory (see "In-memory vs. persisted state" below), so Socket.IO sticky sessions (session affinity) are required if you run more than one instance, or these features must be adapted to a shared store before scaling horizontally.
- Storage footprint is intentionally small: MongoDB holds only metadata, public keys, and encrypted ciphertext, never media. Plan capacity accordingly (the server was designed around environments with only a few GB of storage).

## Environment variables

All variables are listed with defaults in `.env.example`. Key ones:

| Variable | Purpose |
|---|---|
| `PORT` | HTTP/Socket.IO port (default 3000) |
| `MONGODB_URI` | MongoDB connection string |
| `SESSION_EXPIRY` | Session lifetime in seconds |
| `FILE_TRANSFER_LIMIT` | Per-person, per-conversation P2P transfer quota in bytes (default 50 MB) |
| `STUN_SERVER` / `TURN_SERVER` / `TURN_USERNAME` / `TURN_PASSWORD` | ICE server configuration returned to clients |
| `NSFW_BLOCK_THRESHOLD` / `NSFW_REVIEW_THRESHOLD` | Confidence thresholds for client-reported NSFW classifications |
| `NSFW_WARNING_LIMIT` / `NSFW_TEMP_BAN_LIMIT` / `NSFW_PERMANENT_BAN_LIMIT` | Violation-count thresholds for escalating enforcement |
| `TEMP_BAN_DURATION` / `LONG_BAN_DURATION` | Ban durations in seconds |
| `ALLOWED_ORIGINS` | Comma-separated CORS allow-list |
| `SESSION_SECRET` / `IP_HASH_SECRET` | HMAC secrets — never commit real values |
| `ADMIN_SECRET` | Required header value for admin routes |

## Anonymous sessions

There is no email, phone, password, or social login anywhere in this system.

```
POST /api/v1/session
{ "displayName": "Silent Fox", "publicKey": "...", "devicePublicKey": "..." }
→ { "sessionToken": "...", "anonymousId": "...", "displayName": "Silent Fox", "expiresAt": "..." }
```

- If `displayName` is omitted, one is generated in the "Adjective Animal" style (`Silent Fox`, `Blue Raven`, `Midnight Wolf`, ...).
- `sessionToken` is 256 bits of `crypto.randomBytes`, returned once. The server stores only an HMAC-SHA256 hash of it (`tokenHash`), never the raw token — a database compromise cannot be used to forge sessions.
- Send it on every REST call as `Authorization: Bearer <sessionToken>`, and on Socket.IO connection as `auth: { token: "<sessionToken>" }`.
- `POST /api/v1/session/refresh` extends expiry; `DELETE /api/v1/session` logs out and disconnects any live sockets for that session immediately.
- `publicKey` is the user's E2EE public key (see below); `devicePublicKey` is used only to derive a device identity hash (see "Device identity") — **the corresponding private keys must never be sent to or stored by the server.**

## Device identity

The client (not the server) generates a device keypair. Only the device's **public** key is ever sent to the server, and only to derive a keyed HMAC hash (`deviceHash`) used for rate limiting and ban enforcement. The server:

- Never asks for or attempts to obtain a MAC address.
- Never stores a raw device public key permanently tied across many identities beyond what's needed for abuse correlation (`DeviceIdentity.anonymousIds` keeps only the last 10).
- Uses device identity as one signal among several (anonymous identity, session, IP hash, abuse history) — never as a sole basis for a ban.

## IP handling

Client IP addresses are used only for rate limiting, abuse prevention, and ban enforcement. They are:

- Never returned to any client in any API response or Socket.IO payload.
- Never stored in raw form. Wherever persistence is needed (`Ban.ipHash`, `UserSession.ipHash`), the server stores `HMAC-SHA256(IP, IP_HASH_SECRET)` truncated to 40 hex characters — never the address itself.
- Never used as the sole basis for a ban (see "Ban system" below) — a single IP can represent a household, school, office, public Wi-Fi hotspot, or carrier-grade NAT shared by many unrelated people.
- IPv6 addresses are normalized to their /64 prefix before hashing, since individual clients on the same network commonly rotate the low bits of a /64 without meaningfully changing "who" is connecting.

## E2EE architecture

The server never possesses users' private encryption keys and never decrypts anything. Clients are responsible for:

- Generating an ECDH keypair (P-256/P-384/P-521) per device or per identity.
- Performing key exchange (e.g., ECDH to derive a shared secret, then HKDF/SHA-256 to derive an AES-GCM key).
- Encrypting every message, reaction, and any other private payload with AES-GCM before sending it to the server, and decrypting on receipt.
- Generating cryptographically secure random nonces per encryption operation.

The server only ever stores and forwards:

- Public keys (`AnonymousIdentity.keys`, versioned)
- Ciphertext, nonce, and key version (`Message.ciphertext` / `.nonce` / `.keyVersion`)
- Encrypted reaction payloads (`MessageReaction`)
- Routing metadata (conversation id, sender id, recipient id, timestamps)

`ciphertext` is treated as opaque base64 data end-to-end: the server validates only its encoding and length, never its content, and it is never logged.

**Do not invent custom cryptography.** Only established primitives (ECDH, AES-GCM, SHA-256, and your platform's CSPRNG) should be used on the client.

## Public key management

```
POST /api/v1/identity/keys                          Rotate to a new public key (requires auth)
GET  /api/v1/identity/:anonymousId/keys              Fetch someone's current public key
GET  /api/v1/identity/:anonymousId/keys?history=true Also include previous key versions
```

- Each identity has a monotonically increasing `keyVersion`. Rotating keys does not invalidate old messages: `Message.keyVersion` (and `recipientKeyVersion`) records which key version encrypted each message, so clients can look up the right historical public key to derive the correct decryption key.
- Up to the last 20 key versions are retained per identity so recently-exchanged messages remain decryptable after a rotation.
- Rotating a key emits a `identity:key_rotated` Socket.IO event to the identity's own connected sockets (useful for multi-device sync).

## Matchmaking

```
POST /api/v1/matchmaking/join    { "mode": "text" | "video", "interests": [...], "language": "en" }
POST /api/v1/matchmaking/leave
GET  /api/v1/matchmaking/status
```

Socket.IO equivalents: `match:join`, `match:leave`, and the server-pushed `match:found` / `match:ended` / `match:left` / `match:error`.

- Preferences: `mode` (`text` or `video`), `interests` (from a suggested list — see `GET /api/v1/matchmaking/interests` — plus arbitrary short tags), and `language` (ISO 639-1, used as a hard filter when both sides specify one).
- The matcher prefers pairing users who share at least one interest, but will pair users with no interest overlap after a short wait (8 seconds) rather than leaving them queued indefinitely.
- Blocked-user pairs, banned users, and a short "don't immediately re-match the same pair" cooldown are all enforced during pairing.
- On match, the server randomly designates one side as the WebRTC `initiator` and creates an ephemeral direct conversation the two participants can message in; video-mode matches also get an active `CallSession` created automatically.
- Disconnected or stale queue entries are removed automatically (see "Cleanup" below); joining while already matched or already queued is idempotent/updates in place rather than creating duplicate entries.

## WebRTC signaling

The server relays signaling messages only — it never proxies, records, or stores media.

Socket.IO events: `call:offer`, `call:answer`, `call:ice`, `call:accept`, `call:reject`, `call:end` (calls), and `peer:request` / `peer:accept` / `peer:reject` (for establishing a direct conversation with a specific user outside of random matchmaking).

```
Client A → Socket.IO → Server → Socket.IO → Client B      (signaling only)
Client A ⇄ WebRTC ⇄ Client B                                (actual audio/video/data)
```

`GET /api/v1/config/ice-servers` returns the configured STUN/TURN servers (`STUN_SERVER`, `TURN_SERVER`, `TURN_USERNAME`, `TURN_PASSWORD` from the environment — TURN credentials are never hard-coded).

## Voice and video calls

- A `CallSession` document tracks `callId`, `conversationId`, `callerId`, `receiverId`, `type` (`voice`/`video`), `status`, `startedAt`, `endedAt`.
- Calls ring for 45 seconds before automatically being marked `missed` if unanswered.
- The 50 MB transfer quota **does not** apply to calls — calls are unlimited from the server's perspective since it never touches call media, only signaling.
- Calls are never recorded, transcoded, uploaded, or stored by this server.

## P2P file transfers

There is no file-upload server and no `/upload` endpoint of any kind. The server only negotiates transfers; the bytes travel directly between clients over a WebRTC DataChannel.

Socket.IO events: `transfer:request`, `transfer:accept`, `transfer:reject`, `transfer:cancel`, `transfer:complete` (and `transfer:signal` for any extra DataChannel-establishment signaling payload a client needs to relay).

```json
{
  "transferId": "...",
  "conversationId": "...",
  "receiverId": "...",
  "fileName": "photo.jpg",
  "mimeType": "image/jpeg",
  "size": 1234567
}
```

### 50 MB quota

Each **sender** gets a cumulative 50 MB (`FILE_TRANSFER_LIMIT`, configurable) P2P transfer allowance per conversation, tracked in `TransferQuota` (`conversationId`, `senderId`, `usedBytes`, `reservedBytes`, `limitBytes`).

- Requesting a transfer **reserves** the requested size against the quota (`usedBytes + reservedBytes + size <= limitBytes`), preventing concurrent transfer requests from bypassing the limit.
- If the transfer is rejected, cancelled, or times out, the reservation is released.
- On `transfer:complete`, the reservation converts into `usedBytes`.
- Stale reservations (abandoned transfers) are swept automatically after 30 minutes.
- The quota never applies to live voice/video calls.

```
GET /api/v1/conversations/:id/quota
→ { "limitBytes": 52428800, "usedBytes": 10485760, "reservedBytes": 2097152, "remainingBytes": 41943040 }
```

## Conversations and groups

```
POST   /api/v1/conversations                          Create a direct or group conversation
GET    /api/v1/conversations                           List your conversations
GET    /api/v1/conversations/:id                        Conversation detail + members
PATCH  /api/v1/conversations/:id                        Update group title/settings (admin+)
POST   /api/v1/conversations/:id/members                Add members (group)
PATCH  /api/v1/conversations/:id/members/:userId         Change a member's role
DELETE /api/v1/conversations/:id/members/:userId         Remove a member / leave
```

- Direct conversations are deduplicated: starting a conversation with the same person twice returns the same conversation.
- Group roles: `owner` > `admin` > `moderator` > `member`. Adding members, changing roles, deleting others' messages, and changing group settings all require sufficient rank; only the owner can transfer ownership or grant admin.
- Group messages remain end-to-end encrypted exactly like direct messages — the server never stores group media, only encrypted text ciphertext.
- Membership is always validated server-side before any message, reaction, call, or transfer action is allowed in a conversation.

## Messages

```
GET    /api/v1/conversations/:id/messages?limit=&before=&after=   Cursor-paginated history
POST   /api/v1/conversations/:id/messages                          Send an encrypted message
DELETE /api/v1/messages/:id                                        Delete (soft-delete) a message
POST   /api/v1/messages/:id/reactions                              Add/remove an encrypted reaction
POST   /api/v1/messages/delivered                                   Mark delivered
POST   /api/v1/messages/read                                        Mark read
```

Socket.IO: `message:new`, `message:delivered`, `message:read`, `message:deleted`, `message:reaction`, `typing:start`, `typing:stop`.

- Every message record contains only `ciphertext`, `nonce`, `keyVersion`, and routing metadata — the server treats ciphertext as opaque and never attempts to decrypt or log it.
- `clientMessageId` gives idempotent sends: retrying a send with the same `clientMessageId` returns the original message rather than creating a duplicate.
- Deleting a message clears its ciphertext/nonce from storage and marks it `deleted` rather than truly erasing the row immediately, so read receipts and ordering remain consistent; it TTL-expires with the rest of the conversation's history.

## Temporary rooms

```
POST   /api/v1/rooms                    { name, maxMembers, pin, expiresInSeconds, allowCalls, allowTransfers, allowVoiceMessages }
GET    /api/v1/rooms/:id
POST   /api/v1/rooms/:id/join           { pin }
POST   /api/v1/rooms/:id/leave
DELETE /api/v1/rooms/:id                (owner only)
```

- Rooms require `maxMembers >= 2` and expire automatically (`expiresAt`, enforced both by a TTL index and by rejecting joins to already-expired rooms).
- An optional PIN is stored only as a salted hash (`scrypt`), never in plaintext; repeated wrong PIN attempts are rate-limited and temporarily locked out per room+identity and per room+IP.
- `allowCalls` / `allowTransfers` / `allowVoiceMessages` are enforced server-side before permitting the corresponding Socket.IO actions inside that room's conversation.
- Each identity is limited to a small number of concurrently active rooms to prevent room-spam.

## Blocking

```
POST   /api/v1/blocks             { anonymousId }
GET    /api/v1/blocks
DELETE /api/v1/blocks/:anonymousId
```

Blocking is enforced everywhere two people could otherwise interact: it is checked before matchmaking pairs two users, before a message is accepted, before a call offer is created, before a peer request is sent, and before a file transfer is negotiated. Blocking someone also immediately tears down any in-progress match, call, or transfer between the two of you.

## Reporting

```
POST /api/v1/reports   { reportedId, category, conversationId?, description? }
```

Categories: `spam`, `harassment`, `sexual_content`, `scam`, `hate`, `illegal_content`, `other`. Reports require some shared context (a shared conversation) so the report system cannot be used to target arbitrary strangers, and duplicate reports of the same category against the same person within 24 hours are deduplicated. Reports never require or accept private P2P media as evidence — only metadata and an optional text description. Enough independent reports against the same identity within a short window trigger an automatic temporary matchmaking/room restriction pending further signal.

## Client-side NSFW moderation

Because media is P2P and end-to-end encrypted, this server **cannot and does not** inspect decrypted images or video. It does not run — and does not pretend to run — any server-side media scanner. Instead:

- The Web and Mobile clients run local, on-device NSFW classification **after decrypting** media they receive.
- If flagged, the client reports it:

```
POST /api/v1/moderation/events   (or Socket.IO: moderation:event)
{ "type": "nsfw_detected", "category": "explicit_nudity", "confidence": 0.94, "transferId": "...", "conversationId": "..." }
```

- The server stores only this event (`ModerationEvent`) — never the media itself.
- A single client's classification is treated as one signal, combined with confidence thresholds (`NSFW_REVIEW_THRESHOLD`, `NSFW_BLOCK_THRESHOLD`), corroboration from other reporters for borderline (`review`-tier) events, and the sender's accumulated violation history — never as automatic, unilateral proof.
- Enforcement escalates with violation count (see `.env.example` for the exact thresholds): first confirmed violation is a warning; further ones add a transfer restriction, then a temporary ban, then longer/permanent restrictions. **A single uncertain classification never results in a permanent ban.**

## Ban system

```
GET    /api/v1/admin/bans
POST   /api/v1/admin/bans     { scope, anonymousId | deviceHash | ip, banType, restrictions, reason, durationSeconds }
DELETE /api/v1/admin/bans/:id (lift)
```

- Ban `scope` is `identity`, `device`, `ip`, or `combined` (an IP ban that only applies in conjunction with a matching identity or device — the safest form of IP-based restriction, used to avoid collaterally banning an entire shared network).
- `banType` is `warning`, `temporary`, `long_term`, or `permanent`; `restrictions` is any subset of `session`, `matchmaking`, `rooms`, `messaging`, `calls`, `transfers`, so a ban can be as narrow (e.g., transfers only) or as broad as needed.
- Bans are checked on session creation, socket connection, and before every restricted action; a newly-created ban is also pushed live to any already-connected matching sockets so enforcement is immediate, not just on next request.
- IP is always combined with other signals for anything beyond a `combined`-scope restriction — see "IP handling" above.

## Rate limiting

Implemented directly in `server.js` with in-memory sliding-window counters (no external dependency, no Redis). Session creation, matchmaking, messages, reads, room creation/joins, blocks, reports, calls, signaling, transfers, peer requests, typing indicators, moderation events, and Socket.IO connections/events are all separately rate-limited, keyed by a combination of IP hash, anonymous identity, and device hash as appropriate. Counters are swept periodically so the tracking map cannot grow unbounded.

## CORS

`ALLOWED_ORIGINS` is a comma-separated allow-list checked against the request's `Origin` header for both REST (via the `cors` package) and Socket.IO connections; `origin: *` is never used for these credentialed flows. In development, `localhost`/`127.0.0.1` origins are also allowed regardless of the list to simplify local client development.

## Request limits

JSON body size is capped (`express.json({ limit: '32kb' })`) since the API only ever carries metadata, ciphertext, and signaling payloads — never file bytes. Socket.IO's `maxHttpBufferSize` is similarly capped.

## Health endpoint

```
GET /api/v1/health
→ { "status": "ok" | "degraded", "database": "connected" | "disconnected", "uptime": 12345 }
```

Exposes no environment variables, secrets, credentials, internal IPs, or session data.

## Admin API

Requires header `X-Admin-Secret: <ADMIN_SECRET>` — a completely separate credential from any user session token; anonymous user sessions can never be used as admin credentials.

```
GET    /api/v1/admin/stats    activeUsers, activeRooms, activeCalls, activeTransfers, activeMatches, databaseStatus, uptime, memoryUsage, diskUsage
GET    /api/v1/admin/bans
POST   /api/v1/admin/bans
DELETE /api/v1/admin/bans/:id
```

## Cleanup and TTL

MongoDB TTL indexes automatically expire: sessions, anonymous identities (after a retention grace period), messages, message reactions, ephemeral match conversations, rooms, room memberships, matches, reports, moderation events, and old (even lifted) bans. In addition, the process runs its own periodic in-memory sweeps for: stale matchmaking queue entries, expired rate-limit buckets, expired peer requests, expired transfer quota reservations, locked-out PIN attempt records, and stale (never-answered) call sessions — so nothing accumulates unbounded in memory even under sustained load.

## In-memory vs. persisted state

To keep the system lightweight and fast, active matchmaking queues, in-progress calls, in-progress file transfers, and pending peer requests live in server process memory, backed by MongoDB records for durability/auditing/history. If you deploy more than one server instance, use sticky sessions (Socket.IO session affinity) so a given user's real-time state stays on one instance, or adapt these subsystems to a shared coordination layer before scaling horizontally.

## Storage architecture

The server is designed around minimal storage: MongoDB holds only lightweight metadata, public keys, and encrypted message ciphertext — **never** images, video, audio, voice messages, documents, ZIP files, media chunks, call recordings, thumbnails, or uploaded files of any kind. All real media moves directly between clients over WebRTC (media streams for calls, DataChannels for file transfers). There are no upload directories, no GridFS, no object storage integration, and no media proxy anywhere in this codebase.

## Logging

Only operational events are logged (server started, database connected/disconnected, socket connected/disconnected, match created, call started/ended, transfer negotiated, ban created), using short truncated anonymous identifiers — never private keys, session tokens, plaintext message content, file contents/media, raw persistent IP addresses, passwords, or secrets. In production, error logs omit stack traces and only report the error's name/code to avoid leaking sensitive detail; in development, full stack traces are shown to ease debugging.

## Error handling and resilience

- All async route handlers and Socket.IO event handlers are wrapped so thrown/rejected errors are converted into clean JSON error responses (or ack error payloads) rather than crashing the process.
- MongoDB connectivity issues are detected and surfaced as `503 db_unavailable` rather than a generic `500`, and the server retries its initial connection indefinitely with a backoff rather than crashing on startup if MongoDB is briefly unavailable.
- `uncaughtException` and `unhandledRejection` are caught and logged; the process keeps running rather than crashing outright on unexpected errors from malformed client input.

## Graceful shutdown

On `SIGINT`/`SIGTERM`, the server stops accepting new Socket.IO connections, disconnects existing sockets, closes the HTTP server, closes the MongoDB connection, and exits — with a safety timeout that force-exits if shutdown hangs.

## API versioning

Every REST route is under `/api/v1/`.

## Security considerations summary

- No plaintext private message content, file content, or media ever reaches the server.
- No private keys (encryption or device) are ever transmitted to or stored by the server.
- IP addresses are hashed before any persistence and are never returned to clients.
- Bans always combine multiple signals for anything beyond narrow, explicit single-scope restrictions, to avoid collaterally punishing shared networks.
- Admin access uses a separate secret from user sessions.
- All client-supplied identity claims in Socket.IO events are ignored in favor of the identity derived from the authenticated session — a client cannot claim to be someone else.
