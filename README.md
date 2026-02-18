# Vins Bridge - Pi ↔ OpenClaw Session Sync

Sync your Pi coding sessions to OpenClaw for cross-context awareness.

## Features

- **Session mirroring** — Pi sessions are synced to OpenClaw workspace
- **Secure device pairing** — Ed25519 keypair with gateway approval
- **Active watch loop** — `/vins:watch on|off|status` controls server-side watch state per session
- **Event-driven continuation delivery** — queued follow-up messages are fetched on enqueue events, reconnect, and post-sync
- **Gateway RPC extension** — OpenClaw is extended with custom `pi.session.*` methods
- **On-demand access** — Zero tokens during sync, Vins reads when needed
- **Auto-sync** — Syncs on `agent_start`/`agent_end` (debounced 2s) and forwards `agentState`

## Installation

```bash
# Install from local path
pi install ./pi-extension

# Or copy to extensions directory
cp -r ./pi-extension ~/.pi/agent/extensions/openclaw-bridge
```

## OpenClaw Side (Required)

This project follows a **2-repo architecture**:

1. Pi extension (this repo: `pi-extension/`) running inside Pi coding agent
2. OpenClaw plugin (separate repo): `https://github.com/dmorn/pi-bridge` (private)

The OpenClaw plugin must be installed separately in the OpenClaw environment.

### OpenClaw plugin methods

The OpenClaw plugin registers these custom gateway methods:

- `pi.session.sync` — append/write session entries to JSONL (accepts optional `agentState`)
- `pi.session.list` — list synced Pi sessions
- `pi.session.get` — read session entries with pagination (`offset`, `limit`)
- `pi.session.delete` — delete a synced session
- `pi.session.watch.set` / `pi.session.watch.get` — persist and inspect watch state
- `pi.session.enqueue` — enqueue continuation messages for a Pi session
- `pi.session.messages.fetch` / `pi.session.messages.ack` — fetch/ack continuation queue items

### Install OpenClaw plugin

```bash
openclaw plugins install /path/to/pi-bridge
```

### OpenClaw plugin config

In `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "pi-bridge": {
        "enabled": true,
        "config": {
          "sessionsDir": "pi-sessions"
        }
      }
    }
  }
}
```

`sessionsDir` is resolved relative to `agents.defaults.workspace`.

## Setup

### 1. Set Gateway URL (optional if using default)

```bash
export OPENCLAW_GATEWAY_URL="wss://your-gateway.example.com"
```

Default: `wss://rpi-4b.tail8711b.ts.net`

### 2. Set Gateway Password (optional if using device token)

```bash
export OPENCLAW_GATEWAY_PASSWORD="your-password"
```

### 3. Pair the Device

Start Pi and run:

```
/vins:pair
```

This generates an Ed25519 keypair and sends a pairing request to the gateway.

### 4. Approve on Gateway

On your OpenClaw gateway host:

```bash
# List pending pairing requests
openclaw devices list

# Approve the request
openclaw devices approve <requestId>
```

After approval, the device receives a token that's stored locally. Future
connections use this token automatically.

## Commands

| Command | Description |
|---------|-------------|
| `/vins:pair` | Initiate device pairing with gateway |
| `/vins:sync` | Force sync current session |
| `/vins:watch on\|off\|status` | Enable/disable/show active watch for current session |
| `/vins:status` | Show connection, sync, and watch status |

## How It Works

```
Pi (silver)                    OpenClaw (rpi-4b)
    │                               │
    │── connect.challenge ──────────│
    │                               │
    │── connect (device identity) ──│
    │                               │
    │◄─ hello-ok (device token) ────│
    │                               │
    │── pi.session.sync ────────────│
    │                               │
    └───────────────────────────────┘
```

1. **Connect** — Pi sends Ed25519-signed device identity
2. **Auth** — Gateway verifies signature and checks pairing
3. **Token** — Gateway issues device-scoped token
4. **Sync** — Pi pushes session deltas via RPC (no agent invocation)

## Storage

Pi side:

```
~/.pi/agent/extensions/openclaw-bridge/
├── device-identity.json   # Ed25519 keypair (chmod 600)
└── device-token.json      # Gateway-issued token (chmod 600)
```

OpenClaw side (default):

```
<workspace>/pi-sessions/
├── <sessionId>.jsonl      # synced entries
└── <sessionId>.meta.json  # session metadata
```

## Security

- Device identity uses Ed25519 (same as OpenClaw native clients)
- Private key never leaves the device
- Device tokens are scoped to role + permissions
- Gateway admin can revoke tokens at any time

## Troubleshooting

**"NOT_PAIRED" error**

Run `/vins:pair` and approve on gateway with `openclaw devices approve`.

**"Connection timeout"**

Check gateway URL and network connectivity:
```bash
curl -I https://your-gateway.example.com
```

**Token expired/revoked**

Clear stored token and re-pair:
```bash
rm ~/.pi/agent/extensions/openclaw-bridge/device-token.json
pi /vins:pair
```
