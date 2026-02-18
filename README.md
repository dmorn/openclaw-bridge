# openclaw-bridge

Pi coding agent extension that syncs sessions to [OpenClaw](https://github.com/openclaw/openclaw) and receives continuation messages.

**Counterpart:** [pi-bridge](https://github.com/dmorn/pi-bridge) (OpenClaw gateway plugin)

## What it does

- **Syncs** Pi session entries to OpenClaw gateway via WebSocket RPC
- **Watches** sessions for state changes with server-side notifications
- **Receives** continuation messages from OpenClaw and injects them as user input

## Install

```bash
pi install git:github.com/dmorn/openclaw-bridge
```

## Setup

### 1. Configure gateway URL

```bash
export OPENCLAW_GATEWAY_URL="wss://your-gateway.example.com"
```

### 2. Pair the device

In Pi:
```
/openclaw:pair
```

On the OpenClaw gateway host:
```bash
openclaw devices list              # find the pending request
openclaw devices approve <id>      # approve it
```

Back in Pi, run `/openclaw:pair` again. The extension receives a device token and connects automatically. Token is stored locally — future connections are automatic.

### 3. Enable watch (recommended)

```
/openclaw:watch always
```

This auto-enables watch on every new session, so OpenClaw gets notified when Pi finishes a task.

## Commands

| Command | Description |
|---------|-------------|
| `/openclaw:pair` | Initiate device pairing with gateway |
| `/openclaw:sync` | Force sync current session |
| `/openclaw:watch on\|off\|always\|never\|status` | Control session watch |
| `/openclaw:status` | Show connection and sync status |

## How it works

### Session sync (Pi → OpenClaw)

```
Pi                                 OpenClaw Gateway
  │── connect (device identity) ─────│
  │◄─ hello-ok (device token) ───────│
  │                                   │
  │── pi.session.sync ────────────────│──→ .jsonl + .meta.json
  │   (on agent_start, agent_end)     │──→ watch transition → notification
  └───────────────────────────────────┘
```

Sync is **one-way** (Pi → OpenClaw) and **debounced** (2s). Sends `agentState` for watch detection.

### Continuations (OpenClaw → Pi)

```
OpenClaw Gateway                   Pi
  │── pi.session.continuation ───────│
  │   (broadcast: sessionId+message) │──→ sendUserMessage(message)
  │                                   │
  │◄── pi.session.continuation.ack ──│
  └───────────────────────────────────┘
```

Direct delivery — no queue, no polling. If Pi is disconnected, the message is lost (by design — the user is back at the keyboard).

## Security

- Ed25519 device identity (same as OpenClaw native clients)
- Private key never leaves the device
- Device tokens are role-scoped (`operator` with `read`/`write`/`admin`)
- Gateway admin can revoke tokens anytime

## Storage

```
<extension-dir>/
├── device-identity.json   # Ed25519 keypair (auto-generated)
├── device-token.json      # Gateway-issued token (after pairing)
└── preferences.json       # Watch preferences
```

All files are co-located with the extension and gitignored.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `NOT_PAIRED` error | Run `/openclaw:pair`, approve on gateway |
| Connection timeout | Check `OPENCLAW_GATEWAY_URL` and network |
| Token revoked | Delete `device-token.json`, re-pair |

## OpenClaw side setup

The gateway needs the [pi-bridge](https://github.com/dmorn/pi-bridge) plugin installed:

```bash
openclaw plugins install /path/to/pi-bridge
```

See pi-bridge README for config details.
