# vins-bridge

Pi extension to sync coding sessions to an OpenClaw gateway.

## Installation

```bash
pi install git:github.com/danielmorandini/vins-bridge
```

Or for a specific version:

```bash
pi install git:github.com/danielmorandini/vins-bridge@v1.0.0
```

## Configuration

Set the gateway URL via environment variable:

```bash
export OPENCLAW_GATEWAY_URL="wss://your-gateway.example.com"
```

Default: `wss://rpi-4b.tail8711b.ts.net`

## Commands

| Command | Description |
|---------|-------------|
| `/vins:pair` | Initiate device pairing with the gateway |
| `/vins:sync` | Force sync current session |
| `/vins:status` | Show connection and sync status |

## Pairing Flow

1. Run `/vins:pair` in Pi
2. On the gateway, run `openclaw devices list` to see pending requests
3. Approve with `openclaw devices approve <requestId>`
4. Run `/vins:pair` again to connect

## How It Works

- Uses Ed25519 device identity for secure authentication
- Sessions sync automatically after each agent turn
- Device token persisted locally after first pairing

## Files

Device identity and tokens are stored in:
- `~/.pi/agent/extensions/vins-bridge/device-identity.json`
- `~/.pi/agent/extensions/vins-bridge/device-token.json`

## License

MIT
