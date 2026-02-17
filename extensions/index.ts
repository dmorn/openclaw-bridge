/**
 * Vins Bridge Extension for Pi
 *
 * Syncs Pi session entries to OpenClaw (Vins) for on-demand access.
 * Uses proper device identity and pairing for secure gateway access.
 *
 * Commands:
 *   /vins:sync    - Force sync current session
 *   /vins:status  - Show connection and sync status
 *   /vins:pair    - Initiate device pairing with gateway
 *   /vins:watch   - Enable/disable active watch for current session
 *
 * Environment:
 *   OPENCLAW_GATEWAY_URL      - WebSocket URL (default: wss://rpi-4b.tail8711b.ts.net)
 *   OPENCLAW_GATEWAY_PASSWORD - Gateway password for auth
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// Configuration
const GATEWAY_URL = process.env.OPENCLAW_GATEWAY_URL || "wss://rpi-4b.tail8711b.ts.net";
const GATEWAY_PASSWORD = process.env.OPENCLAW_GATEWAY_PASSWORD || "";
const SYNC_DEBOUNCE_MS = 2000;
const RECONNECT_DELAY_MS = 5000;
const CONNECT_TIMEOUT_MS = 10000;
const FETCH_LIMIT = 3;

// Storage paths
const CONFIG_DIR = path.join(os.homedir(), ".pi", "agent", "extensions", "vins-bridge");
const IDENTITY_FILE = path.join(CONFIG_DIR, "device-identity.json");
const TOKEN_FILE = path.join(CONFIG_DIR, "device-token.json");

// Protocol version
const PROTOCOL_VERSION = 3;

// ============================================
// Types
// ============================================

type ConnectionState = "disconnected" | "connecting" | "connected" | "pairing_required" | "pairing" | "error";
type AgentState = "running" | "done" | "blocked" | "failed";

interface DeviceIdentity {
  version: 1;
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
  createdAtMs: number;
}

interface DeviceToken {
  token: string;
  role: string;
  scopes: string[];
  issuedAtMs: number;
}

interface GatewayFrame {
  type: "req" | "res" | "event";
  id?: string;
  method?: string;
  params?: Record<string, unknown>;
  ok?: boolean;
  payload?: unknown;
  error?: { message: string; code?: string };
  event?: string;
}

interface WatchStatePayload {
  enabled?: boolean;
}

interface WatchLocalState {
  enabled: boolean;
  sessionId: string | null;
}

interface QueuedMessage {
  id: string;
  message: string;
  correlationId?: string | null;
  enqueuedAt: string;
}

interface BridgeState {
  connectionState: ConnectionState;
  lastError: string | null;
  lastSyncedIndex: number;
  lastSyncAt: number | null;
  sessionId: string | null;
  projectPath: string;
  syncPending: boolean;
  watchState: WatchLocalState;
}

function shortDeviceId(deviceId: string): string {
  return `${deviceId.slice(0, 12)}...`;
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ============================================
// Device Identity (Ed25519)
// ============================================

function ensureDir(filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString("base64url");
}

function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const key = crypto.createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" });
  const ED25519_SPKI_PREFIX_LEN = 12;
  if (spki.length === ED25519_SPKI_PREFIX_LEN + 32) {
    return spki.subarray(ED25519_SPKI_PREFIX_LEN);
  }
  return spki;
}

function fingerprintPublicKey(publicKeyPem: string): string {
  const raw = derivePublicKeyRaw(publicKeyPem);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function generateIdentity(): DeviceIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  return {
    version: 1,
    deviceId: fingerprintPublicKey(publicKeyPem),
    publicKeyPem,
    privateKeyPem,
    createdAtMs: Date.now(),
  };
}

function loadOrCreateDeviceIdentity(): DeviceIdentity {
  try {
    if (fs.existsSync(IDENTITY_FILE)) {
      const raw = fs.readFileSync(IDENTITY_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (
        parsed?.version === 1 &&
        typeof parsed.deviceId === "string" &&
        typeof parsed.publicKeyPem === "string" &&
        typeof parsed.privateKeyPem === "string"
      ) {
        const derivedId = fingerprintPublicKey(parsed.publicKeyPem);
        if (derivedId !== parsed.deviceId) {
          const updated = { ...parsed, deviceId: derivedId };
          fs.writeFileSync(IDENTITY_FILE, JSON.stringify(updated, null, 2) + "\n", { mode: 0o600 });
          return { ...parsed, deviceId: derivedId };
        }
        return parsed as DeviceIdentity;
      }
    }
  } catch {
    // Identity load failed, will regenerate
  }

  const identity = generateIdentity();
  ensureDir(IDENTITY_FILE);
  fs.writeFileSync(IDENTITY_FILE, JSON.stringify(identity, null, 2) + "\n", { mode: 0o600 });
  return identity;
}

function loadDeviceToken(): DeviceToken | null {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")) as DeviceToken;
    }
  } catch {
    // Token not available
  }
  return null;
}

function saveDeviceToken(token: DeviceToken): void {
  ensureDir(TOKEN_FILE);
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(token, null, 2) + "\n", { mode: 0o600 });
}

function clearDeviceToken(): void {
  try {
    if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE);
  } catch {
    // Ignore
  }
}

// ============================================
// Device Auth
// ============================================

function buildDeviceAuthPayload(params: {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token: string | null;
  nonce?: string;
}): string {
  const version = params.nonce ? "v2" : "v1";
  const scopes = params.scopes.join(",");
  const token = params.token ?? "";
  const base = [version, params.deviceId, params.clientId, params.clientMode, params.role, scopes, String(params.signedAtMs), token];
  if (version === "v2") base.push(params.nonce ?? "");
  return base.join("|");
}

function signPayload(privateKeyPem: string, payload: string): string {
  const key = crypto.createPrivateKey(privateKeyPem);
  return base64UrlEncode(crypto.sign(null, Buffer.from(payload, "utf8"), key));
}

function publicKeyToBase64Url(publicKeyPem: string): string {
  return base64UrlEncode(derivePublicKeyRaw(publicKeyPem));
}

// ============================================
// Extension Entry Point
// ============================================

export default function (pi: ExtensionAPI) {
  const identity = loadOrCreateDeviceIdentity();

  let ws: WebSocket | null = null;
  let connectNonce: string | null = null;
  let connectTimeout: ReturnType<typeof setTimeout> | null = null;
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  let syncTimer: ReturnType<typeof setTimeout> | null = null;
  let requestId = 0;
  let currentCtx: ExtensionContext | null = null;
  let pendingSyncState: AgentState | undefined;

  const pendingRequests = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  const state: BridgeState = {
    connectionState: "disconnected",
    lastError: null,
    lastSyncedIndex: 0,
    lastSyncAt: null,
    sessionId: null,
    projectPath: process.cwd(),
    syncPending: false,
    watchState: {
      enabled: false,
      sessionId: null,
    },
  };

  async function refreshWatchState(sessionId: string): Promise<void> {
    if (state.connectionState !== "connected") return;
    try {
      const payload = (await sendRequest("pi.session.watch.get", { sessionId })) as WatchStatePayload;
      state.watchState = {
        enabled: Boolean(payload?.enabled),
        sessionId,
      };
    } catch {
      // Keep local state unchanged on transient errors
    }
  }

  async function fetchAndInjectMessages(sessionId: string): Promise<number> {
    if (state.connectionState !== "connected") return 0;

    const payload = (await sendRequest("pi.session.messages.fetch", {
      sessionId,
      limit: FETCH_LIMIT,
    })) as { messages?: QueuedMessage[] };

    const messages = Array.isArray(payload?.messages) ? payload.messages : [];
    if (messages.length === 0) return 0;

    for (const msg of messages) {
      pi.sendUserMessage(msg.message, { deliverAs: "followUp" });
    }

    await sendRequest("pi.session.messages.ack", {
      sessionId,
      ids: messages.map((m) => m.id),
    });

    return messages.length;
  }

  async function maybeFetchQueuedMessages(reason: string): Promise<void> {
    if (!state.watchState.enabled || !state.sessionId || !currentCtx) return;
    const sessionId = getSessionId(currentCtx);
    if (state.watchState.sessionId && state.watchState.sessionId !== sessionId) return;

    try {
      const fetched = await fetchAndInjectMessages(sessionId);
      if (fetched > 0) {
        currentCtx.ui.notify(`VINS_WATCH | delivered ${fetched} queued follow-up message(s) | ${reason}`, "info");
      }
    } catch {
      // Non-fatal; event-driven retries happen on next enqueue/reconnect/agent_end
    }
  }

  // ============================================
  // State Machine
  // ============================================

  function setState(newState: ConnectionState, error?: string): void {
    const prev = state.connectionState;
    state.connectionState = newState;
    state.lastError = error ?? null;

    // Notify on significant state changes
    if (prev !== newState && currentCtx) {
      switch (newState) {
        case "connected":
          currentCtx.ui.notify("Vins: connected", "success");
          void maybeFetchQueuedMessages("reconnect");
          break;
        case "pairing_required":
          currentCtx.ui.notify("Vins: pairing required, run /vins:pair", "warning");
          break;
        case "error":
          currentCtx.ui.notify(`Vins: error${error ? ` - ${error}` : ""}`, "error");
          break;
        case "disconnected":
          if (prev === "connected") {
            currentCtx.ui.notify("Vins: disconnected", "warning");
          }
          break;
      }
    }
  }

  function isConfigured(): boolean {
    return Boolean(GATEWAY_PASSWORD || loadDeviceToken());
  }

  // ============================================
  // Connection Management (Non-blocking)
  // ============================================

  function connect(): void {
    if (state.connectionState === "connecting" || state.connectionState === "connected") {
      return;
    }

    // Don't require config for pairing attempt
    if (state.connectionState !== "pairing" && !isConfigured()) {
      setState("disconnected");
      return;
    }

    // Only set connecting if not already in pairing state
    // (pairing state means we're actively trying to pair)
    if (state.connectionState !== "pairing") {
      setState("connecting");
    }
    connectNonce = null;

    try {
      ws = new WebSocket(GATEWAY_URL);

      ws.onopen = () => {
        // Connection established, waiting for challenge
      };

      ws.onmessage = (event) => {
        try {
          handleFrame(JSON.parse(event.data.toString()));
        } catch {
          // Parse error, ignore malformed frames
        }
      };

      ws.onclose = (event) => {
        clearConnectTimeout();
        const reason = event.reason || `code ${event.code}`;

        flushPendingRequests(new Error("Connection closed"));

        // Handle based on current state
        switch (state.connectionState) {
          case "pairing":
            // Stay in pairing state - user is waiting for approval
            // Don't change state, don't reconnect
            break;

          case "pairing_required":
            // Already in pairing_required, stay there
            break;

          case "connected":
            // Was connected, try to reconnect
            setState("disconnected", reason);
            scheduleReconnect();
            break;

          case "connecting":
            // Connection failed
            setState("error", reason);
            scheduleReconnect();
            break;

          default:
            setState("disconnected", reason);
        }
      };

      ws.onerror = () => {
        // onclose will fire after this
      };

      // Set connect timeout
      connectTimeout = setTimeout(() => {
        if (state.connectionState === "connecting" || state.connectionState === "pairing") {
          ws?.close();
          if (state.connectionState === "pairing") {
            // Pairing attempt timed out, go back to pairing_required
            setState("pairing_required", "Connection timeout");
          } else {
            setState("error", "Connection timeout");
            scheduleReconnect();
          }
        }
      }, CONNECT_TIMEOUT_MS);
    } catch (err) {
      setState("error", String(err));
      scheduleReconnect();
    }
  }

  function disconnect(): void {
    clearConnectTimeout();
    clearReconnectTimeout();
    ws?.close();
    ws = null;
    setState("disconnected");
    flushPendingRequests(new Error("Disconnected"));
  }

  function clearConnectTimeout(): void {
    if (connectTimeout) {
      clearTimeout(connectTimeout);
      connectTimeout = null;
    }
  }

  function clearReconnectTimeout(): void {
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }
  }

  function scheduleReconnect(): void {
    clearReconnectTimeout();

    // Don't auto-reconnect when pairing is needed
    if (state.connectionState === "pairing" || state.connectionState === "pairing_required") {
      return;
    }

    reconnectTimeout = setTimeout(() => {
      if (state.connectionState !== "connected" && state.connectionState !== "connecting") {
        connect();
      }
    }, RECONNECT_DELAY_MS);
  }

  function flushPendingRequests(error: Error): void {
    for (const [, pending] of pendingRequests) {
      pending.reject(error);
    }
    pendingRequests.clear();
  }

  // ============================================
  // Protocol Handling
  // ============================================

  function sendConnectFrame(): void {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    const role = "operator";
    const scopes = ["operator.read", "operator.write", "operator.admin"];
    const signedAtMs = Date.now();
    const storedToken = loadDeviceToken();
    const authToken = storedToken?.token ?? undefined;

    const payload = buildDeviceAuthPayload({
      deviceId: identity.deviceId,
      clientId: "gateway-client",
      clientMode: "backend",
      role,
      scopes,
      signedAtMs,
      token: authToken ?? null,
      nonce: connectNonce ?? undefined,
    });

    ws.send(
      JSON.stringify({
        type: "req",
        id: "connect-1",
        method: "connect",
        params: {
          minProtocol: PROTOCOL_VERSION,
          maxProtocol: PROTOCOL_VERSION,
          client: {
            id: "gateway-client",
            displayName: "Pi Vins Bridge",
            version: "0.3.0",
            platform: process.platform,
            mode: "backend",
          },
          role,
          scopes,
          caps: [],
          commands: [],
          permissions: {},
          auth: { token: authToken, password: GATEWAY_PASSWORD || undefined },
          device: {
            id: identity.deviceId,
            publicKey: publicKeyToBase64Url(identity.publicKeyPem),
            signature: signPayload(identity.privateKeyPem, payload),
            signedAt: signedAtMs,
            nonce: connectNonce ?? undefined,
          },
        },
      })
    );
  }

  function handleFrame(frame: GatewayFrame): void {
    // Challenge
    if (frame.type === "event" && frame.event === "connect.challenge") {
      const payload = frame.payload as { nonce?: string } | undefined;
      connectNonce = payload?.nonce ?? null;
      sendConnectFrame();
      return;
    }

    if (frame.type === "event" && frame.event === "pi.session.message.queued") {
      const payload = frame.payload as { sessionId?: string } | undefined;
      if (!payload?.sessionId || !state.sessionId) return;
      if (payload.sessionId !== state.sessionId) return;
      void maybeFetchQueuedMessages("queued-event");
      return;
    }

    // Connect response
    if (frame.type === "res" && frame.id === "connect-1") {
      clearConnectTimeout();

      if (frame.ok) {
        setState("connected");

        const helloPayload = frame.payload as { auth?: { deviceToken?: string; role?: string; scopes?: string[] } } | null;
        if (helloPayload?.auth?.deviceToken) {
          saveDeviceToken({
            token: helloPayload.auth.deviceToken,
            role: helloPayload.auth.role ?? "operator",
            scopes: helloPayload.auth.scopes ?? [],
            issuedAtMs: Date.now(),
          });
        }

        // Process pending sync
        if (state.syncPending) {
          state.syncPending = false;
          void doSync(pendingSyncState);
          pendingSyncState = undefined;
        }
      } else {
        const errorMsg = frame.error?.message || "Auth failed";

        if (errorMsg.toLowerCase().includes("pairing") || errorMsg.toLowerCase().includes("not_paired")) {
          // If we were in "pairing" state (user ran /vins:pair), stay there awaiting approval
          // Otherwise go to pairing_required
          if (state.connectionState !== "pairing") {
            setState("pairing_required");
          }
        } else {
          setState("error", errorMsg);
          scheduleReconnect();
        }
      }
      return;
    }

    // Other responses
    if (frame.type === "res" && frame.id) {
      const pending = pendingRequests.get(frame.id);
      if (pending) {
        pendingRequests.delete(frame.id);
        if (frame.ok) {
          pending.resolve(frame.payload);
        } else {
          pending.reject(new Error(frame.error?.message || "Request failed"));
        }
      }
    }
  }

  // ============================================
  // RPC
  // ============================================

  function sendRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (state.connectionState !== "connected" || !ws || ws.readyState !== WebSocket.OPEN) {
        reject(new Error("Not connected"));
        return;
      }

      const id = `req-${++requestId}`;
      pendingRequests.set(id, { resolve, reject });

      ws.send(JSON.stringify({ type: "req", id, method, params }));

      setTimeout(() => {
        if (pendingRequests.has(id)) {
          pendingRequests.delete(id);
          reject(new Error("Request timeout"));
        }
      }, 30000);
    });
  }

  // ============================================
  // Sync (Non-blocking)
  // ============================================

  function getSessionId(ctx: ExtensionContext): string {
    const sessionFile = ctx.sessionManager.getSessionFile();
    if (sessionFile) {
      const match = sessionFile.match(/([^/\\]+)\.jsonl$/);
      return match ? match[1] : sessionFile.replace(/[^a-zA-Z0-9_-]/g, "_");
    }
    return `ephemeral-${Date.now()}`;
  }

  function scheduleSync(ctx: ExtensionContext, agentState?: AgentState): void {
    currentCtx = ctx;

    if (syncTimer) clearTimeout(syncTimer);
    pendingSyncState = agentState ?? pendingSyncState;

    syncTimer = setTimeout(() => {
      const syncState = pendingSyncState;
      pendingSyncState = undefined;
      void doSync(syncState);
    }, SYNC_DEBOUNCE_MS);
  }

  async function doSync(agentState?: AgentState): Promise<void> {
    try {
      if (!currentCtx) return;

      if (state.connectionState !== "connected") {
        state.syncPending = true;
        pendingSyncState = agentState ?? pendingSyncState;
        if (state.connectionState === "disconnected") {
          connect();
        }
        return;
      }

      const ctx = currentCtx;
      const entries = ctx.sessionManager.getEntries();
      const sessionId = getSessionId(ctx);

      if (state.sessionId !== sessionId) {
        state.sessionId = sessionId;
        state.lastSyncedIndex = 0;
      }

      const newEntries = entries.slice(state.lastSyncedIndex);
      if (newEntries.length === 0) return;

      await sendRequest("pi.session.sync", {
        sessionId,
        projectPath: state.projectPath,
        entries: newEntries,
        append: state.lastSyncedIndex > 0,
        agentState,
      });

      state.lastSyncedIndex = entries.length;
      state.lastSyncAt = Date.now();

      await maybeFetchQueuedMessages("post-sync");
    } catch {
      // swallow errors to keep sync/watch loop stable (non-fatal retry path)
    }
  }

  // ============================================
  // Event Handlers (Non-blocking)
  // ============================================

  pi.on("session_start", (_event, ctx) => {
    currentCtx = ctx;
    state.sessionId = getSessionId(ctx);
    state.lastSyncedIndex = 0;

    if (state.watchState.sessionId !== state.sessionId) {
      state.watchState = { enabled: false, sessionId: state.sessionId };
    }

    if (isConfigured() && state.connectionState === "disconnected") {
      connect();
    }

    if (state.connectionState === "connected" && state.sessionId) {
      void refreshWatchState(state.sessionId).then(() => maybeFetchQueuedMessages("session-start"));
    }
  });

  pi.on("agent_start", (_event, ctx) => {
    if (isConfigured()) {
      scheduleSync(ctx, "running");
    }
  });

  pi.on("agent_end", (_event, ctx) => {
    if (isConfigured()) {
      scheduleSync(ctx, "done");
    }
  });

  pi.on("session_switch", (_event, ctx) => {
    currentCtx = ctx;
    state.sessionId = getSessionId(ctx);
    state.lastSyncedIndex = 0;

    if (isConfigured()) {
      scheduleSync(ctx);
    }

    if (state.connectionState === "connected" && state.sessionId) {
      void refreshWatchState(state.sessionId);
    }
  });

  pi.on("session_shutdown", () => {
    if (syncTimer) clearTimeout(syncTimer);
    disconnect();
  });

  // ============================================
  // Commands
  // ============================================

  pi.registerCommand("vins:pair", {
    description: "Initiate device pairing with OpenClaw gateway",
    handler: async (_args, ctx) => {
      clearDeviceToken();
      disconnect();

      setState("pairing");

      ctx.ui.notify(`PAIRING | device ${shortDeviceId(identity.deviceId)}`, "info");

      connect();

      await new Promise((r) => setTimeout(r, 5000));

      if (state.connectionState === "connected") {
        ctx.ui.notify("PAIRED | connected", "success");
      } else if (state.connectionState === "pairing") {
        ctx.ui.notify("PAIRING | awaiting approval | openclaw devices list", "warning");
      } else {
        setState("pairing_required");
        ctx.ui.notify(`PAIRING_REQUIRED | ${state.lastError || "failed"}`, "error");
      }
    },
  });

  pi.registerCommand("vins:sync", {
    description: "Force sync session to Vins (OpenClaw)",
    handler: async (_args, ctx) => {
      if (!isConfigured()) {
        ctx.ui.notify("PAIRING_REQUIRED | run /vins:pair", "warning");
        return;
      }

      currentCtx = ctx;
      state.lastSyncedIndex = 0;
      void doSync();

      ctx.ui.notify("SYNC | triggered", "info");
    },
  });

  pi.registerCommand("vins:watch", {
    description: "Manage active watch for current Pi session: on | off | status",
    handler: async (args, ctx) => {
      const action = (typeof args === "string" ? args.trim().split(/\s+/)[0] || "status" : args[0] || "status").toLowerCase();
      const sessionId = getSessionId(ctx);
      currentCtx = ctx;

      if (!isConfigured()) {
        ctx.ui.notify("PAIRING_REQUIRED | run /vins:pair", "warning");
        return;
      }

      if (state.connectionState !== "connected") {
        connect();
        ctx.ui.notify("VINS_WATCH | connecting to gateway", "warning");
        return;
      }

      if (action === "status") {
        await refreshWatchState(sessionId);
        ctx.ui.notify(
          `VINS_WATCH | ${state.watchState.enabled ? "ON" : "OFF"} | session ${sessionId}`,
          "info",
        );
        return;
      }

      if (action !== "on" && action !== "off") {
        ctx.ui.notify("Usage: /vins:watch on|off|status", "warning");
        return;
      }

      const enabled = action === "on";
      await sendRequest("pi.session.watch.set", { sessionId, enabled });
      state.watchState = { enabled, sessionId };

      if (enabled) {
        await maybeFetchQueuedMessages("watch-enabled");
      }

      ctx.ui.notify(`VINS_WATCH | ${enabled ? "ON" : "OFF"} | session ${sessionId}`, "success");
    },
  });

  pi.registerCommand("vins:status", {
    description: "Show Vins bridge status",
    handler: async (_args, ctx) => {
      const stateName = state.connectionState.toUpperCase();
      let details = "";
      let hints = "";

      switch (state.connectionState) {
        case "connected":
          details = `${state.lastSyncedIndex} entries`;
          hints = state.lastSyncAt ? `last sync ${formatTime(state.lastSyncAt)}` : "sync pending";
          break;

        case "pairing":
          details = `device ${shortDeviceId(identity.deviceId)}`;
          hints = "awaiting gateway approval";
          break;

        case "pairing_required":
          details = `device ${shortDeviceId(identity.deviceId)}`;
          hints = "run /vins:pair";
          break;

        case "disconnected":
          details = "offline";
          hints = "will reconnect";
          break;

        case "error":
          details = state.lastError || "unknown error";
          hints = "check gateway reachability";
          break;

        case "connecting":
          details = "connecting";
          hints = "please wait";
          break;
      }

      const watch = state.watchState.sessionId
        ? `watch ${state.watchState.enabled ? "ON" : "OFF"} (${state.watchState.sessionId})`
        : "watch OFF";

      const parts = [stateName, details, watch, hints].filter(Boolean);
      ctx.ui.notify(parts.join(" | "), state.connectionState === "error" ? "error" : "info");
    },
  });
}
