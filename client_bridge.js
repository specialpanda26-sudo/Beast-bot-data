const {
  default: makeWASocket,
  useMultiFileAuthState,
  Browsers,
  DisconnectReason,
  delay,
  fetchLatestBaileysVersion,
  downloadMediaMessage
} = require("@whiskeysockets/baileys");
const { Boom } = require("@hapi/boom");
const axios = require("axios");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const pino = require("pino");
const qrcode = require("qrcode-terminal");
const http = require("http");
// ── Anti-ban middleware (baileys-antiban, bundled locally in /libs) ────────
// Wraps every session's socket with rate limiting, warm-up ramping, health
// monitoring, legitimacy-signal injection, and group-op guarding — all the
// features from the baileys-antiban package — without touching Baileys itself.
const {
  wrapSocket,
  FileStateAdapter,
  resolveConfig,
  // ── Previously-bundled-but-unwired modules, now wired in below ──────────
  generateFingerprint,   // stable per-session randomized device identity
  applyFingerprint,
  credsSnapshot,         // auto-backup of creds.json + corruption detection
  readReceiptVariance,   // human-like jitter on read receipts
  parseRetryReason,      // used to detect Bad-MAC/session-decrypt errors
  isMacError,
  proxyRotator,          // optional residential/4G proxy rotation
  WebhookAlerts,         // optional Telegram/Discord/generic risk alerts
  Scheduler,             // "safe sending hours" — used only for .announce broadcasts
  ContentVariator,       // de-duplicates identical bulk-broadcast text
  classifyDisconnect     // ✅ FIX: typed fatal/recoverable/rate-limited disconnect classification
} = require("./libs/baileys-antiban");

// ── Owner & Bot Config ──────────────────────────────────────────────────────
// 🔒 SECURITY FIX: no more hardcoded fallback number baked into the source.
// Set OWNER_NUMBER in your environment (Render/Railway dashboard, .env, etc).
// The effective owner number can also be changed at runtime — without a
// redeploy — from the Admin Panel (Settings → Owner Number), or by the
// owner themself via the hidden `.ownerrecovery` WhatsApp command. See
// getOwnerNumber() below for the resolution order.
const OWNER_NUMBER_ENV = (process.env.OWNER_NUMBER || '').replace(/[^0-9]/g, '');
const OWNER_NAME_CFG = process.env.OWNER_NAME   || 'Henry Ochibots';
const BOT_NAME_DEFAULT   = process.env.BOT_NAME      || 'Henry Ochibots v19™';
const CMD_PREFIX_DEFAULT = '.';

// ✅ NEW (Update 15): .setbotname/.setprefix (plugins/settings-ext.js) used to
// save successfully but never actually change anything — BOT_NAME/CMD_PREFIX
// were frozen constants read once at startup. These two now re-read the
// settings store live, so a change takes effect on the very next message
// with no restart needed. Falls back to the env-based default above if
// settings-ext can't be loaded for any reason, or hasn't been touched yet.
function getBotName() {
  try { return require('./plugins/settings-ext.js').__getSetting('botname') || BOT_NAME_DEFAULT; }
  catch (_) { return BOT_NAME_DEFAULT; }
}
function getPrefix() {
  try { return require('./plugins/settings-ext.js').__getSetting('prefix') || CMD_PREFIX_DEFAULT; }
  catch (_) { return CMD_PREFIX_DEFAULT; }
}

// ✅ NEW: bot name recognition for group chats — deliberately NOT reusing the
// old broad "bot"/"henry" substring match (see the FIX comment further down
// explaining why that was removed: it fired on "I saw a robot", "chatbot",
// anyone named Henry in the group, etc.). This only matches full name
// phrases, on word boundaries, so "robot"/"chatbot" still won't trigger it —
// customize via BOT_NAME_ALIASES (comma-separated) if "Henry Ochibots" ever
// changes for a reseller/white-label deployment.
const BOT_NAME_ALIASES = (process.env.BOT_NAME_ALIASES || 'ochibots,henry ochibots,beast bot,beastbot')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
function isBotAddressedByName(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return BOT_NAME_ALIASES.some(alias => {
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${escaped}\\b`).test(lower);
  });
}

// ── Co-Owner System ─────────────────────────────────────────────────────────
// Co-owners have the same power as owner but cannot add/remove other co-owners
global.coOwners = new Set(
  (process.env.CO_OWNERS || '').split(',').map(n => n.replace(/[^0-9]/g, '')).filter(Boolean)
);

// ── Mode Persistence (global, not per-config object) ───────────────────────
// ✅ FIX: mode was stored on a throwaway config object rebuilt each message
if (global.botMode === undefined)   global.botMode   = 'public';
if (global.botActive === undefined) global.botActive = true;

// ── Sub-Admin System ─────────────────────────────────────────────────────────
// Numbers that the owner has granted bot-admin access to (without full owner power)
// Persisted in memory — owner uses .addadmin / .removeadmin to manage
global.subAdmins = global.subAdmins || new Set(
  (process.env.SUB_ADMINS || '').split(',').map(n => n.replace(/[^0-9]/g, '')).filter(Boolean)
);

// ── Plugin Loader ────────────────────────────────────────────────────────────
// Loads all command handlers from /plugins/*.js
// ✅ FIX: 'games' and 'osint' plugin files existed on disk but were never
// in this list, so .hangman/.trivia/.guess/.truth/.dare/.wyr/.validate/
// .ipinfo/.whois all resolved to "Unknown command" even though fully coded.
const PLUGIN_NAMES = [
  'general', 'group', 'media', 'cypher', 'atassa', 'scheduler', 'wallet',
  'games', 'osint', 'extended',
  // Delta feature pack:
  'notes', 'groupguard', 'games2', 'texteffects', 'urltools', 'tempmail',
  'sudo', 'settings-ext', 'aichat2', 'sports', 'megabackup', 'overlap-rewrites',
  // Henry v20 ported commands (19 category files):
  'ported_admin', 'ported_ai', 'ported_download', 'ported_fun', 'ported_games',
  'ported_general', 'ported_group', 'ported_images', 'ported_info', 'ported_menu',
  'ported_music', 'ported_owner', 'ported_quotes', 'ported_search', 'ported_stalk',
  'ported_stickers', 'ported_tools', 'ported_upload', 'ported_utility',
];
const allCommands = {};
const cmdOwnerPlugin = {};
PLUGIN_NAMES.forEach(name => {
  try {
    const mod = require(`./plugins/${name}`);
    Object.assign(allCommands, mod);
    Object.keys(mod).forEach(k => { cmdOwnerPlugin[k] = name; });
  } catch (e) {
    console.warn(`⚠️  Plugin "${name}" failed to load: ${e.message}`);
  }
});
// ✅ FIX: some plugin files export internal helpers alongside real commands
// (games.js#_handleGameReply, group.js#canUseCommand) via the same
// module.exports object. Left in, a user could type ".canUseCommand" or
// "._handleGameReply" and the dispatcher would blindly call it with the
// wrong argument shape. These are consumed directly by name elsewhere in
// this file, not through the .command dispatcher, so strip them here.
const NON_COMMAND_KEYS = [
  '_handleGameReply', 'canUseCommand', 'startSchedulerLoop', '__SETTING_KEYS', '__memKey',
  '_handleTTTReply', '_handleWCGReply', '_enforceGroupGuard', '__getSetting',
  '_handleJoinEvent', '_handleLeaveEvent',
];
NON_COMMAND_KEYS.forEach(k => delete allCommands[k]);

// ✅ FIX: .reload (plugins/general.js) mutated global.allCommandsRef, but
// nothing ever pointed that at the real dispatch table below — so .reload
// silently did nothing to the commands actually being used. Now it does.
global.allCommandsRef = allCommands;

const loadedCmds = Object.keys(allCommands);
console.log(`✅ Plugins loaded — ${loadedCmds.length} commands: ${loadedCmds.join(', ')}`);

// ✅ FIX: lib_ported/commandHandler.js is a leftover from the original ported
// Mega-MD bot. It expects plugins shaped like {command, handler, category},
// but every plugin here exports flat {cmdName: fn, ...} instead — so nothing
// ever called registerCommand() on a real command, leaving the singleton's
// .commands/.categories/.stats permanently empty. That silently broke
// .smenu/.shelp (rendered "0 plugins", no categories), .find/.lookup/
// .searchcmd (always "not found"), .perf/.metrics/.diagnostics (always "no
// performance data"), and .manage/.ctrl/.control's toggle+alias features
// (could never find a command to act on). This backfills the registry from
// the real dispatch table above so those commands reflect what's actually
// installed. The dispatcher below still calls allCommands[cmd] directly for
// real execution — this registry is metadata (for listing/search/stats)
// plus disabled-flags and runtime aliases, which the dispatcher now honors.
const CommandHandler = require('./lib_ported/commandHandler.js');
const PLUGIN_CATEGORY = {
  general: 'General', ported_general: 'General',
  group: 'Group', ported_group: 'Group', groupguard: 'Group Guard',
  media: 'Media', 'overlap-rewrites': 'Media',
  cypher: 'AI & Fun', atassa: 'Utility', wallet: 'Wallet',
  games: 'Games', games2: 'Games', ported_games: 'Games',
  osint: 'OSINT', extended: 'Group Intelligence',
  notes: 'Notes', texteffects: 'Text Effects', urltools: 'URL Tools',
  tempmail: 'Temp Mail', sudo: 'Sudo', 'settings-ext': 'Settings',
  aichat2: 'AI Chat', sports: 'Sports', megabackup: 'Backup', scheduler: 'Scheduling',
  ported_admin: 'Admin', ported_ai: 'AI Images & Video', ported_download: 'Downloader',
  ported_fun: 'Fun', ported_images: 'Images', ported_info: 'Info',
  ported_menu: 'Audio & Text Tools', ported_music: 'Music', ported_owner: 'Owner',
  ported_quotes: 'Quotes', ported_search: 'Search', ported_stalk: 'Stalk & Lookup',
  ported_stickers: 'Stickers', ported_tools: 'Tools', ported_upload: 'Upload',
  ported_utility: 'Utility',
};
loadedCmds.forEach(cmdKey => {
  CommandHandler.registerCommand({
    command : cmdKey,
    category: PLUGIN_CATEGORY[cmdOwnerPlugin[cmdKey]] || 'Misc',
    handler : allCommands[cmdKey], // metadata only — see dispatcher below for real execution
  });
});
console.log(`✅ CommandHandler registry backfilled — ${CommandHandler.commands.size} commands across ${CommandHandler.categories.size} categories`);

// ── Pairing Web Server ──────────────────────────────────────
// Open /pair in browser to link any WhatsApp number without touching .env
// Multi-session: each session slot gets its own resolve queue entry
const pendingPairResolves = {};   // sessionId → resolve fn (replaces single global)
let pendingPairResolve = null;    // kept for legacy single-call compat (points to active slot)
let lastPairingCode = null;
let lastPairingNumber = null;
let botOnline = false;
let pairingPending = false;  // true while a new session is starting up
let currentSessionId = "beastbot";
let lastQRDataUrl = null;  // base64 data URL of the latest QR code for web display
// ✅ FIX: track consecutive *fatal* disconnects per session so we can allow
// a few bounded retries (in case a "fatal" code is ever a rare transient
// blip) without falling back into the old infinite-retry-forever behavior.
const fatalRetryCounts = {};
const MAX_FATAL_RETRIES = 3;
// ✅ RESTORED FEATURE: chat-based ".pair" self-service linking (was present
// in an earlier menu version, missing from this codebase). Tracks in-progress
// "which method? which number?" conversations per sender, and resolver
// callbacks so a freshly-started session can hand its code/QR back to the
// chat that requested it instead of only the web /pair UI.
const chatPairSessions = {};
const chatPairResolvers = {};
// Track all active session IDs so /pair-status can report correctly
const activeSessions = new Set();
// ✅ NEW: live socket registry, keyed by sessionId — lets HTTP routes (like
// /send-otp-whatsapp) reach a connected WhatsApp socket to send messages
// on behalf of the bot, outside the normal messages.upsert flow.
const activeSockets = new Map();

// ── Paid Pairing / Activation Keys ───────────────────────────────────────
// Per-session lock state for the customer-paid activation flow. Every
// session gets its own entry (unlike global.subscriptionExpired, which is
// shared across sessions and only really correct for a single-session
// deploy) — keyed by sessionId, since one process here can run many
// customer sessions at once.
//   { activated, expiryTs, pendingRequest, requesterChat }
const sessionActivation = new Map();

function getActivation(sessionId) {
  if (!sessionActivation.has(sessionId)) {
    sessionActivation.set(sessionId, {
      activated: false, expiryTs: null, pendingRequest: false, requesterChat: null
    });
  }
  return sessionActivation.get(sessionId);
}

function isSessionLive(sessionId) {
  const a = sessionActivation.get(sessionId);
  if (!a) return false;
  if (!a.activated) return false;
  if (a.expiryTs && (Date.now() / 1000) >= a.expiryTs) return false;
  return true;
}

// ── 🌝 Reaction-triggered recovery cache ────────────────────────────────────
// Keeps a short-lived copy of recent messages (key, raw message, sender, name,
// and — for view-once — the already-downloaded buffer) so that reacting with
// 🌝 on a view-once or later-deleted message can pull it back up and forward
// it privately to the bot's own number. Capped + time-pruned so it can't grow
// unbounded on a busy bot.
global.recentMsgCache = global.recentMsgCache || new Map();
const RECENT_MSG_CACHE_MAX = 800;
const RECENT_MSG_CACHE_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

function cacheRecentMessage(msgId, entry) {
  if (!msgId) return;
  global.recentMsgCache.set(msgId, { ...entry, cachedAt: Date.now() });
  if (global.recentMsgCache.size > RECENT_MSG_CACHE_MAX) {
    const oldestKey = global.recentMsgCache.keys().next().value;
    global.recentMsgCache.delete(oldestKey);
  }
}

function pruneRecentMsgCache() {
  const cutoff = Date.now() - RECENT_MSG_CACHE_TTL_MS;
  for (const [id, entry] of global.recentMsgCache) {
    if (entry.cachedAt < cutoff) global.recentMsgCache.delete(id);
  }
}
setInterval(pruneRecentMsgCache, 15 * 60 * 1000);
// ✅ RESTORED FEATURE: sweep abandoned chat-based .pair conversations (e.g.
// someone sends ".pair" then never replies) so they don't linger forever.
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [sender, convo] of Object.entries(chatPairSessions)) {
    if (convo.lastActivity < cutoff) delete chatPairSessions[sender];
  }
}, 60 * 1000);

// ✅ SECURITY FIX: /send-otp-whatsapp, /notify-owner, /notify-user and the
// new /internal/action route below are meant to be called ONLY by app.py
// over 127.0.0.1 — but this HTTP server listens on the same public port as
// /pair, so with no check, anyone who found the bot's public URL could POST
// straight to them and use the live WhatsApp socket to send arbitrary
// messages, or (with /internal/action) message strangers, set the bot's
// status, or change its bio — no login required. Every internal route now
// requires this header; app.py sends it on every internal call.
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";
function isInternalCall(req) {
  if (!INTERNAL_SECRET) return true; // no secret configured — old behavior, but logs a warning below
  return req.headers["x-internal-secret"] === INTERNAL_SECRET;
}
if (!INTERNAL_SECRET) {
  console.warn("⚠️  INTERNAL_SECRET is not set — internal routes (/send-otp-whatsapp, " +
    "/notify-owner, /notify-user, /internal/action) are reachable by anyone who has " +
    "your bot's public URL. Set INTERNAL_SECRET to the same random value in both " +
    "this process's env and app.py's env to lock them down.");
}

// ✅ NEW: customer-facing web actions (Command Console + status/bio editor).
// Only reachable internally (see isInternalCall above) — app.py is the one
// that actually checks "is this logged-in customer allowed to touch this
// sessionId" before ever calling here. This endpoint trusts that check and
// just does the requested action against that session's live socket.
//
// Scope of v1 (deliberately NOT everything asked for):
//   - send-message  : send a text message to a phone number or group JID
//   - set-status    : update the WhatsApp "About" status text
//   - set-bio       : alias of set-status (WhatsApp only has one "About" field)
//   - set-name      : update the profile display name
// NOT included yet: full inbox/message history (needs a persistent message
// store this bot doesn't have yet), and "change number" (WhatsApp's real
// number migration is an official in-app flow — there's no safe way to do
// it through an unofficial library like Baileys without real risk of the
// account getting permanently banned, so this deliberately isn't offered).
async function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", () => {
      try { resolve(JSON.parse(body || "{}")); } catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

async function pairServerRoutesExtra(req, res, url) {
  if (req.method === "POST" && url.pathname === "/internal/action") {
    if (!isInternalCall(req)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "forbidden" }));
      return true;
    }
    try {
      const { sessionId, action, to, text, name } = await readJsonBody(req);
      const socket = sessionId && activeSockets.get(sessionId);
      if (!socket) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: "That session isn't connected right now." }));
        return true;
      }
      if (action === "send-message") {
        const cleanTo = (to || "").replace(/[^0-9@.\-]/g, "");
        const jid = cleanTo.includes("@") ? cleanTo : `${cleanTo.replace(/[^0-9]/g, "")}@s.whatsapp.net`;
        if (!text) throw new Error("text is required");
        await socket.sendMessage(jid, { text });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
        return true;
      }
      if (action === "set-status" || action === "set-bio") {
        if (typeof text !== "string") throw new Error("text is required");
        await socket.updateProfileStatus(text);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
        return true;
      }
      if (action === "set-name") {
        if (!name) throw new Error("name is required");
        await socket.updateProfileName(name);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
        return true;
      }
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: `Unknown action "${action}"` }));
      return true;
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: e.message }));
      return true;
    }
  }
  return false;
}

const pairServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // GET / → redirect to /pair (clean URL)
  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
    res.writeHead(302, { Location: "/pair" });
    res.end();
    return;
  }

  // GET /pair — serve the dedicated pairing page (pair.html)
  if (req.method === "GET" && url.pathname === "/pair") {
    const htmlPath = path.join(__dirname, "pair.html");
    const fallback = path.join(__dirname, "index.html");
    const filePath = fs.existsSync(htmlPath) ? htmlPath : fallback;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(fs.readFileSync(filePath, "utf8"));
    return;
  }

  // GET /index or / for landing page
  if (req.method === "GET" && (url.pathname === "/index" || url.pathname === "/index.html")) {
    const htmlPath = path.join(__dirname, "index.html");
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(fs.readFileSync(htmlPath, "utf8"));
    } else { res.writeHead(404); res.end("Not found"); }
    return;
  }

// ✅ NEW: optional DEDICATED number for sending OTPs, separate from the main
// bot number — pair a second WhatsApp session (any spare SIM/eSIM/virtual
// number you control) and set OTP_SENDER_SESSION_ID to its session name.
// This is the closest you can get to "Instagram-style" OTP delivery on
// WhatsApp: there's no free/anonymous SMS-style push channel — WhatsApp
// only delivers messages from a real, paired WhatsApp account — but a
// second dedicated number at least keeps OTPs out of your main bot's
// regular chat history and gives it its own clean identity/profile name.
const OTP_SENDER_SESSION_ID = (process.env.OTP_SENDER_SESSION_ID || "").trim();

function getOtpSocket() {
  if (OTP_SENDER_SESSION_ID && activeSockets.has(OTP_SENDER_SESSION_ID)) {
    return activeSockets.get(OTP_SENDER_SESSION_ID);
  }
  // Falls back to whichever session is connected first if no dedicated
  // OTP session is configured/online — keeps OTPs working even before
  // you've set one up.
  return activeSockets.values().next().value;
}

// ✅ NEW: finds the one connected session that's paired to the admin's own
// OWNER_NUMBER — used exclusively for the admin-panel "forgot password"
// OTP, so a password reset that grants full admin access always visibly
// comes from the admin's own bot number and never falls back to some
// other connected customer session or the dedicated OTP sender.
function getOwnerSessionSocket() {
  const ownerNum = getOwnerNumber();
  if (!ownerNum) return null;
  for (const socket of activeSockets.values()) {
    const paired = (socket.user?.id || "").split("@")[0].replace(/:\d+$/, "").replace(/[^0-9]/g, "");
    if (paired && paired === ownerNum) return socket;
  }
  return null;
}

  // deliver a registration OTP straight to the user's WhatsApp, instead of
  // email. Internal-only: app.py reaches this over 127.0.0.1, same as the
  // /pair proxy routes below.
  if (req.method === "POST" && url.pathname === "/send-otp-whatsapp") {
    if (!isInternalCall(req)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ success: false, error: "forbidden" }));
    }
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { phone, otp, name, requireOwnerSession } = JSON.parse(body || "{}");
        const cleanPhone = (phone || "").replace(/[^0-9]/g, "");
        if (!cleanPhone || !otp) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "phone and otp are required" }));
        }
        // ✅ NEW: requireOwnerSession=true (used only by the admin-panel
        // password reset) forces this to go out from the Owner Session ONLY
        // — no fallback to OTP_SENDER_SESSION_ID or any other connected
        // number, since this code grants full admin access and must always
        // visibly come from the admin's own bot number.
        let socket;
        if (requireOwnerSession) {
          socket = getOwnerSessionSocket();
          if (!socket) {
            res.writeHead(503, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "The Owner Session isn't connected right now — pair the admin's own number to the bot to enable admin password reset." }));
          }
        } else {
          // Prefers a dedicated OTP-sending session (OTP_SENDER_SESSION_ID) if
          // one is paired and online; otherwise falls back to the first
          // connected session so OTPs still work without one configured.
          socket = getOtpSocket();
          if (!socket) {
            res.writeHead(503, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "No WhatsApp session is connected right now." }));
          }
        }
        await socket.sendMessage(`${cleanPhone}@s.whatsapp.net`, {
          text: `🔐 *Henry Ochibots v19™ — Verification Code*\n\n` +
                `Hi ${name || "there"}, your code is: *${otp}*\n\n` +
                `This code expires in 10 minutes. Enter it on the registration page to verify your number and unlock your trust badge + free credit.`
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // POST /notify-owner — called locally by app.py whenever something needs
  // the bot owner's attention right away (e.g. a new wallet top-up request
  // waiting for approval). Sends a WhatsApp message straight to OWNER_NUMBER.
  if (req.method === "POST" && url.pathname === "/notify-owner") {
    if (!isInternalCall(req)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ success: false, error: "forbidden" }));
    }
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { text } = JSON.parse(body || "{}");
        const socket = activeSockets.values().next().value;
        if (!socket || !text) {
          res.writeHead(503, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "No WhatsApp session connected, or missing text." }));
        }
        const ownerNum = getOwnerNumber();
        if (!ownerNum) {
          res.writeHead(503, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "No owner number configured yet." }));
        }
        await socket.sendMessage(`${ownerNum}@s.whatsapp.net`, { text });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // POST /notify-user — called locally by app.py to message a specific
  // user directly (e.g. their top-up request was approved/rejected).
  if (req.method === "POST" && url.pathname === "/notify-user") {
    if (!isInternalCall(req)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ success: false, error: "forbidden" }));
    }
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { phone, text } = JSON.parse(body || "{}");
        const cleanPhone = (phone || "").replace(/[^0-9]/g, "");
        const socket = activeSockets.values().next().value;
        if (!socket || !cleanPhone || !text) {
          res.writeHead(503, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ success: false, error: "No WhatsApp session connected, or missing phone/text." }));
        }
        await socket.sendMessage(`${cleanPhone}@s.whatsapp.net`, { text });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // POST /pair-reset — clear pairing state and start a NEW session
  // OLD sessions keep running — supports 100+ numbers simultaneously
  // POST /pair-abandon — user left the page without pairing; free the session slot
  // Called via navigator.sendBeacon when user closes/leaves the tab
  if (req.method === "POST" && url.pathname === "/pair-abandon") {
    // Read body (sendBeacon sends JSON)
    let body = "";

    req.on("data", d => body += d);
    req.on("end", () => {
      console.log(`🚪 User left pairing page without pairing — auto-releasing slot`);
      // Only clear state if a code hasn't been used/connected yet
      if (!botOnline) {
        lastPairingCode = null;
        lastPairingNumber = null;
        lastQRDataUrl = null;
        pairingPending = false;
        // Kill any pending resolve so the slot is freed for the next visitor
        if (pendingPairResolve) {
          pendingPairResolve = null;
        }
      }
    });
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === "POST" && url.pathname === "/pair-reset") {
    // ✅ FIX: clear code + number immediately so /pair-status never returns stale data
    lastPairingCode = null;
    lastPairingNumber = null;
    lastQRDataUrl = null;  // ✅ FIX: clear old QR so new one is generated fresh
    pendingPairResolve = null;
    pairingPending = true;  // flag: new session is starting, code not yet ready
    // NOTE: do NOT set botOnline = false — old sessions are still running
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    // Start a brand new session with a unique ID — old ones keep running
    const newSid = "session_" + Date.now();
    console.log(`🔄 Starting new session slot: ${newSid} (old sessions still active, total: ${activeSessions.size})`);
    // Delete the session folder for the new slot so it starts fresh (no stale creds)
    try {
      const newPath = path.join(SESSIONS_DIR, newSid);
      if (fs.existsSync(newPath)) fs.rmSync(newPath, { recursive: true, force: true });
    } catch (_) {}
    setTimeout(() => startSession(newSid, { forceQR: false }), 500);
    return;
  }

  // POST /qr-reset — start a NEW session in QR code mode (not pairing code)
  if (req.method === "POST" && url.pathname === "/qr-reset") {
    lastPairingCode = null;
    lastPairingNumber = null;
    lastQRDataUrl = null;
    pendingPairResolve = null;
    pairingPending = true;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    const newSid = "qr_session_" + Date.now();
    console.log(`📷 Starting QR session: ${newSid}`);
    try {
      const newPath = path.join(SESSIONS_DIR, newSid);
      if (fs.existsSync(newPath)) fs.rmSync(newPath, { recursive: true, force: true });
    } catch (_) {}
    setTimeout(() => startSession(newSid, { forceQR: true }), 500);
    return;
  }

  // GET /pair-status — JS polling endpoint (no page refresh needed)
  if (req.method === "GET" && url.pathname === "/pair-status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      code: lastPairingCode || null,
      number: lastPairingNumber || null,
      online: botOnline,
      sessions: activeSessions.size,
      pending: pairingPending,   // true = session started but code not yet generated
      qr: lastQRDataUrl || null  // base64 data URL of QR image, or null
    }));
    return;
  }

  // POST /pair — receive number and trigger pairing
  if (req.method === "POST" && url.pathname === "/pair") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const number = params.get("number")?.replace(/[\s\-\+]/g, "") || "";
      if (number) {
        lastPairingNumber = number;
        // Find the first waiting session slot (FIFO order)
        const waitingSlot = Object.keys(pendingPairResolves)[0];
        if (waitingSlot && pendingPairResolves[waitingSlot]) {
          // ✅ FIX: clear stale code before new one is generated
          lastPairingCode = null;
          lastPairingNumber = number;
          pairingPending = true;
          // A session is ready — resolve it immediately
          const resolve = pendingPairResolves[waitingSlot];
          delete pendingPairResolves[waitingSlot];
          pendingPairResolve = null;
          resolve(number);
        } else if (pendingPairResolve) {
          // Legacy fallback — single-session path
          lastPairingCode = null;
          lastPairingNumber = number;
          pairingPending = true;
          pendingPairResolve(number);
          pendingPairResolve = null;
        } else {
          // ✅ FIX: clear stale code before new one is generated
          lastPairingCode = null;
          lastPairingNumber = number;
          pairingPending = true;
          // No session ready yet — queue with retries for up to 30s
          console.log(`⏳ Number received (${number}) but no session slot ready yet — queuing...`);
          let attempts = 0;
          const retry = setInterval(() => {
            attempts++;
            const slot = Object.keys(pendingPairResolves)[0];
            if (slot && pendingPairResolves[slot]) {
              clearInterval(retry);
              const resolve = pendingPairResolves[slot];
              delete pendingPairResolves[slot];
              pendingPairResolve = null;
              resolve(number);
              console.log(`✅ Queued number delivered to slot "${slot}" after ${attempts} attempts`);
            } else if (pendingPairResolve) {
              clearInterval(retry);
              pendingPairResolve(number);
              pendingPairResolve = null;
              console.log(`✅ Queued number delivered (legacy) after ${attempts} attempts`);
            } else if (attempts >= 60) {
              clearInterval(retry);
              console.log("❌ Gave up waiting for bot to be ready");
            }
          }, 500);
        }
      }
      // ✅ FIX: return JSON instead of redirect so app.py can read res.ok + body
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, queued: !!number }));
    });
    return;
  }

  // GET /status — for keep-alive pings
  if (url.pathname === "/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", online: botOnline, version: "V6" }));
    return;
  }

  if (await pairServerRoutesExtra(req, res, url)) return;

  res.writeHead(404);
  res.end("Not found");
});

const WEB_PORT = process.env.WEB_PORT || 3000;
pairServer.listen(WEB_PORT, () => {
  const publicUrl = process.env.RENDER_EXTERNAL_URL || process.env.RAILWAY_STATIC_URL || `http://localhost:${WEB_PORT}`;
  console.log(`🌐 Pairing web UI (internal) → http://localhost:${WEB_PORT}/pair`);
  console.log(`🔗 Public session link      → ${publicUrl}/pair`);
});

const logger = pino({ level: "silent" });
// Must match the port app.py actually binds to (it reads the same PORT env
// var). Hardcoding 5000 here breaks the bridge on platforms like Railway
// that assign a dynamic PORT instead of leaving it at the default.
const BACKEND_PORT = process.env.PORT || 5000;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

// ── Optional anti-ban extras (all inert unless you configure them) ─────────
// These need external resources (real proxy IPs, a webhook URL) or change
// timing behavior, so — unlike the always-on modules above — they stay
// completely off until you opt in via env vars. Wiring them here means
// turning them on later is just an env var, no code changes.

// Proxy rotation — set ANTIBAN_PROXY_LIST="socks5://user:pass@host:port,http://host2:port2"
// Requires the matching optional peer dep to actually be installed
// (socks-proxy-agent for socks5/socks5h, https-proxy-agent for http/https).
let antibanProxyRotator = null;
if (process.env.ANTIBAN_PROXY_LIST) {
  try {
    const pool = process.env.ANTIBAN_PROXY_LIST.split(",").map((raw, i) => {
      const url = new URL(raw.trim());
      return {
        type: url.protocol.replace(":", ""), // http | https | socks5 | socks5h
        host: url.hostname,
        port: Number(url.port),
        username: url.username || undefined,
        password: url.password || undefined,
        label: `proxy-${i + 1}`
      };
    });
    antibanProxyRotator = proxyRotator({
      pool,
      strategy: process.env.ANTIBAN_PROXY_STRATEGY || "round-robin",
      rotateOn: ["disconnect", "ban-warning"],
      logger: { info: (m) => console.log(`🌐 [proxy] ${m}`), warn: (m) => console.warn(`⚠️ [proxy] ${m}`), error: (m) => console.error(`❌ [proxy] ${m}`) }
    });
    console.log(`🌐 Proxy rotation enabled — ${pool.length} endpoint(s), strategy: ${process.env.ANTIBAN_PROXY_STRATEGY || "round-robin"}`);
  } catch (e) {
    console.warn(`⚠️ ANTIBAN_PROXY_LIST set but couldn't be parsed, proxy rotation disabled: ${e.message}`);
  }
}

// Webhook/Telegram/Discord risk alerts — set any of:
//   ANTIBAN_WEBHOOK_URL, ANTIBAN_TELEGRAM_BOT_TOKEN + ANTIBAN_TELEGRAM_CHAT_ID,
//   ANTIBAN_DISCORD_WEBHOOK_URL
let antibanWebhooks = null;
if (process.env.ANTIBAN_WEBHOOK_URL || process.env.ANTIBAN_TELEGRAM_BOT_TOKEN || process.env.ANTIBAN_DISCORD_WEBHOOK_URL) {
  antibanWebhooks = new WebhookAlerts({
    urls: process.env.ANTIBAN_WEBHOOK_URL ? [process.env.ANTIBAN_WEBHOOK_URL] : [],
    telegram: (process.env.ANTIBAN_TELEGRAM_BOT_TOKEN && process.env.ANTIBAN_TELEGRAM_CHAT_ID)
      ? { botToken: process.env.ANTIBAN_TELEGRAM_BOT_TOKEN, chatId: process.env.ANTIBAN_TELEGRAM_CHAT_ID }
      : undefined,
    discord: process.env.ANTIBAN_DISCORD_WEBHOOK_URL ? { webhookUrl: process.env.ANTIBAN_DISCORD_WEBHOOK_URL } : undefined,
    minRiskLevel: process.env.ANTIBAN_WEBHOOK_MIN_RISK || "medium",
    cooldownMs: 5 * 60 * 1000
  });
  console.log("📡 Anti-ban webhook alerts enabled");
}

// Smart broadcast scheduler — set ANTIBAN_SCHEDULER_ENABLED=true.
// IMPORTANT: this only ever gates the .announce/admin-panel BULK BROADCAST
// loop further down this file, never normal command replies — a command
// bot that goes silent to real users at night would be a regression, not
// an anti-ban feature. Broadcasts queued outside active hours just wait
// for the next poll inside the window instead of firing immediately.
let antibanScheduler = null;
if (process.env.ANTIBAN_SCHEDULER_ENABLED === "true") {
  antibanScheduler = new Scheduler({
    timezone: process.env.ANTIBAN_SCHEDULER_TZ || "Africa/Nairobi",
    activeHours: [
      Number(process.env.ANTIBAN_SCHEDULER_START_HOUR || 7),
      Number(process.env.ANTIBAN_SCHEDULER_END_HOUR || 22)
    ]
  });
  console.log(`⏰ Broadcast scheduler enabled — active hours ${process.env.ANTIBAN_SCHEDULER_START_HOUR || 7}:00-${process.env.ANTIBAN_SCHEDULER_END_HOUR || 22}:00`);
}

// Content variator — invisible per-recipient variation on bulk-broadcast
// text so 500 identical messages don't read as a spam blast. No config
// needed, always on for .announce broadcasts (never touches normal command
// replies, which should stay exactly as typed).
const antibanContentVariator = new ContentVariator({ zeroWidthChars: true, punctuationVariation: true });

// Env vars let the bot start unattended on Railway/Render, where there is no
// interactive terminal to answer the session-name / linking-method prompts.
const SESSION_ID_ENV = (process.env.SESSION_ID || "").trim();
const PAIRING_NUMBER_ENV = (process.env.PAIRING_NUMBER || "").replace(/[\s\-\+]/g, "");
const IS_INTERACTIVE = Boolean(process.stdin.isTTY);

const apiClient = axios.create({
  baseURL: BACKEND_URL,
  timeout: 8000,
  maxContentLength: Infinity,
  maxBodyLength: Infinity,
  headers: { Authorization: `Bearer ${process.env.ADMIN_PASSWORD || ''}` }
});

// ── Feature flag cache ──────────────────────────────────────────────────────
// Polls the backend's feature toggles every 30s so we don't hit the DB on
// every single message. Defaults to "on" if the backend hasn't responded yet.
let featureCache = {};
async function refreshFeatures() {
  try {
    const res = await apiClient.get("/bot/features");
    featureCache = res.data || {};
    global.__featureCache = featureCache;
  } catch (e) { /* keep last known cache on failure */ }
}
refreshFeatures();
setInterval(refreshFeatures, 30000);
function isFeatureOn(name) {
  return featureCache[name] !== false; // unknown/missing = treated as on
}

// ── Owner number resolution ─────────────────────────────────────────────────
// Polls the backend for an admin-panel-set override every 30s, same pattern
// as the feature cache above. Resolution order (highest priority first):
//   1. global.ownerOverride   — set instantly via the hidden .ownerrecovery
//                                WhatsApp command (this process only)
//   2. ownerNumberCache       — set via the Admin Panel, synced from the DB
//   3. OWNER_NUMBER_ENV       — the OWNER_NUMBER env var at deploy time
// getOwnerNumber() returns '' if none of these are configured, in which case
// all owner-only checks correctly deny everyone (no silent hardcoded fallback).
let ownerNumberCache = '';
async function refreshOwnerNumber() {
  try {
    const res = await apiClient.get("/bot/owner-number");
    const val = (res.data?.owner_number || '').replace(/[^0-9]/g, '');
    if (val) ownerNumberCache = val;
  } catch (e) { /* keep last known cache on failure */ }
}
refreshOwnerNumber();
setInterval(refreshOwnerNumber, 30000);
function getOwnerNumber() {
  return (global.ownerOverride || ownerNumberCache || OWNER_NUMBER_ENV || '').replace(/[^0-9]/g, '');
}

// ── Activity Log / Owner Notifications ──────────────────────────────────────
// Three categories, each with its own admin-panel view (GET /admin/activity-log
// ?category=...) and its own notification behaviour:
//   'command'   — every command anyone runs. Panel-only (too high-volume to
//                 WhatsApp-ping the owner on every .ping).
//   'error'     — a command threw, or a download/etc. failed. Panel + a live
//                 WhatsApp DM to the owner so failures don't go unnoticed.
//   'sensitive' — an owner/admin-tier action was taken (kick, promote,
//                 payment review, login, broadcast, addadmin, etc.). Panel +
//                 WhatsApp DM, regardless of whether it succeeded or failed,
//                 since these are the actions worth knowing about even when
//                 they work exactly as intended.
// Fire-and-forget by design — logging must never slow down or break the
// actual command reply, so every failure here is swallowed silently.
const SENSITIVE_COMMANDS = new Set([
  'kick', 'add', 'promote', 'demote', 'mute', 'unmute', 'revoke', 'antispam',
  'setperm', 'resetperm', 'creategroup', 'addtogroup', 'tagall', 'bcgc',
  'addadmin', 'removeadmin', 'addcoowner', 'removecoowner', 'settier',
  'announce', 'checkblocked', 'welcome', 'status', 'pp', 'bio', 'public',
  'private', 'setmode', 'ownerrecovery', 'login', 'logout', 'maintenance',
  'reload', 'addfunds',
]);

// Types that must never trigger a WhatsApp owner-ping. These fire *from
// inside* the send pipeline itself (antiban warning about its own send), so
// alerting on them via a normal sendMessage would recurse: notify → send →
// beforeSend flags it → notify again → forever. This is what caused the
// 2026-07-03 incident (1000+ identical pings in ~6s, forced account unlink).
// Panel logging (apiClient.post above) still happens for these — only the
// WhatsApp ping is suppressed.
const NO_PING_TYPES = new Set(['antiban-recovery', 'antiban-risk']);

async function logActivity(category, type, detail, actor) {
  try {
    await apiClient.post('/activity/log', { category, type, detail, actor: actor || '' });
  } catch (e) { /* never let logging break the bot */ }

  if (category === 'command') return; // panel-only, no WhatsApp ping
  if (NO_PING_TYPES.has(type)) return; // panel-only, see comment above

  try {
    const socket = activeSockets.values().next().value;
    const ownerNum = getOwnerNumber();
    if (!socket || !ownerNum) return;
    const icon = category === 'error' ? '⚠️' : '🛡️';
    const label = category === 'error' ? 'Error' : 'Sensitive action';
    // Use the raw (un-wrapped) send here on purpose: this is a system
    // notification about the bot's own send pipeline, not outbound bot
    // traffic, so it must not re-enter antiban's beforeSend() — see
    // sendMessageRaw in wrapper.js for why.
    const send = socket.sendMessageRaw || socket.sendMessage;
    await send(`${ownerNum}@s.whatsapp.net`, {
      text: `${icon} *${label}: ${type}*\n\n${detail}${actor ? `\n\n👤 ${actor}` : ''}`,
    });
  } catch (e) { /* never let notification break the bot */ }
}
global.logActivity = logActivity;

// ── Persistent data directory ───────────────────────────────────────────────
// ✅ FIX: everything that needs to survive a restart/redeploy (WhatsApp auth
// sessions, saved view-once media) now lives under one DATA_DIR root instead
// of scattered relative paths. On Render/Railway, mount a persistent disk at
// this path (see render.yaml) or it'll still be wiped on redeploy — but at
// least a plain process restart / crash / sleep-wake no longer loses data,
// and app.py's DB now lives in the same place for the same reason.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Sessions directory
const SESSIONS_DIR = path.join(DATA_DIR, "sessions");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// ✅ NEW: manual override to clear a stuck ban-recovery pause without needing
// shell access to the server. Set RESET_ANTIBAN_STATE=true in Render's
// Environment tab, save (triggers a redeploy), then REMOVE the env var
// again afterwards — otherwise every future restart wipes it too, which
// defeats the point of persisting it across restarts in the first place.
// ⚠️ This does NOT undo whatever WhatsApp did server-side — it only makes
// the bot stop remembering/respecting its own pause. If WhatsApp is still
// enforcing the timelock on their end, resuming sends can escalate a
// temporary restriction into a permanent ban. Use only if you're confident
// enough time has genuinely passed, or you're accepting that risk.
if (process.env.RESET_ANTIBAN_STATE === "true") {
  try {
    const entries = fs.existsSync(SESSIONS_DIR) ? fs.readdirSync(SESSIONS_DIR) : [];
    let cleared = 0;
    for (const sessionId of entries) {
      const antibanDir = path.join(SESSIONS_DIR, sessionId, "antiban");
      if (fs.existsSync(antibanDir)) {
        fs.rmSync(antibanDir, { recursive: true, force: true });
        cleared++;
      }
    }
    console.log(`⚠️  RESET_ANTIBAN_STATE=true — cleared antiban state for ${cleared} session(s). REMOVE this env var now so it doesn't wipe state on every future restart.`);
  } catch (e) {
    console.warn(`⚠️  RESET_ANTIBAN_STATE cleanup failed: ${e.message}`);
  }
}

function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function printBanner() {
  console.log("\n╔══════════════════════════════════════╗");
  console.log("   🔥 HENRY OCHIBOTS v19™ 🔥   ");
  console.log("╚══════════════════════════════════════╝\n");
}

async function askLinkingMethod() {
  console.log("1️⃣  QR Code  - Scan with WhatsApp camera");
  console.log("2️⃣  Pairing Code - Enter code in WhatsApp\n");
  const answer = await prompt("Choose method (1 or 2): ");
  return answer;
}

async function askPhoneNumber() {
  const num = await prompt("Enter phone number with country code (e.g. 2547XXXXXXXX): ");
  // Strip spaces, dashes, plus sign
  return num.replace(/[\s\-\+]/g, "");
}

async function askSessionId() {
  if (SESSION_ID_ENV) return SESSION_ID_ENV;
  if (!IS_INTERACTIVE) {
    console.log("ℹ️  No TTY detected and no SESSION_ID env var set — using 'default'.");
    return "default";
  }
  const existing = fs.readdirSync(SESSIONS_DIR).filter(f =>
    fs.statSync(path.join(SESSIONS_DIR, f)).isDirectory()
  );
  if (existing.length > 0) {
    console.log("\n📂 Existing sessions:");
    existing.forEach((s, i) => console.log(`   ${i + 1}. ${s}`));
  }
  const answer = await prompt("\nEnter session name (e.g. mybot or your name): ");
  return answer || "default";
}

async function startSession(sessionId, opts = {}) {
  const forceQR = opts.forceQR === true;
  currentSessionId = sessionId;
  activeSessions.add(sessionId);
  const sessionPath = path.join(SESSIONS_DIR, sessionId);
  const { state, saveCreds } = await useMultiFileAuthState(sessionPath);

  // Fetch latest Baileys version for best compatibility
  const { version } = await fetchLatestBaileysVersion();
  console.log(`\n📦 Using Baileys WA version: ${version.join(".")}`);

  let usePairingCode = false;
  let phoneNumber = "";

  if (!state.creds.registered) {
    if (opts.phoneNumberOverride) {
      // ✅ RESTORED FEATURE: number supplied directly by the chat-based
      // .pair flow — skip QR/terminal/web-UI resolution entirely.
      usePairingCode = true;
      phoneNumber = opts.phoneNumberOverride;
      console.log(`📱 [${sessionId}] Using phone number from chat-based .pair request: ${phoneNumber}`);
    } else if (forceQR) {
      // QR mode — don't request pairing code, let Baileys generate QR naturally
      usePairingCode = false;
      console.log(`📷 [${sessionId}] QR mode — waiting for QR from Baileys...`);
      pairingPending = true;
    } else if (PAIRING_NUMBER_ENV) {
      usePairingCode = true;
      phoneNumber = PAIRING_NUMBER_ENV;
      console.log(`🔢 Using pairing code linking for ${phoneNumber} (from PAIRING_NUMBER env var.)`);
    } else if (IS_INTERACTIVE) {
      const method = await askLinkingMethod();
      if (method === "2") {
        usePairingCode = true;
        phoneNumber = await askPhoneNumber();
      }
    } else {
      // No TTY — use web UI for pairing code
      console.log(`🌐 No terminal detected. Open /pair in browser to link your number.`);
      usePairingCode = true;
      phoneNumber = await new Promise((resolve) => {
        pendingPairResolves[sessionId] = resolve;
        pendingPairResolve = resolve;
        console.log(`⏳ [${sessionId}] Waiting for number from web UI at /pair ...`);
      });
      delete pendingPairResolves[sessionId];
      pendingPairResolve = null;
      console.log(`📱 Got number from web UI: ${phoneNumber}`);
    }
  }

  let msgCount = 0;
  // ✅ NEW: connection watchdog state — see the setInterval further down
  // for why this exists (long-idle "zombie" socket recovery).
  let lastConfirmedAliveAt = Date.now();

  // ── Device fingerprint (was bundled in the anti-ban lib but never wired
  // in) ────────────────────────────────────────────────────────────────
  // Every real WhatsApp device reports a consistent (browser, OS, app
  // version) triple. Previously every session used the exact same fixed
  // string here, which is itself a pattern WhatsApp's fleet-detection can
  // key on across many numbers. This derives a fingerprint that's random
  // PER SESSION but stable ACROSS RESTARTS (seeded off sessionId), so each
  // number looks like a distinct real device instead of a Henry-Bots clone.
  // Set ANTIBAN_DEVICE_FINGERPRINT=false to fall back to the old fixed
  // browser string if you ever need to A/B this.
  let socketConfig = {
    version,
    auth: state,
    printQRInTerminal: false, // handled manually below
    logger,
    markOnlineOnConnect: true,
    generateHighQualityLinkPreview: true,
    // Helps avoid bans — don't look like web browser
    // ✅ Changed from "Chrome" to "Safari" per Henry's request. This is
    // purely the label WhatsApp shows for the linked device (Settings →
    // Linked Devices) — doesn't require Safari to actually exist on
    // Ubuntu, Browsers.ubuntu() just takes any string as the display name.
    browser: Browsers.ubuntu("Safari")
  };

  if (process.env.ANTIBAN_DEVICE_FINGERPRINT !== "false") {
    try {
      const fingerprint = generateFingerprint({ seed: sessionId });
      socketConfig = applyFingerprint(socketConfig, fingerprint);
    } catch (e) {
      console.warn(`⚠️  [${sessionId}] Device fingerprint generation failed, using default browser string: ${e.message}`);
    }
  }

  if (antibanProxyRotator) {
    try {
      const agent = antibanProxyRotator.currentAgent();
      if (agent) socketConfig.agent = agent;
    } catch (e) {
      console.warn(`⚠️  [${sessionId}] Proxy agent unavailable, connecting directly: ${e.message}`);
    }
  }

  let socket = makeWASocket(socketConfig);

  // ── Anti-ban wrap ──────────────────────────────────────────────────────
  // Every session gets its own AntiBan instance + persisted warm-up/rate
  // state (survives restarts) so a fresh redeploy doesn't reset a number
  // back to "day 1" sending limits. State lives next to that session's
  // auth files: sessions/<sessionId>/antiban/
  const antibanStateAdapter = new FileStateAdapter(path.join(sessionPath, "antiban"));
  let antibanWarmupState = null;
  try {
    const savedState = await antibanStateAdapter.load("warmup");
    if (savedState) antibanWarmupState = savedState;
  } catch (e) {
    console.warn(`⚠️  [${sessionId}] Could not load saved anti-ban warm-up state: ${e.message}`);
  }

  const resolvedPreset = resolveConfig(process.env.ANTIBAN_PRESET || "moderate");

  // NOTE on the shape below: AntiBan's constructor only turns on
  // jidCanonicalizer / lidResolver / sessionStability / topologyThrottler
  // when it sees their *legacy nested* keys (jidCanonicalizer: {...} etc.)
  // at the top level of this config object — that's the only thing that
  // flips it into "legacy passthrough" mode. But that mode also re-derives
  // the flat rate-limit fields from nested `rateLimiter` / `warmUp` blocks
  // instead of a `preset` name, and silently falls back to the
  // "conservative" preset for anything it can't find. So we mirror every
  // field of the resolved preset back into the nested shape here — this
  // keeps the exact same rate limits as ANTIBAN_PRESET while also
  // unlocking the modules below. (Confirmed against presets.js — this is
  // every field PRESETS.* defines, nothing is silently dropped.)
  const antibanConfig = {
    rateLimiter: {
      maxPerMinute: resolvedPreset.maxPerMinute,
      maxPerHour: resolvedPreset.maxPerHour,
      maxPerDay: resolvedPreset.maxPerDay,
      minDelayMs: resolvedPreset.minDelayMs,
      maxDelayMs: resolvedPreset.maxDelayMs,
      newChatDelayMs: resolvedPreset.newChatDelayMs
    },
    warmUp: {
      warmUpDays: resolvedPreset.warmupDays,
      day1Limit: resolvedPreset.day1Limit,
      growthFactor: resolvedPreset.growthFactor
    },
    maxIdenticalMessages: resolvedPreset.maxIdenticalMessages,
    identicalMessageWindowMs: resolvedPreset.identicalMessageWindowMs,
    burstAllowance: resolvedPreset.burstAllowance,
    inactivityThresholdHours: resolvedPreset.inactivityThresholdHours,
    autoPauseAt: resolvedPreset.autoPauseAt,
    groupMultiplier: resolvedPreset.groupMultiplier,
    groupProfiles: resolvedPreset.groupProfiles,
    stateAdapter: antibanStateAdapter,
    logging: false, // we do our own console logging below

    // ── Owner exemption + notify-only mode ───────────────────────────────
    // Fixes: owner's own .menu/.command replies were getting hard-blocked
    // by the topology/reply-ratio heuristics on a fresh session (0% reply
    // ratio on self-chat — nothing to divide by yet). Owner's JID is now
    // ALWAYS exempt from every per-contact risk block below. For every
    // other contact, instead of failing the send outright, the bot lets
    // it through and pings the owner on WhatsApp with a disclaimer (via
    // logActivity's existing 'error' category, which already DMs the
    // owner — see wrapper.js's notifyOwner handling). Set
    // ANTIBAN_NOTIFY_ONLY=false to restore the old hard-block behavior.
    ownerJid: `${getOwnerNumber()}@s.whatsapp.net`,
    // ✅ NEW: this session's OWN number, re-checked live (socket.user isn't
    // populated yet at this point — only once "connection open" fires) —
    // exempts view-once/antidelete self-forwards from every ban-risk check
    // in the antiban library, the same way ownerJid already exempts the
    // global admin number. See antiban.js's _isSelf() for why this needed
    // to be separate from ownerJid: on any session other than the one
    // paired to the global OWNER_NUMBER, self-forwards were being treated
    // as a risky send to a stranger instead of a message to yourself.
    selfJid: () => socket.user?.id?.replace(/:.*@/, "@") || null,
    // Live switch, re-checked on every send — not frozen at socket-creation
    // time. Admin Panel → Features → "Send Anyway During Ban-Recovery
    // Pause" writes to the `antiban_notify_only` feature row; featureCache
    // refreshes from it every 30s (see refreshFeatures above). If the panel
    // has never set it, fall back to the ANTIBAN_NOTIFY_ONLY env var,
    // defaulting to strict/safe (blocks sends during a pause) rather than
    // silently trading away real ban protection.
    notifyOnlyMode: () => {
      if (Object.prototype.hasOwnProperty.call(featureCache, 'antiban_notify_only')) {
        return featureCache['antiban_notify_only'] === true;
      }
      return (process.env.ANTIBAN_NOTIFY_ONLY || "false") === "true";
    },
    // BUG FIX: the `socket.antiban.on?.("healthChange", ...)` listener further
    // below has never actually fired — AntiBan is a plain class, it doesn't
    // implement `.on()`, so that call was a silent no-op (optional chaining
    // swallowed it). The real hook the library supports is this `onRiskChange`
    // config callback, wired below to do the same console-log + owner-DM +
    // webhook-alert work the dead listener was meant to do. Left the old
    // listener in place (harmless no-op) rather than deleting it.
    onRiskChange: (status) => {
      console.log(`🩺 [${sessionId}] Anti-ban health: ${status.risk?.toUpperCase?.() || status.risk}`);
      if (status.risk === "high" || status.risk === "critical") {
        const ownerJid = `${getOwnerNumber()}@s.whatsapp.net`;
        // Raw send on purpose — this is a system alert about the send
        // pipeline's own health, not outbound bot traffic. Routing it
        // through the antiban-wrapped sendMessage risked the same kind of
        // self-feeding loop fixed in logActivity (an alert that itself
        // gets flagged, alerting again, forever).
        const send = socket?.sendMessageRaw || socket?.sendMessage;
        send?.(ownerJid, {
          text: `⚠️ *Anti-ban warning* [${sessionId}]\nRisk level: *${String(status.risk).toUpperCase()}*\n${status.recommendation || "Check .antibanstats for details."}`
        }).catch(() => {});
      }
      if (antibanWebhooks) {
        antibanWebhooks.alert({
          risk: status.risk,
          score: status.score ?? 0,
          recommendation: status.recommendation || `Session [${sessionId}] risk level: ${status.risk}`,
          reasons: status.reasons || []
        }).catch(() => {});
      }
    },

    // ── Newly unlocked (previously bundled but never enabled) ───────────
    // Canonicalizes @lid / @s.whatsapp.net JID variants so rate-limit and
    // warm-up counters aren't fooled into treating one contact as two.
    jidCanonicalizer: { enabled: true },
    lidResolver: {},
    // Tracks Bad-MAC / session-decrypt error rates and flags a session as
    // degraded before it spirals into a full logout. Fed from the
    // messages.update listener below.
    sessionStability: { enabled: true },
    // Extra throttle specifically on *new* contacts (separate from the
    // general rate limiter) since spam reports mostly come from strangers.
    topologyThrottler: { maxNewContactsPerHour: 8, maxNewContactsPerDay: 30 }
  };

  // ✅ NEW: antiban on/off toggle, actually enforced (was previously just DB
  // columns nobody read). Protection only applies when BOTH the global
  // 'antiban_enabled' feature flag AND this session's own antiban_enabled
  // column are on (both default ON, so this changes nothing unless an
  // admin deliberately flips one off from the Admin Panel).
  let antibanOn = true;
  try {
    const [globalRes, sessionRes] = await Promise.all([
      apiClient.get("/bot/features").catch(() => null),
      apiClient.get("/admin/session-antiban", { params: { session: sessionId } }).catch(() => null),
    ]);
    const globalOn = globalRes?.data?.antiban_enabled !== false;
    const sessionOn = sessionRes?.data?.antiban_enabled !== false;
    antibanOn = globalOn && sessionOn;
  } catch (_) { /* fail open — never let a check failure strip protection */ }

  if (antibanOn) {
    socket = wrapSocket(socket, antibanConfig, antibanWarmupState, {
    // Adds human-like typos/typing pauses/read gaps to outgoing sends.
    // Disabled: was corrupting structured command/menu replies (e.g. .pair
    // flow sending "QR Cide" then a "*Code" correction 0.5-2s later) and
    // adding up to 60-minute silent read-gaps before ANY reply went out.
    // Bot menu/command output isn't casual chat, so human-typo mimicry
    // doesn't apply here — real anti-ban protection (rate limits, warm-up,
    // fingerprinting) is untouched by this change.
    legitimacySignals: false,
    // Rate-limits group add/remove/create operations
    groupOpGuard: true,
    // Detects a socket that looks "connected" but has stopped delivering
    // messages (Baileys issue #2491) and force-reconnects it
    deafSession: { deafThresholdMs: 5 * 60 * 1000 }
    });
  } else {
    console.log(`🔕 [${sessionId}] Anti-ban protection is OFF (global or per-session toggle) — running unwrapped.`);
  }

  // ── Read-receipt variance (was bundled, never wired in) ────────────────
  // Wraps sock.readMessages with a small human-like random delay instead
  // of marking messages read instantly, every time, forever.
  try {
    socket = readReceiptVariance().wrap(socket);
  } catch (e) {
    console.warn(`⚠️  [${sessionId}] Read-receipt variance wrap failed (non-fatal): ${e.message}`);
  }

  // ── Session decrypt-health feed ─────────────────────────────────────────
  // sessionStability (enabled above) needs to be told about decrypt
  // successes/failures — it doesn't listen for these itself. A failed
  // decrypt on the other end shows up here as a message-status error with
  // a Signal/MAC retry-reason code, exactly like retryTracker already
  // detects internally; a normal inbound message is treated as a success
  // signal.
  socket.ev.on("messages.update", (updates) => {
    const monitor = socket.antiban?.sessionStability;
    if (!monitor) return;
    for (const update of updates) {
      if (update.status !== 0 && !update.error) continue;
      const reason = parseRetryReason(update.error || update.update || update);
      monitor.recordDecryptFail(isMacError(reason));
    }
  });
  socket.ev.on("messages.upsert", () => {
    socket.antiban?.sessionStability?.recordDecryptSuccess?.();
  });

  // ✅ NEW (extended-commands update): .antidelete — a separate, additive
  // listener (doesn't touch the two above). Detects a WhatsApp message
  // revocation (protocolMessage type REVOKE) and, only for chats that have
  // explicitly run *.antidelete on*, reposts the cached copy of whatever
  // was deleted. Falls through silently for everyone else — the existing
  // manual 🌝-reaction recovery path is untouched and keeps working
  // regardless of this toggle.
  socket.ev.on("messages.upsert", async (chatUpdate) => {
    try {
      const m = chatUpdate.messages?.[0];
      const proto = m?.message?.protocolMessage;
      if (!proto || proto.type !== 0 /* REVOKE */) return; // 0 === proto.Message.ProtocolMessage.Type.REVOKE
      const deletedId = proto.key?.id;
      const chatId = m.key.remoteJid;
      if (!deletedId || !chatId) return;

      const adSetting = await apiClient.get("/chat-settings/get", { params: { chat_id: chatId, key: "antidelete" } });
      if (adSetting?.data?.value !== "on") return;

      const cached = global.recentMsgCache.get(deletedId);
      if (!cached) return;

      // ✅ FIX: some groups are announcement-only (admins-post-only) — the
      // whole point of that setting is that regular members don't post
      // there. Reposting a recovered deleted message INTO that group would
      // either silently fail (bot isn't an admin) or go against the
      // group's own "no chatter" culture even when it does work. In a
      // restricted group, send the recovery privately to this session's
      // own number instead, tagged with which group it came from — same
      // "private to the number running it, not back into the chat" rule
      // the view-once recovery above already follows.
      let destination = chatId;
      let restrictedNote = "";
      const isGroupChat = chatId.endsWith("@g.us");
      if (isGroupChat) {
        try {
          const groupMeta = await socket.groupMetadata(chatId);
          if (groupMeta?.announce) {
            destination = socket.user?.id?.replace(/:.*@/, "@") || chatId;
            restrictedNote = `\n📍 (from *${groupMeta.subject || "a restricted group"}* — admins-only chat, sent here privately instead)`;
          }
        } catch (_) { /* if metadata lookup fails, fall back to posting in-chat as before */ }
      }

      const who = cached.senderJid ? `+${cached.senderJid.split("@")[0]}` : "someone";
      const text = cached.msg?.message?.conversation
        || cached.msg?.message?.extendedTextMessage?.text
        || null;

      // ✅ CHANGED (cosmetic only, per request): dropped the "🗑️ Antidelete"
      // stamp/branding — this still goes ONLY to your own private chat,
      // exactly as before, just without a big label announcing it's a
      // recovered item. A light, small attribution line stays (who + which
      // chat) since that context is genuinely useful and isn't a privacy
      // concern in a chat only you see.
      if (cached.viewOnceBuffer) {
        const caption = `${who}${restrictedNote}`;
        if (cached.viewOnceMediaType === "imageMessage") {
          await socket.sendMessage(destination, { image: cached.viewOnceBuffer, caption });
        } else if (cached.viewOnceMediaType === "videoMessage") {
          await socket.sendMessage(destination, { video: cached.viewOnceBuffer, caption });
        }
      } else if (text) {
        await socket.sendMessage(destination, { text: `${who}: "${text}"${restrictedNote}` });
      }
      // No cached media/text (cache expired or message predates the cache
      // window) — nothing we can recover, so stay silent rather than send
      // an empty "something was deleted" ping.
    } catch (_) { /* antidelete is best-effort, never throw into Baileys' event loop */ }
  });

  // ── creds.json snapshotting (was bundled, never wired in) ──────────────
  // Keeps rolling backups of creds.json next to the session's antiban
  // state, so a corrupted/truncated write (crash mid-save on Render,
  // Termux storage hiccup, etc.) can be recovered from with
  // .credsrestore instead of forcing a full re-pair.
  const credsSnapshotter = credsSnapshot({
    credsPath: path.join(sessionPath, "creds.json"),
    snapshotDir: path.join(sessionPath, "antiban", "creds-backups"),
    keep: 5,
    logger: {
      warn: (m) => console.warn(`⚠️  [${sessionId}] ${m}`),
      error: (m) => console.error(`❌ [${sessionId}] ${m}`)
    }
  });
  socket.antiban && (socket.antiban.credsSnapshotter = credsSnapshotter);
  // Debounced snapshot on every creds.update — creds.json itself is already
  // saved by saveCreds (registered separately below); this just keeps a
  // rolling history of known-good copies to fall back to.
  let credsSnapshotTimer = null;
  socket.ev.on("creds.update", () => {
    clearTimeout(credsSnapshotTimer);
    credsSnapshotTimer = setTimeout(() => {
      credsSnapshotter.take().catch(() => {});
    }, 5000);
  });

  // Persist warm-up/rate-limiter state every 2 minutes and on disconnect,
  // so restarts (Render/Railway redeploys, crashes) don't lose progress.
  // Also pushes current health/warm-up to the admin panel, so a session
  // that's connected but quiet (no inbound messages) doesn't show stale
  // anti-ban info there.
  const antibanSaveInterval = setInterval(() => {
    socket.antiban?.saveState?.().catch(() => {});
    const abStats = socket.antiban?.getStats?.();
    if (abStats) {
      apiClient.post("/admin/update-session", {
        name: sessionId,
        antiban_risk: abStats.health?.risk,
        antiban_warmup_day: abStats.warmup?.currentDay,
        antiban_warmup_total: abStats.warmup?.totalDays
      }).catch(() => {});
    }
  }, 2 * 60 * 1000);
  antibanSaveInterval.unref?.();

  // ✅ NEW: connection watchdog — fixes the "comes back after a long idle
  // period showing stale 'last active' and just doesn't respond anymore,
  // forced to re-pair" bug. Baileys' own internal keep-alive can leave a
  // socket in a "zombie" state after a long enough idle stretch — this is
  // especially common on Render's free tier, where the whole Node process
  // (and every timer in it) is frozen solid while the service is asleep;
  // when a request wakes it back up, Baileys' internal keep-alive
  // bookkeeping can be left inconsistent, and the close event that would
  // normally trigger the existing reconnect logic above never fires. The
  // socket LOOKS connected (SESSION_REGISTRY still says online) but is
  // actually dead — nothing gets processed until someone notices and
  // manually terminates + re-pairs.
  //
  // Fix: every 3 minutes, if there's been no genuine inbound traffic for
  // 6+ minutes, actively probe the connection with a lightweight
  // presence update (touches nothing customer-facing, sends to no one).
  // If that probe doesn't complete within 10s, or throws, the socket is
  // almost certainly dead — force-close it so Baileys' own "connection
  // close" handler (already wired above) takes over and reconnects
  // exactly like it would for any other disconnect.
  const WATCHDOG_IDLE_THRESHOLD_MS = 6 * 60 * 1000;
  const WATCHDOG_PROBE_TIMEOUT_MS = 10 * 1000;
  const connectionWatchdog = setInterval(async () => {
    if (Date.now() - lastConfirmedAliveAt < WATCHDOG_IDLE_THRESHOLD_MS) return;
    try {
      await Promise.race([
        socket.sendPresenceUpdate('available'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('watchdog probe timeout')), WATCHDOG_PROBE_TIMEOUT_MS)),
      ]);
      // Probe succeeded — socket is genuinely alive, just quiet. Reset the
      // clock so we don't probe again for another full idle window.
      lastConfirmedAliveAt = Date.now();
    } catch (e) {
      console.warn(`⚠️  [${sessionId}] Watchdog: connection looks dead after ${Math.round((Date.now() - lastConfirmedAliveAt) / 60000)}min idle (${e.message}) — forcing reconnect.`);
      try { socket.end(new Error('watchdog: stale/zombie connection, forcing reconnect')); } catch (_) {}
    }
  }, 3 * 60 * 1000);
  connectionWatchdog.unref?.();

  // Surface health-monitor risk escalation to console + owner DM so Henry
  // gets an early warning before a real ban, not after.
  // NOTE: this never actually ran (AntiBan has no .on() — optional chaining
  // silently no-op'd it). Real wiring is the `onRiskChange` callback passed
  // into antibanConfig above. Left this here rather than deleting it.
  socket.antiban.on?.("healthChange", (health) => {
    console.log(`🩺 [${sessionId}] Anti-ban health: ${health.risk?.toUpperCase?.() || health.risk}`);
    if (health.risk === "high" || health.risk === "critical") {
      const ownerJid = `${getOwnerNumber()}@s.whatsapp.net`;
      socket.sendMessage(ownerJid, {
        text: `⚠️ *Anti-ban warning* [${sessionId}]\nRisk level: *${String(health.risk).toUpperCase()}*\nSending has been auto-throttled to protect this number. Check .antibanstats for details.`
      }).catch(() => {});
    }
    if (antibanWebhooks) {
      antibanWebhooks.alert({
        risk: health.risk,
        score: health.score ?? 0,
        recommendation: health.recommendation || `Session [${sessionId}] risk level: ${health.risk}`,
        reasons: health.reasons || []
      }).catch(() => {});
    }
  });

  // ✅ FIX (OTP reliability/speed): socket used to be registered here, before
  // it's authenticated/connected — a half-open or reconnecting socket has no
  // socket.user yet, so sendMessage() would throw deep inside Baileys
  // ("Cannot read properties of undefined (reading 'id')"). That crash only
  // surfaced once the OTP request was already in flight, making failures
  // slow AND confusing. Now we only mark it active once connection is
  // actually "open" (below) and immediately drop it on close, so a bad
  // session fails fast with a clean error instead of a stack trace.

  // Pairing code generation
  if (usePairingCode && !state.creds.registered) {
    await delay(3000); // Wait for socket to initialize
    try {
      const code = await socket.requestPairingCode(phoneNumber);
      console.log("\n╔══════════════════════════════════════╗");
      console.log(`   🔑 PAIRING CODE: ${code.match(/.{1,4}/g).join("-")}  `);
        lastPairingCode = code.match(/.{1,4}/g).join("-");
      pairingPending = false;  // code is ready
      // ✅ RESTORED FEATURE: hand the code back to a chat-based .pair
      // request too, if one is waiting on this sessionId.
      chatPairResolvers[sessionId]?.resolveCode?.(lastPairingCode);
      console.log("╚══════════════════════════════════════╝");
      console.log("\n📱 Steps:");
      console.log("1. Open WhatsApp");
      console.log("2. Go to Linked Devices");
      console.log("3. Tap Link a Device");
      console.log("4. Tap 'Link with phone number instead'");
      console.log("5. Enter the code above\n");
    } catch (e) {
      console.error("❌ Pairing code error:", e.message);
      console.log("💡 Try method 1 (QR Code) instead, or check your phone number.");
    }
  }

  socket.ev.on("creds.update", saveCreds);

  // Feature: Anti-Call
  socket.ev.on("call", async (inboundCall) => {
    for (const call of inboundCall) {
      if (call.status === "offer") {
        try {
          await socket.rejectCall(call.id, call.from);
          console.log(`🚫 [${sessionId}] AntiCall: rejected call from ${call.from}`);
        } catch (e) {
          console.error("❌ AntiCall error:", e.message);
        }
      }
    }
  });

  // ✅ FIX (Update 17): group-participants.update was never listened to
  // anywhere in the codebase, so .goodbye (and the new .welcomecfg) had
  // working commands and storage but no trigger — nothing ever fired
  // automatically on an actual join/leave. Required directly by file path
  // rather than pulled from allCommands, since both handlers are stripped
  // out of the command table by NON_COMMAND_KEYS above.
  socket.ev.on("group-participants.update", async (update) => {
    try {
      const { _handleJoinEvent, _handleLeaveEvent } = require('./plugins/ported_admin.js');
      if (update.action === 'add') {
        await _handleJoinEvent(socket, update.id, update.participants);
      } else if (update.action === 'remove') {
        await _handleLeaveEvent(socket, update.id, update.participants);
      }
    } catch (e) {
      console.error('❌ group-participants.update handler error:', e.message);
    }
  });

  socket.ev.on("messages.upsert", async (chatUpdate) => {
    try {
      const msg = chatUpdate.messages[0];
      if (!msg || !msg.message) return;

      const sender = msg.key.remoteJid;
      if (!sender) return;

      // ✅ NEW (Update 15): live-read prefix/botname for this message instead
      // of a frozen startup constant — see getPrefix()/getBotName() above.
      const CMD_PREFIX = getPrefix();
      const BOT_NAME = getBotName();

      const isStatus = sender === "status@broadcast";
      const name = msg.pushName || "User";
      const msgId = msg.key.id;

      // Extract message body from all common message types
      const body =
        msg.message?.conversation ||
        msg.message?.extendedTextMessage?.text ||
        msg.message?.imageMessage?.caption ||
        msg.message?.videoMessage?.caption ||
        msg.message?.buttonsResponseMessage?.selectedButtonId ||
        msg.message?.listResponseMessage?.singleSelectReply?.selectedRowId ||
        "";

      // Feature: Auto View & Like Status + AI comment on status
      if (isStatus) {
        try {
          const settingsExt = require('./plugins/settings-ext.js');
          if (settingsExt.__getSetting('autoreadstatus')) {
            await socket.readMessages([msg.key]);
          }
          if (settingsExt.__getSetting('autolikestatus')) {
            await socket.sendMessage(
              sender,
              { react: { text: "❤️", key: msg.key } },
              { statusJidList: [msg.key.participant || sender] }
            );
          }

          // NEW: Auto-save status media to disk before it expires in 24h
          if (isFeatureOn("status_save")) {
            try {
              const statusMediaType = msg.message?.imageMessage ? "imageMessage"
                : msg.message?.videoMessage ? "videoMessage" : null;
              if (statusMediaType) {
                const buffer = await downloadMediaMessage(msg, "buffer", {}, { logger, reuploadRequest: socket.updateMediaMessage });
                const mediaDir = path.join(__dirname, "status_media");
                if (!fs.existsSync(mediaDir)) fs.mkdirSync(mediaDir, { recursive: true });
                const ext = statusMediaType === "imageMessage" ? "jpg" : "mp4";
                const who = (msg.key.participant || sender).split("@")[0];
                const filename = `${who}_${Date.now()}.${ext}`;
                fs.writeFileSync(path.join(mediaDir, filename), buffer);
                apiClient.post("/log-status", {
                  sender: msg.key.participant || sender,
                  name,
                  filename,
                  mediaType: statusMediaType,
                  caption: body || "",
                  timestamp: Date.now()
                }).catch(() => {});
              }
            } catch (_) { /* media download can fail on expired/protected statuses, skip silently */ }
          }
          // ✅ NEW: AI comment reply on text statuses (human-like)
          if (body && global.botActive !== false && settingsExt.__getSetting('autoreplystatus')) {
            try {
              const statusName = msg.pushName || 'rafiki';
              const aiReply = await apiClient.post('/natural-chat', {
                body: `Mtu amepost status WhatsApp akisema: "${body}". Jibu kwa comment fupi ya kirafiki kama vile umeona status yao.`,
                name: statusName,
                context: 'status'
              });
              if (aiReply?.data?.reply) {
                await delay(Math.floor(Math.random() * 3000) + 2000);
                await socket.sendMessage(
                  sender,
                  { text: aiReply.data.reply },
                  { statusJidList: [msg.key.participant || sender] }
                );
              }
            } catch (_) {}
          }
        } catch (e) {}
        return;
      }

      // ── Sender & role detection ──────────────────────────────────────────────
      const isGroup     = sender.endsWith('@g.us');
      const senderJid   = isGroup
        ? (msg.key.participant || sender)
        : msg.key.fromMe
          ? (socket.user?.id || sender)
          : sender;
      const senderNumber = senderJid.split('@')[0].replace(/:\d+$/, '');
      const currentOwnerNumber = getOwnerNumber();
      const isPrimaryOwner = Boolean(currentOwnerNumber && senderNumber === currentOwnerNumber);
      const isCoOwner    = global.coOwners.has(senderNumber);
      const isOwner      = isPrimaryOwner || isCoOwner;  // co-owners get owner powers
      const isSubAdmin   = global.subAdmins.has(senderNumber);
      const isBotAdmin   = isOwner || isSubAdmin;
      // ✅ NEW: is THIS SESSION the owner's own personal WhatsApp number
      // (not "is the sender the owner" — isPrimaryOwner already covers
      // that). Used to scope the personal auto-reply features below to
      // Henry's own number only, never a customer's session.
      const botNumber = (socket.user?.id || "").split(':')[0].split('@')[0];
      const isThisOwnerSession = Boolean(botNumber && currentOwnerNumber && botNumber === currentOwnerNumber);

      // ── ✅ NEW (Update 15): PM Permit — .setpmpermit on/off was saving but
      // doing nothing. When ON, a non-admin DMing for the first time gets a
      // one-time "ask for permission" notice and nothing else runs for them
      // (no AI reply, no commands) until a bot admin approves them with
      // `.pmpermitapprove <number>`. Bot admins are always exempt. Groups
      // and status broadcasts are unaffected — this is DMs only.
      if (!isGroup && !isBotAdmin) {
        try {
          const settingsExtPm = require('./plugins/settings-ext.js');
          if (settingsExtPm.__getSetting('pmpermit') && !settingsExtPm.__isPmApproved(senderNumber)) {
            const strikeCount = settingsExtPm.__bumpPmStrike(senderNumber);
            // ✅ NEW: .setautoblock on/off — only ever acts on senders who are
            // already failing the pmpermit gate above (never blocks anyone
            // pmpermit itself would let through), and only after repeated
            // attempts, so a single stray message never gets someone blocked.
            if (settingsExtPm.__getSetting('autoblock') && strikeCount > 3) {
              try { await socket.updateBlockStatus(sender, "block"); } catch (_) {}
              try {
                const ownerJidForAlert = currentOwnerNumber ? `${currentOwnerNumber}@s.whatsapp.net` : null;
                if (ownerJidForAlert) {
                  await socket.sendMessage(ownerJidForAlert, { text: `🚫 Auto-blocked ${senderNumber} after ${strikeCount} unapproved DM attempts (PM Permit is ON).` });
                }
              } catch (_) {}
              return;
            }
            if (strikeCount === 1) {
              try {
                await socket.sendMessage(sender, { text: `🔒 The owner requires permission before chatting. Your request has been noted — please wait to be approved.` }, { quoted: msg });
              } catch (_) {}
            }
            return;
          }
        } catch (_) {}
      }

      // ── 🌝 Cache this message in case it's reacted to later (view-once
      // recovery, or recovering a message after it gets deleted) ───────────
      if (!msg.message?.reactionMessage && !msg.message?.protocolMessage) {
        cacheRecentMessage(msgId, { msg, sender, name, senderJid });
      }

      // ✅ NEW (extended-commands update): passive group-intel logging.
      // Fire-and-forget, never blocks/breaks the existing flow above or
      // below. Powers .activity/.active/.topics/.influence/.track/
      // .detector/.analyze in plugins/extended.js.
      if (isGroup && body && !msg.message?.reactionMessage && !msg.message?.protocolMessage) {
        apiClient.post("/group-intel/log", {
          group_id: sender, sender: senderJid, name, body, timestamp: Date.now() / 1000
        }).catch(() => {});
      }

      // ── 🌝 Reaction-triggered recovery — react with 🌝 on a view-once or
      // any message to have it privately forwarded to the bot's own number.
      // Bot-admin only (owner / co-owner / sub-admin) so randoms in a group
      // can't go fishing for other people's deleted/view-once content.
      const reactionMsg = msg.message?.reactionMessage;
      if (reactionMsg && reactionMsg.text === "🌝") {
        if (!isBotAdmin) {
          // Silently ignore — don't tip off non-admins that this exists.
          return;
        }
        try {
          const targetId = reactionMsg.key?.id;
          const cached = targetId ? global.recentMsgCache.get(targetId) : null;
          const selfJid = socket.user?.id?.replace(/:.*@/, "@");

          if (!cached || !selfJid) {
            await socket.sendMessage(sender, { text: "🌝 Couldn't find that message anymore (too old or never cached)." }, { quoted: msg });
            return;
          }

          const targetMsg = cached.msg;
          const viewOnceMsg =
            targetMsg.message?.viewOnceMessage?.message ||
            targetMsg.message?.viewOnceMessageV2?.message ||
            targetMsg.message?.viewOnceMessageV2Extension?.message;
          const innerMessage = viewOnceMsg || targetMsg.message;
          const mediaType = cached.viewOnceMediaType ||
            (innerMessage?.imageMessage ? "imageMessage" :
            innerMessage?.videoMessage ? "videoMessage" :
            innerMessage?.audioMessage ? "audioMessage" : null);

          // ✅ CHANGED (cosmetic only, per request): dropped the "🌝
          // Recovered via reaction" stamp/branding — still goes ONLY to
          // your own private chat exactly as before, just reads like a
          // normal forwarded message instead of an announced "recovery."
          const headerText = `👤 ${cached.name} (${cached.sender.split("@")[0]})`;

          if (mediaType) {
            // Reuse the already-downloaded buffer if we have one cached
            // (e.g. view-once media, which often can't be re-fetched).
            const buffer = cached.viewOnceBuffer || await downloadMediaMessage(
              { key: targetMsg.key, message: innerMessage }, "buffer", {}, { logger, reuploadRequest: socket.updateMediaMessage }
            );
            const caption = innerMessage[mediaType]?.caption ? `\n${innerMessage[mediaType].caption}` : "";
            await socket.sendMessage(selfJid, { text: headerText });
            if (mediaType === "imageMessage") {
              await socket.sendMessage(selfJid, { image: buffer, caption: caption.trim() });
            } else if (mediaType === "videoMessage") {
              await socket.sendMessage(selfJid, { video: buffer, caption: caption.trim() });
            } else {
              await socket.sendMessage(selfJid, {
                audio: buffer,
                mimetype: innerMessage[mediaType]?.mimetype || "audio/ogg; codecs=opus",
                ptt: true
              });
            }
          } else {
            const text =
              targetMsg.message?.conversation ||
              targetMsg.message?.extendedTextMessage?.text ||
              "(no text content found)";
            await socket.sendMessage(selfJid, { text: `${headerText}\n\n${text}` });
          }

          // Only confirm in the original chat if it's not already the bot's own DM.
          if (sender !== selfJid) {
            await socket.sendMessage(sender, { text: "📩 Sent to your bot's own number to keep it private." }, { quoted: msg });
          }
        } catch (e) {
          console.error(`❌ [${sessionId}] 🌝 reaction recovery failed:`, e.message);
          try { await socket.sendMessage(sender, { text: `❌ Couldn't recover that: ${e.message}` }, { quoted: msg }); } catch (_) {}
        }
        return;
      }

      // ── NEW: Anti-link — delete link messages from non-admins, warn, kick at 3 ──
      if (isGroup && !isBotAdmin && body && isFeatureOn("antilink")) {
        const hasLink = /(https?:\/\/|chat\.whatsapp\.com|wa\.me\/)\S+/i.test(body);
        if (hasLink) {
          try { await socket.sendMessage(sender, { delete: msg.key }); } catch (_) {}
          try {
            const strikeRes = await apiClient.post("/antilink/strike", { group_id: sender, sender: senderJid });
            const { count = 1, kick = false } = strikeRes.data || {};
            if (kick) {
              try {
                await socket.groupParticipantsUpdate(sender, [senderJid], "remove");
                await socket.sendMessage(sender, { text: `🚫 @${senderNumber} removed — 3 link warnings reached.`, mentions: [senderJid] });
              } catch (_) {
                await socket.sendMessage(sender, { text: `⚠️ @${senderNumber} hit 3 link warnings but I couldn't remove them (need admin rights).`, mentions: [senderJid] });
              }
            } else {
              await socket.sendMessage(sender, { text: `⚠️ @${senderNumber} no links allowed here. Warning ${count}/3.`, mentions: [senderJid] });
            }
          } catch (_) {}
          return; // don't process this message any further
        }
      }

      // ── fromMe guard — allow owner commands even from the bot number ──────
      if (msg.key.fromMe && !body.startsWith(CMD_PREFIX)) {
        // ✅ NEW: on Henry's own number only, remember that he personally
        // replied in this chat just now — the personal auto-reply below
        // (further down) checks this before ever stepping in, so it never
        // talks over him while he's actively chatting.
        if (isThisOwnerSession && !isGroup) {
          apiClient.post("/chat-settings/set", { chat_id: sender, key: "owner_last_reply_ts", value: String(Date.now() / 1000) }).catch(() => {});
        }
        return;
      }

      // ── Paid Pairing / Activation Key gate ─────────────────────────────────
      // Freshly-paired customer sessions come up locked. The customer has to
      // send ".pair key" (routed to the admin for a yes/no), then redeem the
      // random key it issues with ".key XXXXXX" within 10 minutes. Until
      // that happens, every other command is blocked with a short notice.
      // The admin's own OWNER_NUMBER session is exempt (auto-activated
      // server-side), and the admin can approve/deny with a plain reply.
      if (!isGroup && body) {
        const bodyLower = body.trim().toLowerCase();
        const activation = getActivation(sessionId);

        // ── RESTORED FEATURE: chat-based ".pair" self-service linking ──────
        // Lets ANYONE messaging this bot link their OWN number as a brand
        // new, separate bot session — right here in chat, no website needed.
        // Distinct from ".pair key" below, which requests access to THIS
        // bot instance rather than creating a new one.
        if (chatPairSessions[sender]) {
          const convo = chatPairSessions[sender];

          if (convo.step === "await_method") {
            let method = null;
            if (bodyLower === "1" || bodyLower === "qr" || bodyLower === "qr code") method = "qr";
            else if (bodyLower === "2" || bodyLower === "code" || bodyLower === "pairing code" || bodyLower === "pair code") method = "code";

            if (!method) {
              await socket.sendMessage(sender, { text: `Please reply *1* for QR Code or *2* for Pairing Code.` }, { quoted: msg });
              return;
            }
            convo.method = method;
            convo.step = "await_number";
            convo.lastActivity = Date.now();
            await socket.sendMessage(sender, {
              text: `📱 Send the WhatsApp number you want to link — country code, digits only, no *+* or spaces (e.g. 254712345678).`
            }, { quoted: msg });
            return;
          }

          if (convo.step === "await_number") {
            const digits = body.trim().replace(/[\s\-+]/g, "");
            if (!/^\d{9,15}$/.test(digits)) {
              await socket.sendMessage(sender, { text: `That doesn't look like a valid number. Send it with country code, digits only (e.g. 254712345678).` }, { quoted: msg });
              return;
            }

            const method = convo.method;
            delete chatPairSessions[sender];  // one-shot — this conversation is done either way

            const targetSessionId = `chatpair_${digits}`;
            if (activeSessions.has(targetSessionId)) {
              await socket.sendMessage(sender, { text: `⏳ A pairing session for that number is already in progress. Please wait a moment and send *.pair* again.` }, { quoted: msg });
              return;
            }

            await socket.sendMessage(sender, {
              text: method === "qr" ? `⏳ Generating your QR code, one moment...` : `⏳ Generating your pairing code for ${digits}, one moment...`
            }, { quoted: msg });

            try {
              const result = await new Promise((resolve, reject) => {
                chatPairResolvers[targetSessionId] = {
                  resolveCode: (c) => resolve({ type: "code", value: c }),
                  resolveQR: (q) => resolve({ type: "qr", value: q }),
                };
                startSession(targetSessionId, {
                  forceQR: method === "qr",
                  phoneNumberOverride: method === "code" ? digits : undefined,
                }).catch(reject);
                setTimeout(() => reject(new Error("timed out waiting for WhatsApp")), 60000);
              });

              if (result.type === "code") {
                await socket.sendMessage(sender, {
                  text: result.value
                }, { quoted: msg });
                await socket.sendMessage(sender, {
                  text: `🔑 That's your pairing code — copy it now.\n\n📱 *Steps:*\n1. Open WhatsApp\n2. Go to Linked Devices\n3. Tap *Link a Device*\n4. Tap *Link with phone number instead*\n5. Paste/enter the code from the message above\n\n⏱️ This code expires quickly — enter it right away.`
                });
              } else {
                const base64Data = result.value.split(",")[1];
                await socket.sendMessage(sender, {
                  image: Buffer.from(base64Data, "base64"),
                  caption: `📷 Scan this QR code with WhatsApp:\n\nLinked Devices → Link a Device → Scan this image.\n\n⏱️ This QR expires quickly — scan it right away.`
                }, { quoted: msg });
              }
            } catch (e) {
              await socket.sendMessage(sender, { text: `❌ Couldn't generate your pairing code/QR: ${e.message}. Send *.pair* to try again.` }, { quoted: msg });
              // ✅ Tear down the half-started session so the "already in
              // progress" guard above doesn't permanently block a retry.
              activeSessions.delete(targetSessionId);
              activeSockets.delete(targetSessionId);
              try {
                fs.rmSync(path.join(SESSIONS_DIR, targetSessionId), { recursive: true, force: true });
              } catch (_) {}
            } finally {
              delete chatPairResolvers[targetSessionId];
            }
            return;
          }
        }

        if (bodyLower === ".pair" || bodyLower === "pair") {
          chatPairSessions[sender] = { step: "await_method", lastActivity: Date.now() };
          await socket.sendMessage(sender, {
            text: `🔗 *Link a WhatsApp number as a new bot session*\n\nHow would you like to link?\n\n*1* — QR Code\n*2* — Pairing Code\n\nReply with 1 or 2.`
          }, { quoted: msg });

          // ✅ Send the user guide PDF to everyone EXCEPT the bot owner —
          // owners already know the bot inside out; this is for customers
          // and group members who are new to it.
          if (!isPrimaryOwner) {
            try {
              const fs = require("fs");
              const guidePath = path.join(__dirname, "assets", "BeastBot-User-Guide.pdf");
              const guideBuffer = fs.readFileSync(guidePath);
              await socket.sendMessage(sender, {
                document: guideBuffer,
                fileName: "BeastBot-User-Guide.pdf",
                mimetype: "application/pdf",
                caption: "📄 *Beast Bot User Guide* — everything you need to know to use the bot, in one PDF."
              });
            } catch (e) {
              console.log(`⚠️ Couldn't send user guide PDF to ${sender}: ${e.message}`);
            }
          }

          // ✅ Also send the "What Was Fixed" PDF, to everyone including the
          // owner — unlike the user guide, this documents recent changes to
          // the bot's own behavior, which is relevant regardless of role.
          // Same PDFs are downloadable from the /pair web page too.
          try {
            const fs = require("fs");
            const fixedPath = path.join(__dirname, "assets", "BeastBot-Whats-Fixed.pdf");
            const fixedBuffer = fs.readFileSync(fixedPath);
            await socket.sendMessage(sender, {
              document: fixedBuffer,
              fileName: "BeastBot-Whats-Fixed.pdf",
              mimetype: "application/pdf",
              caption: "🛠️ *What Was Fixed* — a plain-language rundown of recent bot fixes and what changed."
            });
          } catch (e) {
            console.log(`⚠️ Couldn't send fixes PDF to ${sender}: ${e.message}`);
          }
          return;
        }

        // Admin approving/denying a pending request with a plain yes/no,
        // optionally with a day count: "yes", "yes 30", "no".
        // ✅ NEW: any bot admin (owner, co-owner, or sub-admin) can now
        // approve/deny — not just the primary owner. Whoever approves a
        // still-unclaimed session becomes its recorded handler (handled_by),
        // which is what lets a sub-admin later run .extend on that same
        // customer. Primary owner/co-owners remain unrestricted everywhere.
        if (isBotAdmin && activation.pendingRequest) {
          const yesMatch = bodyLower.match(/^(yes|y)(\s+(\d+))?$/);
          const noMatch  = bodyLower.match(/^(no|n)$/);
          if (yesMatch || noMatch) {
            const targetChat = activation.requesterChat;
            if (yesMatch) {
              const days = yesMatch[3] ? parseInt(yesMatch[3], 10) : undefined;
              try {
                const res = await apiClient.post("/admin/activation-approve", { session: sessionId, days, handled_by: senderNumber });
                const { key, days: grantedDays } = res.data || {};
                activation.pendingRequest = false;
                if (key && targetChat) {
                  await socket.sendMessage(targetChat, {
                    text: `🔑 *Access Approved!*\n\nYour activation key: *${key}*\n⏳ Valid for *10 minutes* — send it back as:\n*.key ${key}*\n\n📅 Grants *${grantedDays} day(s)* of access.\n\n📌 *Tip:* save this bot's number to your contacts — it helps avoid the number getting flagged/banned.`
                  });
                }
                await socket.sendMessage(sender, { text: `✅ Key sent (${grantedDays} day${grantedDays === 1 ? '' : 's'}).` }, { quoted: msg });
              } catch (e) {
                await socket.sendMessage(sender, { text: `❌ Couldn't approve: ${e.message}` }, { quoted: msg });
              }
            } else {
              try {
                await apiClient.post("/admin/activation-deny", { session: sessionId });
                activation.pendingRequest = false;
                if (targetChat) {
                  await socket.sendMessage(targetChat, { text: `❌ Your access request was declined. Please message the admin directly to arrange access.` });
                }
                await socket.sendMessage(sender, { text: `🚫 Denied.` }, { quoted: msg });
              } catch (e) {
                await socket.sendMessage(sender, { text: `❌ Couldn't deny: ${e.message}` }, { quoted: msg });
              }
            }
            return;
          }
        }

        // "\".pair key\"" — customer requests activation from the admin.
        if (bodyLower === ".pair key" || bodyLower === "pair key") {
          if (isSessionLive(sessionId)) {
            await socket.sendMessage(sender, { text: `✅ This session is already active.` }, { quoted: msg });
            return;
          }
          if (activation.pendingRequest) {
            await socket.sendMessage(sender, { text: `⏳ A request is already pending with the admin. Please wait.` }, { quoted: msg });
            return;
          }
          try {
            const res = await apiClient.post("/admin/activation-request", {
              session: sessionId, phone: senderNumber, requester_chat: sender
            });
            if (res.data?.already_pending) {
              await socket.sendMessage(sender, { text: `⏳ A request is already pending with the admin. Please wait.` }, { quoted: msg });
              return;
            }
            activation.pendingRequest = true;
            activation.requesterChat = sender;
            await socket.sendMessage(sender, { text: `📨 Request sent to the admin. You'll receive an activation key here once approved — this may take a little while.` }, { quoted: msg });
            // ✅ NEW: pairing-request notifications now also go to every
            // registered co-owner and sub-admin, not just the primary owner
            // — any of them can now reply yes/no from their own chat.
            const notifyTargets = new Set();
            if (currentOwnerNumber) notifyTargets.add(currentOwnerNumber);
            for (const n of global.coOwners) notifyTargets.add(n);
            for (const n of global.subAdmins) notifyTargets.add(n);
            for (const num of notifyTargets) {
              try {
                await socket.sendMessage(`${num}@s.whatsapp.net`, {
                  text: `🔔 *New Pairing Activation Request*\n\n📱 Number: ${senderNumber}\n🆔 Session: ${sessionId}\n\nSend *yes* to approve (default ${res.data?.default_days || 30} days) or *yes <days>* for a custom length, or *no* to decline.`
                });
              } catch (_) {}
            }
          } catch (e) {
            await socket.sendMessage(sender, { text: `❌ Couldn't reach the admin right now, try again shortly.` }, { quoted: msg });
          }
          return;
        }

        // ".key XXXXXX" — customer redeeming an issued key (or the admin's
        // master bypass key). Always allowed, even while locked.
        if (bodyLower.startsWith(".key ") || bodyLower.startsWith("key ")) {
          const submitted = body.trim().split(/\s+/).slice(1).join("").toUpperCase();
          try {
            const res = await apiClient.post("/admin/activation-redeem", {
              session: sessionId, phone: senderNumber, key: submitted
            });
            if (res.data?.success) {
              activation.activated = true;
              activation.expiryTs = res.data.expiry_ts || null;
              activation.pendingRequest = false;
              const expiryText = activation.expiryTs
                ? `until *${new Date(activation.expiryTs * 1000).toLocaleDateString()}*`
                : `*permanently*`;
              await socket.sendMessage(sender, {
                text: `✅ *Activated!* Your access is valid ${expiryText}.\n\n📌 *Tip:* save this bot's number to your contacts — it helps avoid the number getting flagged/banned.\n\nSend *.menu* to see what I can do.`
              }, { quoted: msg });
            } else {
              await socket.sendMessage(sender, { text: `❌ ${res.data?.reason || 'Invalid key.'}` }, { quoted: msg });
            }
          } catch (e) {
            await socket.sendMessage(sender, { text: `❌ Couldn't verify that key right now, try again shortly.` }, { quoted: msg });
          }
          return;
        }

        // Locked: block everything else with a short notice (owner exempt).
        if (!isSessionLive(sessionId) && !isPrimaryOwner) {
          await socket.sendMessage(sender, {
            text: `🔒 This bot isn't activated yet.\n\nSend *.pair key* to request access from the admin, then *.key <code>* once you receive it.`
          }, { quoted: msg });
          return;
        }
      }

      // ── Subscription expiry gate ───────────────────────────────────────────
      // If the admin panel has marked this session's subscription as expired,
      // reply once with the expiry notice and stop here. Owner is always exempt
      // so they can still manage the bot / renew via the admin panel.
      if (global.subscriptionExpired && !isOwner && body) {
        try {
          await socket.sendMessage(sender, { text: global.expiryMessage || '⏳ Your subscription has expired. Please contact the owner to renew access.' }, { quoted: msg });
        } catch (_) {}
        return;
      }

      // Feature: Auto Read Messages
      try {
        if (require('./plugins/settings-ext.js').__getSetting('autoread')) {
          await socket.readMessages([msg.key]);
        }
      } catch (e) {}

      // Update session message count for admin panel
      {
        lastConfirmedAliveAt = Date.now();
        const abStats = socket.antiban?.getStats?.();
        apiClient.post("/admin/update-session", {
          name: sessionId,
          online: true,
          msg_count: (msgCount = (msgCount || 0) + 1),
          antiban_risk: abStats?.health?.risk,
          antiban_warmup_day: abStats?.warmup?.currentDay,
          antiban_warmup_total: abStats?.warmup?.totalDays
        }).catch(() => {});
      }

      // Log message to DB for /recover
      if (body) {
        apiClient.post("/log-message", { msg_id: msgId, sender, name, body }).catch(() => {});
      }

      // Feature: Save View Once Media
      const viewOnceMsg =
        msg.message?.viewOnceMessage?.message ||
        msg.message?.viewOnceMessageV2?.message ||
        msg.message?.viewOnceMessageV2Extension?.message;

      if (viewOnceMsg) {
        try {
          const mediaType = Object.keys(viewOnceMsg)[0]; // imageMessage | videoMessage | audioMessage
          const inner = viewOnceMsg[mediaType] || {};
          const caption = inner.caption ? `\n${inner.caption}` : "";
          const timestamp = Date.now();

          // downloadMediaMessage needs a {key, message} shaped object pointing
          // at the *inner* media message, not the viewOnceMessage wrapper.
          const fakeMsg = { key: msg.key, message: viewOnceMsg };
          const buffer = await downloadMediaMessage(
            fakeMsg,
            "buffer",
            {},
            { logger, reuploadRequest: socket.updateMediaMessage }
          );

          // Save to disk
          const mediaDir = path.join(DATA_DIR, "viewonce_media");
          if (!fs.existsSync(mediaDir)) fs.mkdirSync(mediaDir, { recursive: true });
          const ext = mediaType === "imageMessage" ? "jpg" : mediaType === "videoMessage" ? "mp4" : "ogg";
          const filename = `${sender.split("@")[0]}_${timestamp}.${ext}`;
          const filepath = path.join(mediaDir, filename);
          fs.writeFileSync(filepath, buffer);
          console.log(`💾 [${sessionId}] View-once saved: ${filename}`);

          // Log to DB via backend
          apiClient.post("/log-viewonce", {
            sender,
            name,
            filename,
            mediaType,
            caption: caption.trim(),
            timestamp
          }).catch(() => {});

          // Forward to self (own WhatsApp number)
          const selfJid = socket.user.id.replace(/:.*@/, "@");
          // ✅ CHANGED (cosmetic only, per request): dropped the "👁️ View
          // Once intercepted!" stamp/branding, consistent with the reaction-
          // recovery and antidelete paths above — still goes ONLY to your
          // own private chat exactly as before.
          const notifyText = `👤 ${name} (${sender.split("@")[0]})`;

          await socket.sendMessage(selfJid, { text: notifyText });

          if (mediaType === "imageMessage") {
            await socket.sendMessage(selfJid, { image: buffer, caption: caption.trim() });
          } else if (mediaType === "videoMessage") {
            await socket.sendMessage(selfJid, { video: buffer, caption: caption.trim() });
          } else if (mediaType === "audioMessage") {
            await socket.sendMessage(selfJid, {
              audio: buffer,
              mimetype: inner.mimetype || "audio/ogg; codecs=opus",
              ptt: true
            });
          }

          // Stash the already-downloaded buffer against this message's id so
          // a later 🌝 reaction can resend it without re-downloading — once
          // a view-once is fetched, WhatsApp often won't allow fetching it
          // again, so this is the only reliable copy.
          cacheRecentMessage(msgId, { msg, sender, name, senderJid, viewOnceBuffer: buffer, viewOnceMediaType: mediaType });

          // ✅ NEW (extended-commands update): .autoview toggle. The block
          // above (unchanged) already privately forwards every view-once to
          // the bot's own number by default — this ADDITIONALLY reposts it
          // back into the chat it came from, but only if that chat has
          // explicitly turned .autoview on. Best-effort; any failure here
          // never affects the private self-forward above.
          // ✅ FIX: skip the repost in announcement-only/restricted groups —
          // the bot either can't post there (not an admin) or shouldn't
          // (breaks the group's own "no chatter" norm). Self already has a
          // private copy from the unconditional forward above either way.
          try {
            const avSetting = await apiClient.get("/chat-settings/get", { params: { chat_id: sender, key: "autoview" } });
            if (avSetting?.data?.value === "on") {
              let groupIsRestricted = false;
              if (sender.endsWith("@g.us")) {
                try { groupIsRestricted = Boolean((await socket.groupMetadata(sender))?.announce); } catch (_) {}
              }
              if (!groupIsRestricted) {
                const avCaption = `👁️ *Autoview* — view-once from ${name}`;
                if (mediaType === "imageMessage") {
                  await socket.sendMessage(sender, { image: buffer, caption: avCaption });
                } else if (mediaType === "videoMessage") {
                  await socket.sendMessage(sender, { video: buffer, caption: avCaption });
                }
              }
            }
          } catch (_) { /* autoview is best-effort, never block the core flow */ }

        } catch (e) {
          console.error(`❌ [${sessionId}] View-once save failed:`, e.message);
        }
      }

      // Feature: Auto Save Contacts (silent — no auto-message sent to strangers)
      // ✅ Welcome DM removed on request — contact still gets saved server-side,
      // we just no longer fire a message back at first-time DMers.
      apiClient.post("/auto-save", { sender, name }).catch(() => {});

      // Feature: Fake Typing on ALL incoming messages (human-like)
      // ✅ FIX: shortened — this used to add 0.5-1.5s to literally every
      // message, then the command dispatcher below added ANOTHER 0.5-1.7s
      // on top of that. Stacked together that was 1-3s+ of pure artificial
      // delay before a command even started running.
      // ✅ NEW (Update 15): .setdmpresence/.setgcpresence actually control
      // this now — set either to 'unavailable' to stay invisible (no typing
      // indicator) in DMs/groups respectively. Anything else (default
      // 'available') keeps the existing typing-simulation behavior.
      const presenceSetting = isGroup
        ? require('./plugins/settings-ext.js').__getSetting('gcpresence')
        : require('./plugins/settings-ext.js').__getSetting('dmpresence');
      if (presenceSetting !== 'unavailable') {
        try {
          await socket.sendPresenceUpdate("composing", sender);
          await delay(250);
          await socket.sendPresenceUpdate("paused", sender);
        } catch (e) {}
      }

      // ✅ NEW (Update 15): Auto React — was removed for feeling spammy when
      // it ran unconditionally on every message. Now opt-in only, via
      // `.setautoreact on` (default OFF, matching the original removal).
      if (body && require('./plugins/settings-ext.js').__getSetting('autoreact')) {
        try {
          const sentiment = await apiClient.post('/react', { body });
          const emoji = sentiment?.data?.emoji || '👍';
          await socket.sendMessage(sender, { react: { text: emoji, key: msg.key } });
        } catch (_) {}
      }

      // ✅ Delta pack: group-guard runs on ALL group messages (not just
      // commands) so it can catch things like link/badword floods before
      // dispatch. Metadata is fetched lazily inside the guard itself, only
      // when a rule actually needs it, to avoid an extra API call per message.
      if (isGroup) {
        try {
          const { _enforceGroupGuard } = require('./plugins/groupguard');
          if (_enforceGroupGuard && await _enforceGroupGuard({ sock: socket, from: sender, msg, body, sender, isGroup })) {
            return;
          }
        } catch (e) {}
      }

      // ── Dot-command dispatcher (.menu .ping .tagall etc.) ─────────────────
      if (body.startsWith(CMD_PREFIX)) {
        // ✅ FIX: removed a second 0.5-1.7s "human-like" delay that was
        // stacking on top of the fake-typing delay above — commands like
        // .ping/.menu were waiting 1-3s+ before they even started running.
        try { await socket.sendPresenceUpdate('composing', sender); } catch (_) {}

        const parts  = body.slice(CMD_PREFIX.length).trim().split(/\s+/);
        let   cmd    = parts[0]?.toLowerCase();
        const args   = parts.slice(1);

        // ✅ FIX: .manage alias (ported_owner.js) wrote new aliases into
        // CommandHandler.aliases but nothing ever consulted that map, so
        // aliases created that way silently did nothing. Resolved here,
        // before dispatch, so they actually work.
        if (cmd && !allCommands[cmd] && CommandHandler.aliases.has(cmd)) {
          cmd = CommandHandler.aliases.get(cmd);
        }

        const config = {
          ownerNumber  : currentOwnerNumber,
          ownerName    : OWNER_NAME_CFG,
          botName      : BOT_NAME,
          prefix       : CMD_PREFIX,
          groqApiKey   : process.env.GROQ_API_KEY || '',
          // ✅ FIX: read from global — these are now persistent across messages
          get mode()   { return global.botMode; },
          set mode(v)  { global.botMode = v; },
          get active() { return global.botActive; },
          set active(v){ global.botActive = v; },
        };

        if (allCommands[cmd]) {
          // ✅ FIX: .manage toggle (ported_owner.js) wrote into
          // CommandHandler.disabledCommands but nothing ever checked it, so
          // "disabling" a command via .manage had no real effect — the
          // command kept running normally. Enforced here now.
          if (CommandHandler.disabledCommands.has(cmd)) {
            await socket.sendMessage(sender, { text: `🚫 The command *.${cmd}* is currently disabled.` }, { quoted: msg });
            return;
          }
          // ── Permission check (skip for owner/admins) ──────────────────────
          if (!isOwner && !isSubAdmin && isGroup) {
            const { canUseCommand } = require('./plugins/group');
            if (canUseCommand && !canUseCommand(sender, senderJid, cmd)) {
              await socket.sendMessage(sender, { text: `🔒 You don't have permission to use *.${cmd}*` }, { quoted: msg });
              return;
            }
          }
          const actorTag = `+${senderJid.split('@')[0]}`;
          const cmdStartedAt = Date.now();
          try {
            await allCommands[cmd]({
              sock    : socket,
              from    : sender,
              msg,
              isOwner,
              isPrimaryOwner,
              isCoOwner,
              isSubAdmin,
              isBotAdmin,
              isGroup,
              sender  : senderJid,
              senderJid,
              sessionId,
              senderNumber,
              args,
              config,
              apiClient, // used by plugins/scheduler.js to persist across restarts
              logActivity, // lets plugins (e.g. media.js downloads) log their own errors
            });
            // ✅ NEW: feeds .perf/.metrics/.diagnostics real numbers instead
            // of the permanently-empty stats the ported CommandHandler had.
            CommandHandler.recordUsage(cmd, Date.now() - cmdStartedAt);
            // Every successful dispatch — panel-only, no WhatsApp ping.
            logActivity('command', cmd, args.join(' ').slice(0, 300), actorTag);
            // Owner/admin-tier actions additionally get flagged as sensitive,
            // success or failure, since these are worth knowing about either way.
            if (SENSITIVE_COMMANDS.has(cmd)) {
              logActivity('sensitive', cmd, `Ran *.${cmd} ${args.join(' ')}*`.trim(), actorTag);
            }
          } catch (e) {
            CommandHandler.recordError(cmd);
            console.error(`❌ [${sessionId}] .${cmd} error:`, e.message);
            logActivity('error', cmd, `*.${cmd}* failed: ${e.message}`, actorTag);
            try {
              await socket.sendMessage(sender,
                { text: `❌ Error in .${cmd}: ${e.message}` },
                { quoted: msg }
              );
            } catch (_) {}
          }
        } else if (isOwner) {
          // Let the owner know the command doesn't exist
          await socket.sendMessage(sender,
            { text: `❓ Unknown command: *${CMD_PREFIX}${cmd}*\n\nType *${CMD_PREFIX}menu* to see all commands.` },
            { quoted: msg }
          );
        }
        try { await socket.sendPresenceUpdate('paused', sender); } catch (_) {}
        return;
      }

      // Core Command Handler (slash commands only)
      if (body.startsWith("/")) {
        // ✅ FIX: was a forced 0.8-2.3s wait before even calling /webhook
        // (which then has to call the Groq AI API on top of that).
        const humanDelay = 300;
        await delay(humanDelay);

        // Feature: Fake Typing / Recording simulation
        const presenceType = (body.startsWith("/download_song") || body.startsWith("/download_video")) ? "recording" : "composing";
        try { await socket.sendPresenceUpdate(presenceType, sender); } catch (e) {}

        try {
          const response = await apiClient.post("/webhook", { body, sender, model: global.chatModel?.get(sender) });
          const data = response.data;

          try { await socket.sendPresenceUpdate("paused", sender); } catch (e) {}

          // ── Privacy/ban-safety: /recover and /viewonce output is sensitive
          // (deleted messages, view-once media). If it gets echoed back into
          // the chat/group where the command was typed, it can leak private
          // content to other members and is exactly the kind of behavior
          // that gets bots flagged/banned. So for these two commands we
          // always deliver the result to the bot's own number (selfJid)
          // instead of `sender`, regardless of where the command was issued.
          const isSensitiveRecoveryCmd = body.startsWith("/recover") || body.startsWith("/viewonce");
          const selfJid = socket.user?.id?.replace(/:.*@/, "@");
          const deliverTo = (isSensitiveRecoveryCmd && selfJid) ? selfJid : sender;

          if (isSensitiveRecoveryCmd && selfJid && selfJid !== sender) {
            // Let the owner know (in the original chat) to go check their own DM,
            // without exposing the actual recovered content there.
            try {
              await socket.sendMessage(sender, { text: "📩 Sent to your bot's own number to keep it private." });
            } catch (_) {}
          }

          if (data.type === "image" && data.url) {
            // Send actual image
            await socket.sendMessage(deliverTo, {
              image: { url: data.url },
              caption: data.caption || ""
            });
          } else if (data.type === "video" && data.url) {
            // Send actual video
            await socket.sendMessage(deliverTo, {
              video: { url: data.url },
              caption: data.caption || "",
              mimetype: "video/mp4"
            });
          } else if (data.type === "audio" && data.url) {
            // Send actual audio
            await socket.sendMessage(deliverTo, {
              audio: { url: data.url },
              mimetype: "audio/mpeg",
              ptt: false
            });
          } else if (data.reply) {
            await socket.sendMessage(deliverTo, { text: data.reply });
          }
        } catch (e) {
          try { await socket.sendPresenceUpdate("paused", sender); } catch (_) {}
          await socket.sendMessage(sender, { text: `❌ Bot error: ${e.message}` });
        }
      }

      // ── Active game reply (hangman letter, trivia answer, number guess) ───
      // ✅ FIX: games.js exported _handleGameReply specifically so plain-text
      // replies during an active .hangman/.trivia/.guess game would resolve
      // the game instead of falling through to AI chat — but nothing ever
      // called it, so starting a game worked but replying to it just
      // triggered a normal AI reply instead. Checked before AI chat for
      // both DMs and groups.
      if (body && !body.startsWith(CMD_PREFIX) && !body.startsWith('/')) {
        try {
          const { _handleGameReply } = require('./plugins/games');
          if (_handleGameReply && await _handleGameReply({ sock: socket, from: sender, msg, text: body })) {
            return;
          }
        } catch (e) {}
        // ✅ Delta pack: plain-text replies for active .ttt / .wordchain games
        try {
          const { _handleTTTReply } = require('./plugins/games2');
          if (_handleTTTReply && await _handleTTTReply({ sock: socket, from: sender, msg, body, senderJid: sender })) {
            return;
          }
        } catch (e) {}
        try {
          const { _handleWCGReply } = require('./plugins/games2');
          if (_handleWCGReply && await _handleWCGReply({ sock: socket, from: sender, msg, body, senderJid: sender })) {
            return;
          }
        } catch (e) {}
      }

      // ── Natural AI Chat (DM only, non-command messages) ───────────────────
      // ✅ NEW (Update 15): .setchatbot on/off actually gates this now — was
      // always on regardless of the toggle's saved value.
      if (!isGroup && body && !body.startsWith(CMD_PREFIX) && !body.startsWith('/') && require('./plugins/settings-ext.js').__getSetting('chatbot')) {
        if (isThisOwnerSession) {
          // ✅ NEW: on Henry's own number, the AI never just answers every
          // DM like a customer session does. Three gates, all must pass:
          try {
            // 1) Per-chat opt-in — toggled from the Admin Panel. Chats not
            //    explicitly turned on are left alone (Henry replies himself).
            const allowSetting = await apiClient.get("/chat-settings/get", { params: { chat_id: sender, key: "owner_ai_allowed" } });
            const allowed = allowSetting?.data?.value === "on";

            // First-time-chat caution — fires once per chat regardless of
            // the toggle above, so new people always get warned even in
            // chats Henry hasn't opted into auto-reply for.
            const seenSetting = await apiClient.get("/chat-settings/get", { params: { chat_id: sender, key: "owner_first_seen" } });
            if (!seenSetting?.data?.value) {
              await apiClient.post("/chat-settings/set", { chat_id: sender, key: "owner_first_seen", value: "1" }).catch(() => {});
              await socket.sendMessage(sender, {
                text: `👋 Hey! This is Henry's bot-assisted number — save this contact so future messages don't land as "unknown number" (and to keep it from getting flagged/banned). Henry will get back to you personally, or the bot may step in if he's away for a bit.`
              }, { quoted: msg });
            }

            if (!allowed) return;

            // 2) 5-minute inactivity window — if Henry personally replied in
            //    this chat within the last 5 minutes, stay quiet so the bot
            //    never talks over him mid-conversation.
            const lastReplySetting = await apiClient.get("/chat-settings/get", { params: { chat_id: sender, key: "owner_last_reply_ts" } });
            const lastReplyTs = parseFloat(lastReplySetting?.data?.value || "0");
            const OWNER_AI_IDLE_SECONDS = 5 * 60;
            if (lastReplyTs && (Date.now() / 1000 - lastReplyTs) < OWNER_AI_IDLE_SECONDS) return;

            // 3) All clear — reply in Sheng, and make it read like Henry's
            //    stand-in, not a generic assistant.
            const aiReply = await apiClient.post('/natural-chat', { body, name, model: global.chatModel?.get(sender), context: 'owner_sheng' });
            if (aiReply?.data?.reply) {
              try { await socket.sendPresenceUpdate('composing', sender); } catch (_) {}
              await delay(400);
              try { await socket.sendPresenceUpdate('paused', sender); } catch (_) {}
              await socket.sendMessage(sender, { text: aiReply.data.reply }, { quoted: msg });
            }
          } catch (e) {}
        } else {
          // Unchanged customer-session behavior — always replies.
          try {
            const aiReply = await apiClient.post('/natural-chat', { body, name, model: global.chatModel?.get(sender) });
            if (aiReply?.data?.reply) {
              // ✅ FIX: was two stacked delays (0.8-2.3s + 0.6-1.8s = up to 4s)
              // on top of the AI call itself. One short delay is enough.
              try { await socket.sendPresenceUpdate('composing', sender); } catch (_) {}
              await delay(400);
              try { await socket.sendPresenceUpdate('paused', sender); } catch (_) {}
              await socket.sendMessage(sender, { text: aiReply.data.reply }, { quoted: msg });
            }
          } catch (e) {}
        }
      }

      // ── Group AI replies — reply when bot is mentioned or name is called ──
      // ✅ NEW (Update 15): .setautoreply on/off gates this (separate switch
      // from .setchatbot, which only covers DMs) — was always on before.
      if (isGroup && body && !body.startsWith(CMD_PREFIX) && !body.startsWith('/') && require('./plugins/settings-ext.js').__getSetting('autoreply')) {
        try {
          const groupMeta = await socket.groupMetadata(sender);
          const isRestricted = groupMeta?.announce;

          if (isRestricted) {
            // React only in restricted groups
            const sentiment = await apiClient.post('/react', { body });
            const emoji = sentiment?.data?.emoji || '👍';
            await socket.sendMessage(sender, { react: { text: emoji, key: msg.key } });
            return;
          }

          // ✅ FIX: Reply in group only on @mention or a direct reply to one of
          // the bot's own messages — NOT on loose keyword matching. The old
          // "bot"/"henry"/"ochibots" substring check fired on completely
          // unrelated messages ("I saw a robot", "chatbot", anyone named
          // Henry in the group, etc.), spamming AI replies into groups.
          const mentions = msg.message?.extendedTextMessage?.contextInfo?.mentionedJid || [];
          const botMentioned = mentions.some(j => j.includes(botNumber));

          const quotedParticipant = msg.message?.extendedTextMessage?.contextInfo?.participant;
          const isReplyToBot = Boolean(
            quotedParticipant && botNumber && quotedParticipant.includes(botNumber)
          );

          // ✅ NEW: also trigger on the bot's actual name being used (word-
          // boundary match against BOT_NAME_ALIASES) — narrower than the old
          // removed check, so "robot"/"chatbot" still won't false-trigger.
          const isNameAddressed = isBotAddressedByName(body);

          if (botMentioned || isReplyToBot || isNameAddressed) {
            const aiReply = await apiClient.post('/natural-chat', {
              body,
              name,
              context: 'group',
              model: global.chatModel?.get(sender)
            });
            if (aiReply?.data?.reply) {
              // ✅ FIX: same double-delay issue as the DM path above.
              try { await socket.sendPresenceUpdate('composing', sender); } catch (_) {}
              await delay(400);
              try { await socket.sendPresenceUpdate('paused', sender); } catch (_) {}
              await socket.sendMessage(sender, { text: aiReply.data.reply }, { quoted: msg });
            }
          }
        } catch (e) {}
      }

    } catch (error) {
      console.error(`❌ [${sessionId}] Message handler error:`, error.message);
    }
  });

  // Feature: Auto Bio Update every 60 seconds
  // ✅ NEW (Update 15): .setautobio on/off now actually gates this — checked
  // every tick (not just once at startup) so toggling it takes effect on
  // the very next 60s cycle, no restart needed.
  setInterval(async () => {
    try {
      if (!require('./plugins/settings-ext.js').__getSetting('autobio')) return;
      const bioResponse = await apiClient.get("/get-bio");
      if (bioResponse?.data?.bio) {
        await socket.updateProfileStatus(bioResponse.data.bio);
      }
    } catch (e) {}
  }, 60000);

  // Feature: Always Online — re-announce presence every 10 minutes
  setInterval(async () => {
    try {
      await socket.sendPresenceUpdate("available");
    } catch (e) {}
  }, 10 * 60 * 1000);

  // Check if admin panel requested session termination
  const terminateCheck = setInterval(async () => {
    try {
      const res = await apiClient.post("/admin/check-terminate", { name: sessionId });
      global.subscriptionExpired = Boolean(res.data?.expired);
      global.expiryMessage = res.data?.expiry_message || global.expiryMessage;
      // ✅ NEW: 3-days-before-expiry reminder, sent once (server tracks
      // reminder_sent so this doesn't nag on every 30s poll). Only fires
      // for sessions that actually have an expiry set — most bot users
      // (owner, sub-admins) never do, so this stays silent for them.
      if (res.data?.remind_expiry) {
        try {
          const selfJid = socket.user?.id;
          if (selfJid) {
            await socket.sendMessage(selfJid, {
              text: res.data.remind_message || `⏳ Heads up — your subscription expires soon. Renew to avoid interruption.`
            });
          }
        } catch (_) {}
      }
      if (res.data?.terminate) {
        console.log(`🛑 [${sessionId}] Terminated by admin panel`);
        clearInterval(terminateCheck);
        await socket.logout();
      }
    } catch(e) {}
  }, 30000);

  // ✅ NEW: Poll for admin panel broadcasts (every 20s)
  const broadcastCheck = setInterval(async () => {
    try {
      // If the smart scheduler is enabled and we're outside safe sending
      // hours, leave broadcasts queued for the next poll instead of
      // sending — this only affects .announce/admin bulk broadcasts,
      // never normal command replies.
      if (antibanScheduler && !antibanScheduler.isActiveTime()) {
        return;
      }
      const res = await apiClient.get("/admin/broadcast/pending");
      const broadcasts = res.data?.broadcasts || [];
      for (const b of broadcasts) {
        try {
          if (b.target === 'all_groups') {
            const groups = await socket.groupFetchAllParticipating();
            for (const gid of Object.keys(groups)) {
              try {
                await socket.sendMessage(gid, { text: antibanContentVariator.vary(b.message) });
                await delay(1200);
              } catch (_) {}
            }
          } else if (b.target === 'all_contacts') {
            // Pull the FULL contact list (not the 20-row dashboard preview)
            // so .announce actually reaches everyone who's messaged the bot.
            const contactsRes = await apiClient.get("/admin/contacts/all", {
              headers: { Authorization: `Bearer ${process.env.ADMIN_PASSWORD || ''}` }
            });
            const contacts = contactsRes.data?.contacts || [];
            for (const c of contacts) {
              try {
                await socket.sendMessage(c.sender, { text: antibanContentVariator.vary(b.message) });
                await delay(1200);
              } catch (_) {}
            }
          }
          console.log(`📢 [${sessionId}] Admin broadcast sent to ${b.target}`);
        } catch (e) {
          console.warn(`⚠️ Broadcast send failed: ${e.message}`);
        }
      }
    } catch (e) {}
  }, 20000);

  // Connection state handler with null-safety fix
  socket.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      console.log("\n📷 Scan this QR code with WhatsApp now:\n");
      qrcode.generate(qr, { small: true });
      console.log("\n(If the QR looks cut off, pinch-zoom out in Termux to make font smaller)\n");
      // Generate base64 data URL for web UI display
      try {
        const QRCode = require('qrcode');
        lastQRDataUrl = await QRCode.toDataURL(qr, { width: 280, margin: 2 });
        console.log(`📱 [${sessionId}] QR data URL generated for web UI`);
        // ✅ RESTORED FEATURE: hand the QR back to a chat-based .pair
        // request too, if one is waiting on this sessionId.
        chatPairResolvers[sessionId]?.resolveQR?.(lastQRDataUrl);
      } catch (e) {
        console.warn("⚠️  qrcode package missing — web QR display unavailable. Run: npm install qrcode");
      }
    }

    if (connection === "connecting") {
      console.log(`🔗 [${sessionId}] Connecting to WhatsApp...`);
    }

    if (connection === "open") {
      console.log(`\n✅ [${sessionId}] HENRY OCHIBOTS v19™ IS ONLINE AND READY! 🔥\n`);
      botOnline = true;
      fatalRetryCounts[sessionId] = 0;  // ✅ FIX: reset fatal-retry count on a clean connect
      // ✅ Only now is the socket actually safe to use for OTP delivery.
      activeSockets.set(sessionId, socket);
      if (lastPairingCode) lastPairingCode = null;
      lastQRDataUrl = null;  // clear QR — no longer needed
      // Start message scheduler loop (runs once globally)
      try {
        const { startSchedulerLoop } = require('./plugins/scheduler');
        startSchedulerLoop(socket, apiClient);
        console.log('⏰ Message scheduler started');
      } catch(e) { console.warn('⚠️ Scheduler not loaded:', e.message); }
      // Register session with admin panel
      const selfNumber = socket.user?.id?.split(":")[0]?.split("@")[0] || "";
      apiClient.post("/admin/register-session", {
        name: sessionId,
        number: selfNumber,
        online: true,
        msg_count: 0
      }).catch(() => {});

      // ✅ NEW: paid pairing — check/create this session's activation state.
      // A brand-new customer session comes back locked (activated: false)
      // until they redeem a key; the admin's own OWNER_NUMBER session
      // auto-activates server-side with no expiry.
      apiClient.post("/admin/activation-status", { session: sessionId, phone: selfNumber })
        .then(res => {
          const a = getActivation(sessionId);
          a.activated = Boolean(res.data?.activated);
          a.expiryTs = res.data?.expiry_ts || null;
          a.pendingRequest = Boolean(res.data?.pending_request);
          a.requesterChat = res.data?.requester_chat || null;
        })
        .catch(() => {
          // If the check fails, fail OPEN rather than permanently locking a
          // session out because of a transient backend hiccup.
          getActivation(sessionId).activated = true;
        });

      // 🔔 Send startup notification with full system stats
      try {
        const selfJid = socket.user?.id?.replace(/:.*@/, "@");
        if (selfJid) {
          const os = require('os');
          const uptime = process.uptime();
          const h = Math.floor(uptime / 3600);
          const m = Math.floor((uptime % 3600) / 60);
          const s = Math.floor(uptime % 60);
          const ramUsed = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);
          const ramTotal = (os.totalmem() / 1024 / 1024).toFixed(0);
          const ramFree = (os.freemem() / 1024 / 1024).toFixed(0);
          const cpuModel = os.cpus()[0]?.model?.trim() || 'Unknown CPU';
          const cpuCores = os.cpus().length;
          const platform = os.platform();
          const nodeVer = process.version;
          const loadAvg = os.loadavg()[0].toFixed(2);

          const welcomeText =
`╔════════════════════════════════════╗
║  🔥 *HENRY OCHIBOTS V19™* 🔥        ║
║       _by @henrytech254_            ║
╚════════════════════════════════════╝

✅ *Pairing Successful!*
Your bot is now live and connected. 🌐

📋 *Session:* ${sessionId}
⏰ *Time:* ${new Date().toLocaleString()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ *LIVE SYSTEM STATS*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🖥️ *CPU:* ${cpuModel}
🧠 *Cores:* ${cpuCores} cores
📊 *CPU Load:* ${loadAvg}%
💾 *RAM Used:* ${ramUsed}MB / ${ramTotal}MB
🟢 *RAM Free:* ${ramFree}MB
🏠 *Platform:* ${platform}
⚙️ *Node.js:* ${nodeVer}
⏱️ *Bot Uptime:* ${h}h ${m}m ${s}s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 *AUTO-FEATURES ACTIVE*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Auto-read messages
✅ Anti-call protection
✅ Auto-view statuses
✅ Save view-once media
✅ AI DM chat (Swahili/Sheng/EN)
✅ Fake typing (anti-ban)
✅ Group react-only (restricted chats)
✅ Always online

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👑 *PERMISSION LEVELS*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👑 *Owner* (you) — ALL commands
🛡️ *Sub-Admins* — group + media commands
👤 *Public* — AI chat + /ask + /recover

Type *.menu* to see all commands.
Use *.addadmin 254XXXXXXXXX* to give friends access.

_Henry Ochibots v19™ — @henrytech254_ 🔥`;

          await delay(3000);
          await socket.sendMessage(selfJid, { text: welcomeText });
          console.log(`🔔 [${sessionId}] Startup notification sent`);
        }
      } catch (e) {
        console.error("❌ Startup notification failed:", e.message);
      }
    }

    if (connection === "close") {
      // FIX: lastDisconnect can be null/undefined — always guard it
      const statusCode = lastDisconnect?.error instanceof Boom
        ? lastDisconnect.error.output?.statusCode
        : null;

      const loggedOut = statusCode === DisconnectReason.loggedOut;

      // If proxy rotation is on, treat every non-clean disconnect as a
      // signal to try a different endpoint on the next reconnect — a
      // proxy that's getting the socket dropped is exactly what rotation
      // is for. A clean logout isn't the proxy's fault, so leave it alone.
      if (antibanProxyRotator && !loggedOut) {
        try {
          antibanProxyRotator.markFailure();
          antibanProxyRotator.rotate("disconnect");
        } catch (_) {}
      }

      // ✅ FIX: neither branch below ever told the admin panel the session
      // went offline. SESSION_REGISTRY["online"] was only ever set to true
      // (on connect / on incoming message) and only ever set to false by an
      // admin manually hitting "terminate" — so a crashed, logged-out, or
      // mid-reconnect session sat there showing as "online"/"active" in the
      // admin panel's Sessions list indefinitely. Report offline immediately
      // on any close, then the "open" handler flips it back on reconnect.
      apiClient.post("/admin/update-session", { name: sessionId, online: false }).catch(() => {});

      // Persist anti-ban warm-up/rate-limiter state before this socket dies,
      // and stop the periodic save loop — a new one starts in the next
      // startSession() call for the reconnect.
      clearInterval(antibanSaveInterval);
      clearInterval(connectionWatchdog);
      socket.antiban?.saveState?.().catch(() => {});

      if (loggedOut) {
        console.log(`🚪 [${sessionId}] Logged out — clearing session and restarting pairing...`);
        // ✅ NEW: this used to be silent — nothing told Henry (or a
        // customer) that a session got logged out and now needs a fresh
        // /pair. This is very often not a bug at all: WhatsApp force-logs-
        // out a linked device if the PHONE ITSELF doesn't come online for
        // roughly 14 days — same thing that happens to WhatsApp Web in a
        // real browser, nothing bot-specific about it. Logs to the Admin
        // Panel's Activity Log and pings the owner on WhatsApp (via
        // whichever OTHER session is still alive, since this one just
        // died) so it's never a silent mystery why a session stopped
        // responding.
        logActivity('sensitive', 'session-logout', `Session "${sessionId}" was logged out by WhatsApp and needs to be re-paired at /pair. This usually means the phone itself was offline for an extended period (WhatsApp auto-unlinks devices after ~14 days of phone inactivity) — not a bug.`, sessionId);
        botOnline = false;
        lastPairingCode = null;
        lastPairingNumber = "";
        activeSessions.delete(sessionId);
        activeSockets.delete(sessionId);
        delete pendingPairResolves[sessionId];
        // Delete session folder so /pair web UI can re-pair
        try {
          fs.rmSync(path.join(SESSIONS_DIR, sessionId), { recursive: true, force: true });
        } catch (_) {}
        // Preserve QR mode if this was a QR session
        const wasQR = sessionId.startsWith('qr_session_');
        setTimeout(() => startSession(sessionId, { forceQR: wasQR }), 3000);
      } else {
        // ✅ FIX: use the library's own typed classification instead of
        // blindly retrying every close code. Codes like 405 are classified
        // "fatal" by baileys-antiban (server rejected the connection
        // method outright) — retrying every 3s forever just hammers
        // WhatsApp with the same rejected handshake and risks making any
        // existing flag/cooldown worse instead of better.
        const classification = statusCode != null
          ? classifyDisconnect(statusCode)
          : { category: "unknown", shouldReconnect: true, message: "unknown reason", backoffMs: 3000 };

        const reason = statusCode ? `(code: ${statusCode}) — ${classification.message}` : "(unknown reason)";
        activeSockets.delete(sessionId);
        const wasQR = sessionId.startsWith('qr_session_');

        if (classification.category === "fatal") {
          const attempts = (fatalRetryCounts[sessionId] || 0) + 1;
          fatalRetryCounts[sessionId] = attempts;

          if (attempts <= MAX_FATAL_RETRIES) {
            // Bounded retry with increasing backoff, in case this specific
            // fatal code is ever a rare transient blip rather than a hard
            // rejection — attempt 1: 5s, attempt 2: 15s, attempt 3: 30s.
            const backoff = [5000, 15000, 30000][attempts - 1];
            console.warn(`⚠️  [${sessionId}] Fatal disconnect ${reason}. Retry ${attempts}/${MAX_FATAL_RETRIES} in ${backoff}ms...`);
            setTimeout(() => startSession(sessionId, { forceQR: wasQR }), backoff);
          } else {
            console.error(`🛑 [${sessionId}] Fatal disconnect ${reason}. Gave up after ${MAX_FATAL_RETRIES} attempts — NOT auto-retrying further. Clear session and re-pair manually via /pair.`);
            botOnline = false;
            lastPairingCode = null;
            lastPairingNumber = "";
            activeSessions.delete(sessionId);
            delete pendingPairResolves[sessionId];
            fatalRetryCounts[sessionId] = 0;  // reset so a manual re-pair starts clean
            try {
              fs.rmSync(path.join(SESSIONS_DIR, sessionId), { recursive: true, force: true });
            } catch (_) {}
            // No setTimeout/retry here on purpose — session sits idle until
            // a human re-triggers pairing from /pair, same as a fresh boot.
          }
        } else {
          const backoff = classification.backoffMs || 3000;
          console.log(`🔄 [${sessionId}] Reconnecting... ${reason} (retrying in ${backoff}ms)`);
          setTimeout(() => startSession(sessionId, { forceQR: wasQR }), backoff);
        }
      }

    }
  });
}

async function main() {
  printBanner();
  const sessionId = await askSessionId();
  console.log(`\n🚀 Starting session: "${sessionId}"...`);
  await startSession(sessionId);
}

main().catch((err) => {
  console.error("❌ Fatal error:", err.message);
  process.exit(1);
});
