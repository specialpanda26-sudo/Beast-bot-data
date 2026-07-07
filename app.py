import os
import io
import csv
import time
import asyncio
import logging
import json
import random
import hashlib
import secrets
import html
import httpx
import aiosqlite
from urllib.parse import quote_plus
from pathlib import Path
from quart import Quart, request, jsonify, Response, redirect

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("HenryTechCore")

def print_banner():
    banner = """
\033[1;36m
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗███████╗███╗   ██╗██████╗ ██╗   ██╗              ║
║   ██║  ██║██╔════╝████╗  ██║██╔══██╗╚██╗ ██╔╝              ║
║   ███████║█████╗  ██╔██╗ ██║██████╔╝ ╚████╔╝               ║
║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██╗  ╚██╔╝                ║
║   ██║  ██║███████╗██║ ╚████║██║  ██║   ██║                  ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝                 ║
║                                                              ║
║   \033[1;35m██████╗  ██████╗ ████████╗███████╗\033[1;36m                    ║
║   \033[1;35m██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝\033[1;36m                    ║
║   \033[1;35m██████╔╝██║   ██║   ██║   ███████╗\033[1;36m                    ║
║   \033[1;35m██╔══██╗██║   ██║   ██║   ╚════██║\033[1;36m                    ║
║   \033[1;35m██████╔╝╚██████╔╝   ██║   ███████║\033[1;36m                    ║
║   \033[1;35m╚═════╝  ╚═════╝    ╚═╝   ╚══════╝\033[1;36m                   ║
║                                                              ║
║      \033[1;33m✦ Henry Ochibots v19™ — created by Henry ✦\033[1;36m              ║
║      \033[1;32m⚡ HENRY OCHIBOTS v19™  |  PYTHON BACKEND\033[1;36m              ║
║      \033[1;33m⚡ AI  |  DATABASE  |  COMMANDS  |  API\033[1;36m            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
\033[0m"""
    print(banner)

print_banner()

# ── Persistent data directory ───────────────────────────────────────────────
# ✅ FIX: DB file, view-once media, and payment proofs were all scattered as
# plain relative/local paths, so a redeploy on Render/Railway silently wiped
# all of them. They now share one DATA_DIR root with client_bridge.js's
# sessions folder — set DATA_DIR in your env to a mounted persistent disk
# path (see render.yaml) to survive redeploys, not just process restarts.
DATA_DIR = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = Quart(__name__, static_folder="assets", static_url_path="/assets")

# ✅ Force browsers to always fetch the latest HTML instead of using a stale
# local cache — without this, anyone who'd visited before kept seeing old
# landing-page/admin-page content even after a fresh deploy.
NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

# ✅ NEW: baseline security headers on every response.
# Referrer-Policy matters a lot here specifically because the admin panel
# authenticates via a ?pass=PASSWORD query string — without a strict
# referrer policy, clicking any outbound link (or loading any external
# resource) from an authenticated admin page could leak the password to
# a third-party site via the Referer header. no-referrer stops that.
@app.after_request
async def _apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response


def _client_ip(req) -> str:
    """Best-effort real client IP behind a reverse proxy (Render/Railway
    etc. sit in front of this app), falling back to the direct socket addr."""
    fwd = req.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.remote_addr or "unknown"


GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
# ✅ NEW: powers .claude — a separate, opt-in AI command distinct from the
# Groq-backed natural-chat/persona/translate features above. Optional: if
# unset, .claude just replies with a clear "not configured" message rather
# than crashing.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
if not GROQ_API_KEY:
    logger.warning("⚠️  GROQ_API_KEY not set! /ask command will fail.")

# NEW: panel registration OTP — sent via free email SMTP, no WhatsApp/paid SMS needed
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "Henry Tech Bot Panel")

# ✅ FIX: Render blocks outbound traffic on raw SMTP ports (25/465/587) —
# this is why /register's email path always failed with "couldn't reach
# the email server" no matter what SMTP_HOST/PORT was set. Resend's HTTP
# API sends the same email over normal HTTPS (443, same as any web
# request), which Render does allow. Free tier: 100 emails/day, no card
# required — https://resend.com/signup. Leave RESEND_API_KEY unset and
# the code below falls back to the old SMTP path (useful only if hosting
# somewhere that doesn't block SMTP, e.g. Railway/a VPS).
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev")
REG_STARTER_CREDITS = int(os.environ.get("REG_STARTER_CREDITS", "80"))  # 80 kesh starter credit on verify

# ── Referral program ─────────────────────────────────────────────────────
# Whoever invited a new user (referrer) gets REFERRAL_REFERRER_BONUS kesh,
# and the new user themself gets REFERRAL_REFERRED_BONUS kesh — paid out
# automatically (no human review) the moment the referred user completes
# OTP verification. This stacks on top of REG_STARTER_CREDITS, which every
# verified user gets regardless of referral.
REFERRAL_REFERRER_BONUS = int(os.environ.get("REFERRAL_REFERRER_BONUS", "15"))
REFERRAL_REFERRED_BONUS = int(os.environ.get("REFERRAL_REFERRED_BONUS", "30"))
OTP_TTL_SECONDS = 600  # 10 minutes

# NEW: manual top-up / wallet funding via M-Pesa "Send Money" to the admin's
# own number. We CANNOT verify in real time whether an M-Pesa code or
# screenshot is genuine (that needs a Safaricom Daraja API integration this
# project doesn't have) — so instead of pretending to auto-verify, this
# queues every submission for a human admin to approve/reject from the
# Payments tab. Credits only land in the user's wallet once approved.
import re as _re
import base64 as _b64

MPESA_CODE_RE = _re.compile(r"^[A-Z0-9]{8,12}$")
PAYMENT_PROOFS_DIR = DATA_DIR / "payment_proofs"
PAYMENT_PROOFS_DIR.mkdir(exist_ok=True)
ADMIN_PAYTO_NUMBER = os.environ.get("ADMIN_PAYTO_NUMBER", "")  # e.g. 254712345678 — shown to users as where to send M-Pesa funds


def _generate_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with a random per-user salt. Stored as
    'salt_hex$hash_hex' — no plaintext or reversible encoding ever touches
    the database."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split("$", 1)
    except (ValueError, AttributeError):
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return secrets.compare_digest(check.hex(), digest_hex)


# ✅ NEW: WhatsApp OTP delivery — this IS a WhatsApp bot, so the registering
# user's code is sent straight from the bot's own number instead of email.
# Talks to the Node bridge's internal pairing server over localhost (same
# mechanism the /pair proxy routes further down use).
NODE_PAIR_URL = f"http://127.0.0.1:{os.environ.get('WEB_PORT', 3000)}"

# ✅ SECURITY FIX: paired with the same constant in client_bridge.js. Without
# this, /send-otp-whatsapp, /notify-owner, /notify-user and /internal/action
# were reachable by anyone who had the bot's public URL (they're on the same
# port /pair is served from), letting a stranger send arbitrary WhatsApp
# messages or touch the console actions below with no login at all. Set the
# INTERNAL_SECRET env var (any random string) to the same value here and in
# the Node process's env to close that off.
_INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "")
def _node_headers() -> dict:
    return {"X-Internal-Secret": _INTERNAL_SECRET} if _INTERNAL_SECRET else {}


async def _call_node_internal(path: str, payload: dict, timeout: float = 8) -> dict:
    """POST to an internal-only route on the Node bridge (/internal/action, etc.)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{NODE_PAIR_URL}{path}", json=payload, headers=_node_headers())
            data = resp.json()
            if resp.status_code == 200 and data.get("success"):
                return {"success": True, **{k: v for k, v in data.items() if k != "success"}}
            return {"success": False, "error": data.get("error", "Request to the bot failed.")}
    except Exception as e:
        logger.error("Node internal call to %s failed: %s", path, e)
        return {"success": False, "error": "Bot isn't reachable right now. Try again shortly."}


async def send_otp_whatsapp(phone: str, otp: str, name: str, require_owner_session: bool = False) -> dict:
    try:
        # ✅ FIX (speed): was timeout=15 — a dead/half-open session would make
        # registering users wait up to 15s just to see "doesn't work". Since
        # the Node bridge now rejects immediately when there's no live
        # socket, 5s is plenty and failures show up far faster.
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{NODE_PAIR_URL}/send-otp-whatsapp",
                json={"phone": phone, "otp": otp, "name": name, "requireOwnerSession": require_owner_session},
                headers=_node_headers(),
            )
            data = resp.json()
            if resp.status_code == 200 and data.get("success"):
                return {"success": True}
            return {"success": False, "error": data.get("error", "Failed to send WhatsApp message.")}
    except Exception as e:
        logger.error("OTP WhatsApp send failed: %s", e)
        return {"success": False, "error": "Bot isn't connected to WhatsApp right now. Try again shortly."}


async def _send_otp_email_resend(to_email: str, otp: str, name: str) -> dict:
    """HTTPS-based email send via Resend's API — works on Render since it's
    just a normal outbound web request, unlike raw SMTP which Render blocks."""
    subject = "Your Henry Tech Bot Panel verification code"
    html_body = (
        f"<p>Hi {html.escape(name or 'there')},</p>"
        f"<p>Your verification code is: <b style='font-size:20px'>{otp}</b></p>"
        f"<p>This code expires in 10 minutes. Enter it on the registration page to verify "
        f"your number and unlock your trust badge + {REG_STARTER_CREDITS} kesh free credit.</p>"
        f"<p>— Henry Tech Bot Panel</p>"
    )
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                json={
                    "from": f"{SMTP_FROM_NAME} <{RESEND_FROM_EMAIL}>",
                    "to": [to_email],
                    "subject": subject,
                    "html": html_body,
                },
            )
        if resp.status_code in (200, 201):
            return {"success": True}
        logger.error("Resend OTP email failed: %s %s", resp.status_code, resp.text)
        return {"success": False, "error": "Couldn't send the email right now. Please try again or use WhatsApp delivery instead."}
    except Exception as e:
        logger.error("Resend OTP email send failed: %s", e)
        return {"success": False, "error": "Couldn't send the email right now. Please try again or use WhatsApp delivery instead."}


async def send_otp_email(to_email: str, otp: str, name: str) -> dict:
    """
    Optional fallback — sends the OTP via email instead of WhatsApp. Only
    used if RESEND_API_KEY or SMTP_EMAIL/SMTP_PASSWORD are configured;
    WhatsApp delivery above is the primary path now.
    """
    # ✅ Prefer Resend (HTTPS) — this is the path that actually works on
    # Render. Only fall through to raw SMTP if Resend isn't configured.
    if RESEND_API_KEY:
        return await _send_otp_email_resend(to_email, otp, name)

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        logger.warning("⚠️  Neither RESEND_API_KEY nor SMTP_EMAIL/SMTP_PASSWORD are set — cannot send OTP emails.")
        return {"success": False, "error": "OTP email service not configured on server."}

    import smtplib
    from email.mime.text import MIMEText

    subject = "Your Henry Tech Bot Panel verification code"
    body = (
        f"Hi {name or 'there'},\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in 10 minutes. Enter it on the registration page to verify "
        f"your number and unlock your trust badge + {REG_STARTER_CREDITS} kesh free credit.\n\n"
        f"— Henry Tech Bot Panel"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_EMAIL}>"
    msg["To"] = to_email

    def _send_sync():
        # ✅ FIX (speed): was timeout=15 — matches the same "fail fast,
        # don't make the user wait" fix applied to WhatsApp OTP delivery.
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=6) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, [to_email], msg.as_string())

    try:
        await asyncio.to_thread(_send_sync)
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        logger.error("OTP email send failed: SMTP authentication rejected.")
        return {
            "success": False,
            "error": (
                "Email login was rejected by the mail server. If you're using Gmail, "
                "SMTP_PASSWORD must be a 16-character App Password (Google Account → "
                "Security → 2-Step Verification → App passwords), not your normal Gmail "
                "password — Gmail blocks regular passwords for SMTP."
            ),
        }
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, OSError) as e:
        logger.error("OTP email send failed: could not reach SMTP server: %s", e)
        return {
            "success": False,
            "error": (
                "Couldn't reach the email server. Render blocks outbound SMTP ports "
                "(25/465/587) entirely, so this will keep failing on Render regardless of "
                "SMTP_HOST/SMTP_PORT — set RESEND_API_KEY instead (free at resend.com) to "
                "send email over HTTPS, or use WhatsApp delivery."
            ),
        }
    except Exception as e:
        logger.error("OTP email send failed: %s", e)
        return {"success": False, "error": "Couldn't send the email right now. Please try again or use WhatsApp delivery instead."}


DB_FILE = str(DATA_DIR / "henry_tech_v5.db")
SESSION_REGISTRY = {}  # tracks all bot sessions for admin panel
DEFAULT_EXPIRY_MESSAGE = "⏳ Your subscription has expired. Please contact the owner to renew access."
PROCESS_START_TIME = time.time()  # ✅ NEW: for admin uptime tracking

async def call_groq_ai(prompt: str, model: str = None, system: str = None) -> str:
    if not GROQ_API_KEY:
        return "❌ AI not configured. Set GROQ_API_KEY in your .env file."
    chosen_model = model or "llama3-8b-8192"
    # ✅ NEW: optional `system` override (defaults to the original hardcoded
    # message below if not given), so new features like .persona/.translate
    # can reuse this same helper instead of duplicating the Groq call.
    system_msg = system or "You are a helpful WhatsApp assistant. Keep replies concise and friendly."
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": chosen_model,
                    "messages": [
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 1024
                }
            )
            data = response.json()
            if response.status_code == 200:
                return data["choices"][0]["message"]["content"]
            # Fallback model if first fails
            response2 = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "openai/gpt-oss-20b",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024
                }
            )
            data2 = response2.json()
            if response2.status_code == 200:
                return data2["choices"][0]["message"]["content"]
            return f"❌ AI Error: {data.get('error', {}).get('message', 'Unknown error')}"
    except Exception as e:
        return f"❌ AI Error: {str(e)}"


async def get_video_url(url: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "yt-dlp", "--dump-json", "--no-playlist",
            "-f", "best[ext=mp4][filesize<50M]/best[ext=mp4]/best",
            "--no-warnings", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return {
                "success": True,
                "url": data.get("url", ""),
                "title": data.get("title", "Video"),
                "duration": data.get("duration_string", ""),
                "filesize": data.get("filesize", 0)
            }
        return {"success": False, "error": stderr.decode()[:300]}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Timed out. Try a shorter video."}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def get_audio_url(url: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "yt-dlp", "--dump-json", "--no-playlist",
            "-f", "bestaudio[ext=m4a]/bestaudio/best",
            "--no-warnings", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return {
                "success": True,
                "url": data.get("url", ""),
                "title": data.get("title", "Audio"),
                "ext": data.get("ext", "mp3")
            }
        return {"success": False, "error": stderr.decode()[:300]}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Timed out. Try again."}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        # ✅ FIX: every request opens a fresh sqlite connection (auto-save,
        # log-message, registration, etc. all hit the DB on every WhatsApp
        # message / panel request). In the default journal mode, concurrent
        # writes can block each other for the full busy timeout, which stacks
        # up as multi-second delays on bot replies. WAL mode lets reads/writes
        # run concurrently instead of serializing on a file lock.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                sender TEXT PRIMARY KEY, name TEXT, timestamp REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (sender TEXT PRIMARY KEY)
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY, sender TEXT, name TEXT, body TEXT, timestamp REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS viewonce_media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT, name TEXT, filename TEXT,
                media_type TEXT, caption TEXT, timestamp REAL
            )
        """)
        # ✅ FIX: .schedule used to live only in client_bridge.js's in-memory
        # global.scheduledMessages — any restart/redeploy silently dropped
        # every pending scheduled message with no warning to whoever set it.
        # Now persisted here so client_bridge.js can reload it on boot.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_messages (
                id TEXT PRIMARY KEY,
                to_jid TEXT, message TEXT,
                next_run REAL, repeat TEXT,
                sent INTEGER DEFAULT 0,
                created_by TEXT
            )
        """)
        # NEW: keyword auto-reply table - admin-managed trigger/response pairs
        await db.execute("""
            CREATE TABLE IF NOT EXISTS keywords (
                trigger TEXT PRIMARY KEY,
                reply TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'contains',
                enabled INTEGER NOT NULL DEFAULT 1,
                timestamp REAL
            )
        """)
        # NEW: feature toggle table - admin can flip modules on/off without redeploying
        await db.execute("""
            CREATE TABLE IF NOT EXISTS features (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        """)
        # NEW: auto-saved status media log
        await db.execute("""
            CREATE TABLE IF NOT EXISTS status_media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT, name TEXT, filename TEXT,
                media_type TEXT, caption TEXT, timestamp REAL
            )
        """)
        # NEW: anti-link warning strikes, per group per sender
        await db.execute("""
            CREATE TABLE IF NOT EXISTS group_warnings (
                group_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, sender)
            )
        """)
        # NEW: panel registration — phone+email verification, trust badges, credits
        await db.execute("""
            CREATE TABLE IF NOT EXISTS registrations (
                phone TEXT PRIMARY KEY,
                name TEXT,
                email TEXT,
                otp TEXT,
                otp_expiry REAL,
                verified INTEGER NOT NULL DEFAULT 0,
                credits INTEGER NOT NULL DEFAULT 0,
                badge TEXT NOT NULL DEFAULT 'none',
                created_at REAL,
                verified_at REAL,
                referred_by TEXT,
                referral_bonus_given INTEGER NOT NULL DEFAULT 0,
                password_hash TEXT
            )
        """)
        # Best-effort migration for DBs created before the referral/password
        # columns existed — ALTER TABLE ... ADD COLUMN throws if the column
        # is already there, so each is wrapped individually and ignored.
        for col, ddl in [
            ("referred_by", "ALTER TABLE registrations ADD COLUMN referred_by TEXT"),
            ("referral_bonus_given", "ALTER TABLE registrations ADD COLUMN referral_bonus_given INTEGER NOT NULL DEFAULT 0"),
            ("password_hash", "ALTER TABLE registrations ADD COLUMN password_hash TEXT"),
            ("reset_otp_attempts", "ALTER TABLE registrations ADD COLUMN reset_otp_attempts INTEGER NOT NULL DEFAULT 0"),
        ]:
            try:
                await db.execute(ddl)
            except Exception:
                pass
        # NEW: referral audit log — one row per successful referral payout,
        # so .myreferrals / an admin can see who referred whom and when.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_phone TEXT NOT NULL,
                referred_phone TEXT NOT NULL,
                referrer_bonus INTEGER NOT NULL,
                referred_bonus INTEGER NOT NULL,
                created_at REAL
            )
        """)
        # NEW: wallet top-up requests — user claims they sent M-Pesa funds to
        # the admin and submits the transaction code (+ optional screenshot).
        # Nothing here is auto-trusted: status starts 'pending' and only an
        # admin approving it from /admin moves kesh into the wallet. The
        # mpesa_code UNIQUE constraint stops the same code being replayed
        # twice (a common fake-payment trick).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                name TEXT,
                amount INTEGER NOT NULL,
                mpesa_code TEXT NOT NULL UNIQUE,
                screenshot_path TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                admin_note TEXT,
                created_at REAL,
                reviewed_at REAL
            )
        """)
        for default_feature in ("ai_chat", "downloads", "keywords",
                                 "status_save", "antilink", "menu_buttons"):
            await db.execute(
                "INSERT OR IGNORE INTO features (name, enabled) VALUES (?, 1)",
                (default_feature,)
            )
        # ✅ NEW: owner-controllable switch for ban-recovery behavior (was a
        # hardcoded env var, ANTIBAN_NOTIFY_ONLY, that silently let sends
        # through during a WA ban-recovery pause). Defaults OFF — i.e. the
        # SAFE/STRICT behavior (block sends during recovery) — since the
        # notify-only override is what led to the 2026-07-03 unlink incident.
        # Owner can flip it on from the Admin Panel → Features if they'd
        # rather be pinged than blocked, and back off again any time.
        await db.execute(
            "INSERT OR IGNORE INTO features (name, enabled) VALUES (?, 0)",
            ("antiban_notify_only",)
        )
        # ✅ NEW: paid pairing / activation-key system — every newly paired
        # customer session starts LOCKED (can't run commands) until it's
        # unlocked with a random key issued by the admin after payment.
        # Survives restarts, unlike in-memory SESSION_REGISTRY.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS session_subscriptions (
                session TEXT PRIMARY KEY,
                phone TEXT,
                activated INTEGER NOT NULL DEFAULT 0,
                activated_at REAL,
                expiry_ts REAL,
                subscription_days INTEGER,
                request_status TEXT NOT NULL DEFAULT 'none',
                requester_chat TEXT,
                pending_key TEXT,
                pending_key_expires_at REAL,
                created_at REAL,
                updated_at REAL
            )
        """)
        # ✅ NEW: admin_settings — lets the admin password be changed at
        # runtime (via "forgot password" reset) instead of being permanently
        # fixed to whatever ADMIN_PASSWORD was set to at deploy time.
        # Also holds the (hashed, one-time) reset code state.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        # ✅ NEW: activity_log — central event feed for the admin panel.
        # category is one of: 'command' (every command anyone runs),
        # 'error' (a command/download/etc. failed), 'sensitive' (an
        # owner/admin-tier action was taken — kick, promote, payment review,
        # login, broadcast, etc.). client_bridge.js writes here on every
        # dispatch; 'error' and 'sensitive' rows also trigger a live WhatsApp
        # ping to the owner, 'command' rows are panel-only (too high-volume
        # to WhatsApp-notify on every single one).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                type TEXT NOT NULL,
                actor TEXT,
                detail TEXT,
                timestamp REAL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_cat_ts ON activity_log(category, timestamp)")

        # ✅ NEW: global anti-ban kill-switch ("in general", across every
        # session at once) — separate from each session's own per-number
        # antiban_enabled column on session_subscriptions. A session is only
        # actually protected while BOTH this global switch AND its own
        # per-number switch are on. Defaults ON (protection stays on unless
        # an admin deliberately turns it off from Admin Panel → Features).
        await db.execute(
            "INSERT OR IGNORE INTO features (name, enabled) VALUES (?, 1)",
            ("antiban_enabled",)
        )

        # ✅ NEW: is_owner_session flags the one session paired to the admin's
        # own OWNER_NUMBER — surfaced in the Admin Panel as "🔑 Owner Session"
        # (no limit, no expiry, never needs a key). antiban_enabled is the
        # PER-NUMBER anti-ban on/off switch (default ON); a separate global
        # switch lives in `features` as 'antiban_enabled' — a session is only
        # actually protected when BOTH are on.
        for col, ddl in [
            ("is_owner_session", "ALTER TABLE session_subscriptions ADD COLUMN is_owner_session INTEGER NOT NULL DEFAULT 0"),
            ("antiban_enabled", "ALTER TABLE session_subscriptions ADD COLUMN antiban_enabled INTEGER NOT NULL DEFAULT 1"),
            # ✅ NEW: handled_by — phone number of the sub-admin/co-owner who
            # approved or is otherwise responsible for this customer session.
            # Lets sub-admins generate activation keys and extend/upgrade
            # only the sessions they personally onboarded, while co-owners
            # and the primary owner remain unrestricted across all sessions.
            ("handled_by", "ALTER TABLE session_subscriptions ADD COLUMN handled_by TEXT"),
        ]:
            try:
                await db.execute(ddl)
            except Exception:
                pass

        # ✅ NEW (extended-commands update): everything below is additive —
        # new tables only, nothing above this line was touched. Powers the
        # new plugins/extended.js command set (group intel, polls, reports,
        # bans, per-chat settings/persona/memory).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS group_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                name TEXT,
                body TEXT,
                timestamp REAL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_group_activity_group_ts ON group_activity(group_id, timestamp)")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS group_relations (
                group_id TEXT NOT NULL,
                user_a TEXT NOT NULL,
                user_b TEXT NOT NULL,
                weight INTEGER DEFAULT 1,
                PRIMARY KEY (group_id, user_a, user_b)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS polls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                question TEXT NOT NULL,
                options TEXT NOT NULL,
                created_by TEXT,
                active INTEGER DEFAULT 1,
                created_at REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS poll_votes (
                poll_id INTEGER NOT NULL,
                voter TEXT NOT NULL,
                option_index INTEGER NOT NULL,
                PRIMARY KEY (poll_id, voter)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT,
                reporter TEXT,
                target TEXT,
                reason TEXT,
                timestamp REAL,
                resolved INTEGER DEFAULT 0
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS group_bans (
                group_id TEXT NOT NULL,
                number TEXT NOT NULL,
                reason TEXT,
                banned_at REAL,
                PRIMARY KEY (group_id, number)
            )
        """)

        # Generic per-chat KV store — backs .persona, .remember/.recall
        # (key prefixed "mem:"), .silence, .antidelete, .autoview,
        # .autoreact, .fullpp default. One table instead of five, same
        # pattern as the existing admin_settings KV table above.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (chat_id, key)
            )
        """)

        # ✅ NEW: customer chat panel — public room + DMs, anonymous by
        # default. chat_users tracks an anon identity (generated client-side
        # ID, persisted in the browser) with an optional nickname. Messages
        # are snapshotted with sender_name at send time so a later nickname
        # change doesn't rewrite history.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chat_users (
                anon_id TEXT PRIMARY KEY,
                nickname TEXT,
                created_at REAL,
                last_seen REAL,
                banned INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                sender_name TEXT,
                body TEXT NOT NULL,
                created_at REAL,
                deleted INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_room_id ON chat_messages(room, id)")
        # Helper index so a user's DM inbox can be listed without scanning
        # every message — one row per DM thread, keyed by a canonical room
        # id (sorted pair of anon_ids), updated on every DM send.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chat_dm_index (
                room TEXT PRIMARY KEY,
                user_a TEXT NOT NULL,
                user_b TEXT NOT NULL,
                last_message_at REAL
            )
        """)

        await db.commit()
        logger.info("\033[1;32m⚡ Henry Ochibots v19™ — Master Database Synchronized — All tables ready.\033[0m")


@app.before_serving
async def startup():
    await init_db()
    logger.info("\033[1;36m🔥 Henry Ochibots v19™ Backend LIVE on port %s\033[0m", os.environ.get("PORT", 5000))
    logger.info("\033[1;33m📡 Waiting for WhatsApp bot session (Node.js) to connect...\033[0m")
    if not ADMIN_PASSWORD:
        logger.warning("\033[1;31m⚠️  ADMIN_PASSWORD is not set — /admin has FULL OPEN ACCESS to anyone with the URL. Set ADMIN_PASSWORD in your environment before going live.\033[0m")


async def check_db_blacklist(sender: str) -> bool:
    if not sender:
        return False
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT 1 FROM blacklist WHERE sender = ?", (sender,)) as c:
            return (await c.fetchone()) is not None


async def is_feature_enabled(name: str) -> bool:
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT enabled FROM features WHERE name = ?", (name,)) as c:
            row = await c.fetchone()
            return True if row is None else bool(row[0])


async def match_keyword(text: str):
    """Return the configured reply if text matches an enabled keyword trigger, else None."""
    if not text:
        return None
    lowered = text.lower().strip()
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT trigger, reply, match_type FROM keywords WHERE enabled = 1"
        ) as c:
            rows = await c.fetchall()
    for trigger, reply, match_type in rows:
        t = (trigger or "").lower().strip()
        if not t:
            continue
        if match_type == "exact" and lowered == t:
            return reply
        if match_type == "starts_with" and lowered.startswith(t):
            return reply
        if match_type == "contains" and t in lowered:
            return reply
    return None


@app.route("/")
async def landing_page():
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        html_text = index_path.read_text(encoding="utf-8")
        contact_number = os.environ.get("PUBLIC_CONTACT_NUMBER", "").replace("+", "").replace(" ", "")
        if contact_number:
            html_text = html_text.replace("{{PUBLIC_CONTACT_NUMBER}}", contact_number)
        else:
            # No contact number configured — remove the whole button rather
            # than ship a dead/placeholder wa.me link.
            html_text = _re.sub(
                r'<a href="https://wa\.me/\{\{PUBLIC_CONTACT_NUMBER\}\}"[^>]*id="contact-whatsapp-btn"[^>]*>.*?</a>',
                "", html_text, flags=_re.DOTALL
            )
        return Response(html_text, mimetype="text/html", headers=NO_CACHE_HEADERS)
    return jsonify({"status": "ok"})


@app.route("/status")
async def status_check():
    # Lives on the Python side because hosting platforms (Render, etc.)
    # route external traffic to whatever port app.py binds to via $PORT —
    # not to the Node bridge's internal-only WEB_PORT.
    return jsonify({"status": "ok"})


@app.route("/register")
async def register_page():
    reg_path = Path(__file__).parent / "register.html"
    if reg_path.exists():
        return Response(reg_path.read_text(encoding="utf-8"), mimetype="text/html", headers=NO_CACHE_HEADERS)
    return jsonify({"status": "ok"})


@app.route("/api/register", methods=["POST"])
async def api_register():
    """Step 1: user submits their WhatsApp number (+ optional name/email) ->
    we generate an OTP and send it via whichever delivery method they chose
    (WhatsApp from the bot, or email as a fallback for anyone whose WhatsApp
    session/bot isn't reachable right now)."""
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    method = (data.get("method") or "whatsapp").strip().lower()
    ref = (data.get("ref") or "").strip().replace(" ", "").replace("+", "")
    password = data.get("password") or ""

    if not phone or not phone.isdigit() or len(phone) < 9:
        return jsonify({"success": False, "error": "Enter a valid WhatsApp number with country code."}), 400

    # ✅ NEW: Henry's own number is managed exclusively from the Admin
    # Panel — it never goes through the public customer registration flow.
    owner_number = await _get_effective_owner_number()
    if owner_number and phone == owner_number:
        return jsonify({"success": False, "error": "This number is managed from the Admin Panel, not customer registration."}), 403

    if not name:
        return jsonify({"success": False, "error": "Enter your name."}), 400

    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."}), 400

    if method == "email":
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            return jsonify({"success": False, "error": "Enter a valid email address."}), 400
    elif method != "whatsapp":
        return jsonify({"success": False, "error": "Invalid delivery method."}), 400

    # A referral code is just the referrer's own verified phone number.
    # Reject self-referral and codes that don't match a verified account —
    # otherwise this becomes a free way to mint bonus credits.
    valid_ref = None
    if ref and ref != phone and ref.isdigit():
        async with aiosqlite.connect(DB_FILE) as db:
            async with db.execute("SELECT verified FROM registrations WHERE phone = ?", (ref,)) as c:
                ref_row = await c.fetchone()
        if ref_row and ref_row[0] == 1:
            valid_ref = ref

    otp = _generate_otp()
    now = time.time()
    password_hash = _hash_password(password)

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT verified FROM registrations WHERE phone = ?", (phone,)) as c:
            row = await c.fetchone()
        if row and row[0] == 1:
            return jsonify({"success": False, "error": "This number is already verified. Use the panel login instead."}), 400

        await db.execute("""
            INSERT INTO registrations (phone, name, email, otp, otp_expiry, verified, credits, badge, created_at, referred_by, password_hash)
            VALUES (?, ?, ?, ?, ?, 0, 0, 'none', ?, ?, ?)
            ON CONFLICT(phone) DO UPDATE SET
                name=excluded.name, email=excluded.email, otp=excluded.otp,
                otp_expiry=excluded.otp_expiry,
                referred_by=COALESCE(registrations.referred_by, excluded.referred_by),
                password_hash=excluded.password_hash
        """, (phone, name, email, otp, now + OTP_TTL_SECONDS, now, valid_ref, password_hash))
        await db.commit()

    if method == "email":
        result = await send_otp_email(email, otp, name)
    else:
        result = await send_otp_whatsapp(phone, otp, name)
    if not result["success"]:
        return jsonify({"success": False, "error": result["error"]}), 500

    return jsonify({
        "success": True,
        "message": "OTP sent to your email. Enter it below to verify." if method == "email"
                   else "OTP sent to your WhatsApp. Enter it below to verify."
    })


@app.route("/api/verify-otp", methods=["POST"])
async def api_verify_otp():
    """Step 2: user submits phone + OTP -> verify, award trust badge + free credits."""
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    otp = (data.get("otp") or "").strip()

    if not phone or not otp:
        return jsonify({"success": False, "error": "Phone and OTP are required."}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT otp, otp_expiry, verified, name, referred_by FROM registrations WHERE phone = ?", (phone,)
        ) as c:
            row = await c.fetchone()

        if not row:
            return jsonify({"success": False, "error": "No registration found for this number."}), 404

        stored_otp, expiry, verified, name, referred_by = row
        if verified:
            return jsonify({"success": False, "error": "Already verified."}), 400
        if time.time() > expiry:
            return jsonify({"success": False, "error": "OTP expired. Please register again."}), 400
        if otp != stored_otp:
            return jsonify({"success": False, "error": "Incorrect OTP."}), 400

        await db.execute("""
            UPDATE registrations
            SET verified = 1, badge = 'Trusted', credits = credits + ?, verified_at = ?
            WHERE phone = ?
        """, (REG_STARTER_CREDITS, time.time(), phone))

        referral_message = ""
        total_credits = REG_STARTER_CREDITS
        if referred_by:
            # Re-check the referrer is still a verified account at payout time
            # (defensive — they were checked at registration too).
            async with db.execute("SELECT verified FROM registrations WHERE phone = ?", (referred_by,)) as c:
                ref_row = await c.fetchone()
            if ref_row and ref_row[0] == 1:
                await db.execute(
                    "UPDATE registrations SET credits = credits + ? WHERE phone = ?",
                    (REFERRAL_REFERRER_BONUS, referred_by)
                )
                await db.execute(
                    "UPDATE registrations SET credits = credits + ?, referral_bonus_given = 1 WHERE phone = ?",
                    (REFERRAL_REFERRED_BONUS, phone)
                )
                await db.execute("""
                    INSERT INTO referrals (referrer_phone, referred_phone, referrer_bonus, referred_bonus, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (referred_by, phone, REFERRAL_REFERRER_BONUS, REFERRAL_REFERRED_BONUS, time.time()))
                total_credits += REFERRAL_REFERRED_BONUS
                referral_message = f" Plus a {REFERRAL_REFERRED_BONUS} kesh referral bonus for signing up via invite!"

        await db.commit()

    return jsonify({
        "success": True,
        "message": f"Number verified! 🛡️ Trust badge unlocked + {REG_STARTER_CREDITS} kesh free credit added.{referral_message}",
        "badge": "Trusted",
        "credits": total_credits
    })


@app.route("/api/forgot-password", methods=["POST"])
async def api_forgot_password():
    """
    ✅ NEW: "forgot panel password" for regular registered users (the
    Name/Number/Password login at /panel — separate from /admin).
    Sends a one-time 6-digit code to the user's OWN registered WhatsApp
    number (reusing send_otp_whatsapp), reusing the same otp/otp_expiry
    columns already on `registrations` for the registration-verify flow.
    Safe to reuse: /api/verify-otp only acts on accounts that are NOT YET
    verified, and this only acts on accounts that ARE verified, so the two
    flows never collide on the same row.
    """
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    if not phone or not phone.isdigit():
        return jsonify({"success": False, "error": "Valid WhatsApp number required."}), 400

    now = time.time()
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT name, verified, otp_expiry FROM registrations WHERE phone = ?", (phone,)
        ) as c:
            row = await c.fetchone()

        if not row:
            return jsonify({"success": False, "error": "No account found for this number. Register first."}), 404
        name, verified, otp_expiry = row
        if not verified:
            return jsonify({"success": False, "error": "This number isn't verified yet. Complete registration first."}), 403

        # Cooldown: block re-requesting while a still-fresh code was sent
        # less than 60s ago, so this can't be used to spam a number.
        if otp_expiry and (otp_expiry - OTP_TTL_SECONDS) > (now - RESET_REQUEST_COOLDOWN_SECONDS):
            wait = int(RESET_REQUEST_COOLDOWN_SECONDS - (now - (otp_expiry - OTP_TTL_SECONDS)))
            return jsonify({"success": False, "error": f"Please wait {max(wait, 1)}s before requesting another code."}), 429

        otp = _generate_otp()
        await db.execute(
            "UPDATE registrations SET otp = ?, otp_expiry = ?, reset_otp_attempts = 0 WHERE phone = ?",
            (otp, now + OTP_TTL_SECONDS, phone)
        )
        await db.commit()

    result = await send_otp_whatsapp(phone, otp, name)
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error", "Couldn't send the reset code. Is the bot connected to WhatsApp?")}), 502

    return jsonify({"success": True, "message": "A reset code was sent to your WhatsApp. It expires in 10 minutes."})


@app.route("/api/reset-password", methods=["POST"])
async def api_reset_password():
    """Step 2 of panel password reset: verify the code and set a new password."""
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    otp = (data.get("otp") or "").strip()
    new_password = data.get("new_password") or ""

    if not phone or not phone.isdigit():
        return jsonify({"success": False, "error": "Valid WhatsApp number required."}), 400
    if not otp:
        return jsonify({"success": False, "error": "Enter the code sent to your WhatsApp."}), 400
    if len(new_password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT otp, otp_expiry, verified, reset_otp_attempts FROM registrations WHERE phone = ?", (phone,)
        ) as c:
            row = await c.fetchone()

        if not row:
            return jsonify({"success": False, "error": "No account found for this number."}), 404
        stored_otp, expiry, verified, attempts = row
        if not verified:
            return jsonify({"success": False, "error": "This number isn't verified yet."}), 403
        if not stored_otp or not expiry:
            return jsonify({"success": False, "error": "No reset code was requested. Tap 'Forgot password' first."}), 400
        if (attempts or 0) >= RESET_OTP_MAX_ATTEMPTS:
            await db.execute(
                "UPDATE registrations SET otp = NULL, otp_expiry = NULL, reset_otp_attempts = 0 WHERE phone = ?",
                (phone,)
            )
            await db.commit()
            return jsonify({"success": False, "error": "Too many wrong attempts. Request a new code."}), 429
        if time.time() > expiry:
            return jsonify({"success": False, "error": "That code expired. Request a new one."}), 400
        if otp != stored_otp:
            await db.execute(
                "UPDATE registrations SET reset_otp_attempts = reset_otp_attempts + 1 WHERE phone = ?",
                (phone,)
            )
            await db.commit()
            return jsonify({"success": False, "error": "Incorrect code."}), 401

        await db.execute(
            "UPDATE registrations SET password_hash = ?, otp = NULL, otp_expiry = NULL, reset_otp_attempts = 0 WHERE phone = ?",
            (_hash_password(new_password), phone)
        )
        await db.commit()

    return jsonify({"success": True, "message": "Password updated! You can log in with your new password now."})


@app.route("/api/referrals", methods=["GET"])
async def api_referrals():
    """Referral summary for a verified user: their referral code (their own
    phone number), total kesh earned from referrals, and the list of people
    who signed up using their code."""
    phone = (request.args.get("phone") or "").strip().replace(" ", "").replace("+", "")
    if not phone or not phone.isdigit():
        return jsonify({"success": False, "error": "Valid phone number required."}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT verified FROM registrations WHERE phone = ?", (phone,)) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Not registered yet. Send *.register* to the bot first."}), 404
        if not row[0]:
            return jsonify({"success": False, "error": "Verify your number first — send *.register*."}), 403

        async with db.execute(
            "SELECT referred_phone, referrer_bonus, created_at FROM referrals WHERE referrer_phone = ? ORDER BY created_at DESC",
            (phone,)
        ) as c:
            rows = await c.fetchall()

    total_earned = sum(r[1] for r in rows)
    return jsonify({
        "success": True,
        "referral_code": phone,
        "total_referrals": len(rows),
        "total_earned": total_earned,
        "referrer_bonus": REFERRAL_REFERRER_BONUS,
        "referred_bonus": REFERRAL_REFERRED_BONUS,
        "referrals": [{"phone": r[0], "bonus": r[1], "created_at": r[2]} for r in rows]
    })



@app.route("/panel")
async def panel_page():
    panel_path = Path(__file__).parent / "panel.html"
    if panel_path.exists():
        return Response(panel_path.read_text(encoding="utf-8"), mimetype="text/html", headers=NO_CACHE_HEADERS)
    return jsonify({"status": "ok"})


@app.route("/chat")
async def chat_page():
    """✅ NEW: community chat panel — public room + DMs, anonymous by
    default. No login required, just an anon identity generated on first
    load (see /chat/identify)."""
    chat_path = Path(__file__).parent / "chat.html"
    if chat_path.exists():
        return Response(chat_path.read_text(encoding="utf-8"), mimetype="text/html", headers=NO_CACHE_HEADERS)
    return jsonify({"status": "ok"})


async def _verify_panel_login(phone: str, name: str, password: str):
    """Shared auth for anything gated behind 'name + phone + panel password'
    (currently /api/profile and /api/subscription/buy). Returns
    (True, user_row_dict) on success, or (False, (json_body, status_code))
    on failure — caller just does `return err` on failure.

    ✅ Factored out of api_profile so the brute-force lockout, password
    check, and name-match logic live in exactly one place instead of being
    copy-pasted (and possibly drifting) across every endpoint that needs
    the same login.
    """
    if not phone or not phone.isdigit():
        return False, (jsonify({"success": False, "error": "Valid phone number required."}), 400)
    if not name or not password:
        return False, (jsonify({"success": False, "error": "Enter your name, WhatsApp number, and password."}), 400)

    now = time.time()
    lock_entry = _panel_login_failures.get(phone)
    if lock_entry and lock_entry.get("locked_until", 0) > now:
        return False, (jsonify({"success": False, "error": "Too many failed attempts. Try again in a few minutes."}), 429)

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT name, email, verified, credits, badge, verified_at, created_at, password_hash FROM registrations WHERE phone = ?",
            (phone,)
        ) as c:
            row = await c.fetchone()
        if not row:
            return False, (jsonify({"success": False, "error": "Not registered yet. Send *.register* to the bot first."}), 404)

        stored_name, email, verified, credits, badge, verified_at, created_at, password_hash = row

        if not verified:
            return False, (jsonify({"success": False, "error": "Verify your number first — send *.register*."}), 403)
        if not password_hash or not _verify_password(password, password_hash):
            if not lock_entry or now - lock_entry.get("window_start", now) > ADMIN_LOCKOUT_WINDOW_SECONDS:
                lock_entry = {"fails": 0, "window_start": now}
            lock_entry["fails"] = lock_entry.get("fails", 0) + 1
            if lock_entry["fails"] >= ADMIN_LOCKOUT_THRESHOLD:
                lock_entry["locked_until"] = now + ADMIN_LOCKOUT_DURATION_SECONDS
            _panel_login_failures[phone] = lock_entry
            return False, (jsonify({"success": False, "error": "Incorrect password."}), 401)
        if stored_name.strip().lower() != name.strip().lower():
            return False, (jsonify({"success": False, "error": "Name doesn't match our records for this number."}), 403)

        _panel_login_failures.pop(phone, None)

    return True, {
        "phone": phone, "name": stored_name, "email": email, "verified": bool(verified),
        "credits": credits, "badge": badge, "verified_at": verified_at, "created_at": created_at,
    }


async def _find_bot_session_for_phone(phone: str):
    """Look up the WhatsApp bot session linked to this customer's own
    number (the number they paired their bot with — same number they log
    into the panel with). Session identity/expiry is persisted in
    session_subscriptions (survives restarts); live antiban/online data
    only exists in the in-memory SESSION_REGISTRY while that session is
    actually connected. Returns None if this phone has no linked session
    yet (e.g. hasn't paired a bot)."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT session, activated, expiry_ts, subscription_days FROM session_subscriptions "
            "WHERE phone = ? ORDER BY updated_at DESC LIMIT 1",
            (phone,)
        ) as c:
            row = await c.fetchone()
    if not row:
        return None
    session, activated, expiry_ts, subscription_days = row
    live = SESSION_REGISTRY.get(session, {})
    return {
        "session": session,
        "activated": bool(activated),
        "expiry_ts": expiry_ts,
        "expiry_display": time.strftime("%d %b %Y, %H:%M", time.localtime(expiry_ts)) if expiry_ts else None,
        "expired": bool(expiry_ts and time.time() >= expiry_ts),
        "subscription_days": subscription_days,
        "online": live.get("online", False),
        "antiban_risk": live.get("antiban_risk"),
        "antiban_warmup_day": live.get("antiban_warmup_day"),
        "antiban_warmup_total": live.get("antiban_warmup_total"),
    }


@app.route("/api/profile", methods=["POST"])
async def api_profile():
    """Profile panel data for a verified user — wallet balance, badge,
    recent top-up requests with their review status, and (✅ NEW) their own
    linked bot session's antiban health + subscription status. Each user
    only ever sees their own session's numbers here — this is deliberately
    NOT the aggregated "worst session" view /admin shows.

    ✅ FIX: this function existed in the codebase with no @app.route above
    it, so it was dead code — nothing could ever call it, and the profile
    panel it was written for was never reachable. Now wired up properly.

    ✅ Also fixed: it was designed to trust a bare phone number with no
    password, which would have exposed wallet balance and M-Pesa payment
    history to anyone who guessed/knew a registered number. Now requires
    name + phone + the password set at registration, matching how
    /api/register and the rest of the panel login work.
    """
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    ok, result = await _verify_panel_login(phone, name, password)
    if not ok:
        body, status = result
        return body, status
    user = result

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, amount, mpesa_code, status, created_at FROM payments WHERE phone = ? ORDER BY created_at DESC LIMIT 10",
            (phone,)
        ) as c:
            prows = await c.fetchall()

    bot_session = await _find_bot_session_for_phone(phone)

    return jsonify({
        "success": True,
        "phone": phone,
        "name": user["name"],
        "email": user["email"],
        "verified": user["verified"],
        "credits": user["credits"],
        "badge": user["badge"] if user["verified"] else "none",
        "verified_at": user["verified_at"],
        "member_since": user["created_at"],
        "recent_payments": [
            {"id": p[0], "amount": p[1], "mpesa_code": p[2], "status": p[3], "created_at": p[4]}
            for p in prows
        ],
        # ✅ NEW: this customer's own bot session — antiban health and
        # subscription/expiry status. None if they haven't paired a bot yet
        # (registering a wallet account and pairing a bot are separate
        # steps). Deliberately just THIS session, not every session like
        # /admin/stats shows — each customer's numbers are their own.
        "bot_session": bot_session,
    })


@app.route("/api/payment-info", methods=["GET"])
async def api_payment_info():
    """Public info the panel's top-up form needs: where to send M-Pesa
    funds. No auth required — this is just instructions, not user data."""
    return jsonify({
        "success": True,
        "payto_number": ADMIN_PAYTO_NUMBER,
        "configured": bool(ADMIN_PAYTO_NUMBER)
    })


@app.route("/api/subscription-pricing", methods=["GET"])
async def api_subscription_pricing_get():
    """✅ NEW: public read of the kesh-per-day price for buying extra bot
    subscription time from the wallet. Separate from /api/pricing (which is
    the config-reselling text) — this is a numeric price used to compute
    the cost of a specific number of days in the panel's Buy Subscription
    Time section."""
    settings = await _get_activation_settings()
    return jsonify({
        "success": True,
        "kesh_per_day": int(settings.get("subscription_kesh_per_day", 10)),
    })


@app.route("/api/subscription/buy", methods=["POST"])
async def api_subscription_buy():
    """✅ NEW: let a logged-in customer extend their OWN bot's subscription
    using their wallet (kesh) balance — no admin approval needed, unlike
    .addfunds top-ups. This is deliberately separate from the .pricing /
    .setprice config-reselling flow: that sells access to internet-bundle
    configs, this sells extra days of the customer's own bot staying
    activated. Requires the same name+phone+password login as /api/profile.
    """
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    ok, result = await _verify_panel_login(phone, name, password)
    if not ok:
        body, status = result
        return body, status
    user = result

    try:
        days = int(data.get("days"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Enter a whole number of days."}), 400
    if days < 1 or days > 365:
        return jsonify({"success": False, "error": "Choose between 1 and 365 days."}), 400

    bot_session = await _find_bot_session_for_phone(phone)
    if not bot_session:
        return jsonify({
            "success": False,
            "error": "No bot session is linked to this number yet. Pair your bot first at /pair, then come back to buy subscription time."
        }), 404

    settings = await _get_activation_settings()
    kesh_per_day = int(settings.get("subscription_kesh_per_day", 10))
    cost = days * kesh_per_day

    if user["credits"] < cost:
        return jsonify({
            "success": False,
            "error": f"Not enough kesh. This costs {cost} kesh ({kesh_per_day}/day × {days} days) but your balance is {user['credits']} kesh. Top up with *.addfunds* first."
        }), 402

    now = time.time()
    base = bot_session["expiry_ts"] if (bot_session["expiry_ts"] and bot_session["expiry_ts"] > now) else now
    new_expiry = base + (days * 86400)
    session = bot_session["session"]

    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE registrations SET credits = credits - ? WHERE phone = ?", (cost, phone))
        await db.execute(
            "UPDATE session_subscriptions SET activated = 1, activated_at = COALESCE(activated_at, ?), "
            "expiry_ts = ?, subscription_days = COALESCE(subscription_days, 0) + ?, updated_at = ? WHERE session = ?",
            (now, new_expiry, days, now, session)
        )
        await db.execute(
            "INSERT INTO activity_log (category, type, actor, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
            ("sensitive", "subscription_purchase", phone,
             f"Bought {days} day(s) for session '{session}' — {cost} kesh spent, new expiry {time.strftime('%d %b %Y, %H:%M', time.localtime(new_expiry))}",
             now)
        )
        await db.commit()

    # Reflect immediately in the live admin view too, not just after the
    # next ~2min /admin/update-session ping from the Node bridge.
    if session in SESSION_REGISTRY:
        SESSION_REGISTRY[session]["expiry_ts"] = new_expiry

    return jsonify({
        "success": True,
        "days_added": days,
        "cost": cost,
        "remaining_credits": user["credits"] - cost,
        "expiry_ts": new_expiry,
        "expiry_display": time.strftime("%d %b %Y, %H:%M", time.localtime(new_expiry)),
    })


@app.route("/api/pricing", methods=["GET"])
async def api_pricing_get():
    """✅ NEW: public read of whatever pricing text the admin has set via
    .setprice or the panel. No auth needed — this is meant to be shown to
    prospective customers. Returns a friendly default if never set, so a
    fresh deploy doesn't show a blank/broken response."""
    text = await _get_admin_setting("pricing_text")
    return jsonify({
        "success": True,
        "pricing": text or (
            "Airtel/Telkom Premium — 50 kesh / 30 days\n"
            "Airtel/Telkom 24H — 15 kesh / 24 hours\n\n"
            "(Admin hasn't customized this yet — send *.setprice* to update it.)"
        ),
    })


@app.route("/admin/pricing", methods=["POST"])
async def api_pricing_set():
    """Owner-only: update the pricing text shown by .pricing / the public
    site. Stored as plain text, not structured — deliberately simple since
    prices here are quoted manually, not enforced programmatically."""
    if not await _check_admin_auth_async(request):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    text = (data.get("pricing") or "").strip()
    if not text:
        return jsonify({"success": False, "error": "Pricing text can't be empty."}), 400
    if len(text) > 2000:
        return jsonify({"success": False, "error": "Keep it under 2000 characters."}), 400
    await _set_admin_setting("pricing_text", text)
    return jsonify({"success": True})


@app.route("/api/payment/submit", methods=["POST"])
async def api_payment_submit():
    """User claims they sent kesh to the admin's M-Pesa number and submits
    the transaction code (+ optional screenshot as base64) for review.

    Important: this endpoint does NOT and CANNOT confirm the code is real —
    there's no Safaricom Daraja/M-Pesa API integration here. It only does
    cheap, honest checks (format looks like a real M-Pesa code, the code
    hasn't been used before, the user is a verified registrant) and then
    queues it as 'pending' for a human admin to approve from the Payments
    tab. Credits are added only on admin approval, never automatically.
    """
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    amount = data.get("amount")
    mpesa_code = (data.get("mpesa_code") or "").strip().upper()
    screenshot_b64 = data.get("screenshot_base64")  # optional, data-URL or raw base64

    if not phone or not phone.isdigit():
        return jsonify({"success": False, "error": "Valid phone number required."}), 400
    try:
        amount = int(amount)
        if amount <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Amount must be a positive whole number."}), 400
    if not MPESA_CODE_RE.match(mpesa_code):
        return jsonify({"success": False, "error": "That doesn't look like a valid M-Pesa transaction code (8-12 letters/numbers, e.g. QFG7H8J9K0)."}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT verified FROM registrations WHERE phone = ?", (phone,)) as c:
            reg = await c.fetchone()
        if not reg or not reg[0]:
            return jsonify({"success": False, "error": "Verify your number first — send *.register* to the bot."}), 403

        async with db.execute("SELECT id, status FROM payments WHERE mpesa_code = ?", (mpesa_code,)) as c:
            dup = await c.fetchone()
        if dup:
            return jsonify({"success": False, "error": f"This transaction code was already submitted (status: {dup[1]}). Each code can only be used once."}), 409

        screenshot_path = None
        if screenshot_b64:
            try:
                raw = screenshot_b64.split(",", 1)[-1]  # strip data: URL prefix if present
                img_bytes = _b64.b64decode(raw)
                if len(img_bytes) > 6 * 1024 * 1024:
                    return jsonify({"success": False, "error": "Screenshot too large (max 6MB)."}), 400
                fname = f"{phone}_{mpesa_code}_{int(time.time())}.jpg"
                (PAYMENT_PROOFS_DIR / fname).write_bytes(img_bytes)
                screenshot_path = fname
            except Exception:
                return jsonify({"success": False, "error": "Couldn't read that screenshot — try sending it again."}), 400

        now = time.time()
        await db.execute("""
            INSERT INTO payments (phone, name, amount, mpesa_code, screenshot_path, status, created_at)
            VALUES (?, '', ?, ?, ?, 'pending', ?)
        """, (phone, amount, mpesa_code, screenshot_path, now))
        await db.commit()
        async with db.execute("SELECT last_insert_rowid()") as c:
            new_id = (await c.fetchone())[0]

    # Best-effort nudge to the admin on WhatsApp — never blocks the response
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            await client.post(f"{NODE_PAIR_URL}/notify-owner", headers=_node_headers(), json={
                "text": (
                    f"💰 *New top-up request* REF-{str(new_id).zfill(4)}\n"
                    f"From: {phone}\nAmount: {amount} kesh\nCode: {mpesa_code}\n"
                    f"{'📸 Screenshot attached' if screenshot_path else '⚠️ No screenshot'}\n\n"
                    f"Review in /admin → Payments tab."
                )
            })
    except Exception:
        pass

    return jsonify({
        "success": True,
        "id": new_id,
        "message": "Submitted! Your top-up is pending admin review — you'll be notified once it's approved."
    })


ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# ✅ NEW: in-memory cooldown so /admin/forgot-password can't be spammed to
# flood the owner's WhatsApp with reset codes. Not persisted on purpose —
# a restart clearing this is a harmless edge case, not a security hole.
_last_reset_request_time = 0.0
RESET_REQUEST_COOLDOWN_SECONDS = 60
RESET_OTP_TTL_SECONDS = 10 * 60
RESET_OTP_MAX_ATTEMPTS = 5

# ✅ NEW: brute-force lockout for the admin login itself. Before this,
# _check_admin_auth was a bare string comparison with NO limit on how many
# times someone could guess — a short/weak ADMIN_PASSWORD was crackable by
# just hammering /admin/stats with different values. Now tracked per client
# IP, in-memory: 5 wrong attempts within 5 minutes locks that IP out for 5
# minutes, even if the very next guess would've been correct. A restart
# clearing this table is an acceptable trade-off for a single-admin tool.
_admin_login_failures: dict[str, dict] = {}
ADMIN_LOCKOUT_THRESHOLD = 5
ADMIN_LOCKOUT_WINDOW_SECONDS = 5 * 60
ADMIN_LOCKOUT_DURATION_SECONDS = 5 * 60

# ✅ NEW: same brute-force protection for the /panel user login, tracked
# per registered phone number (see api_profile below for why per-account
# rather than per-IP fits this threat better).
_panel_login_failures: dict[str, dict] = {}

# ✅ NEW: brute-force lockout for the OWNER_RECOVERY_SECRET path on
# /admin/owner-number (used internally by the .ownerrecovery WhatsApp
# command — see that route for why it needs its own auth path separate
# from ADMIN_PASSWORD). Kept in its own table, not shared with
# _admin_login_failures, so guessing one secret can't lock out — or be
# confused with — attempts on the other.
_owner_recovery_failures: dict[str, dict] = {}


async def _check_owner_recovery_secret(req, provided: str) -> bool:
    """Constant-time check of a submitted OWNER_RECOVERY_SECRET, with the
    same per-IP lockout behavior as _check_admin_auth_async: 5 wrong
    attempts within 5 minutes locks that IP out for 5 minutes. Returns
    False (no distinction from "wrong secret") if OWNER_RECOVERY_SECRET
    isn't configured — there is no dev-mode open-access fallback here,
    unlike admin auth, since this exists specifically to change who the
    owner is."""
    secret_env = os.environ.get("OWNER_RECOVERY_SECRET", "")
    if not secret_env:
        return False

    ip = _client_ip(req)
    now = time.time()
    entry = _owner_recovery_failures.get(ip)
    if entry and entry.get("locked_until", 0) > now:
        return False

    ok = secrets.compare_digest(provided or "", secret_env)
    if ok:
        _owner_recovery_failures.pop(ip, None)
        return True

    if not entry or now - entry.get("window_start", now) > ADMIN_LOCKOUT_WINDOW_SECONDS:
        entry = {"fails": 0, "window_start": now}
    entry["fails"] = entry.get("fails", 0) + 1
    if entry["fails"] >= ADMIN_LOCKOUT_THRESHOLD:
        entry["locked_until"] = now + ADMIN_LOCKOUT_DURATION_SECONDS
    _owner_recovery_failures[ip] = entry
    return False


async def _get_admin_setting(key: str):
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT value FROM admin_settings WHERE key = ?", (key,)) as c:
            row = await c.fetchone()
            return row[0] if row else None


async def _get_effective_owner_number() -> str:
    """
    Resolves the current owner number. Priority order:
      1. admin_settings.owner_number_override — set at runtime from the
         Admin Panel (Settings → Owner Number) or via the .ownerrecovery
         WhatsApp command, no redeploy needed.
      2. OWNER_NUMBER env var — the deploy-time default.
    🔒 No hardcoded fallback — returns "" if neither is set, so owner-only
    checks correctly deny everyone rather than silently trusting a baked-in
    number.
    """
    override = await _get_admin_setting("owner_number_override")
    if override:
        return override
    return os.environ.get("OWNER_NUMBER", "").replace("+", "").replace(" ", "")


async def _set_admin_setting(key: str, value: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value)
        )
        await db.commit()


async def _clear_admin_settings(*keys: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.executemany("DELETE FROM admin_settings WHERE key = ?", [(k,) for k in keys])
        await db.commit()


def _check_admin_auth(req) -> bool:
    """
    ✅ FIX: admin panel had no server-side auth — anyone who found the URL
    could read all sessions, contacts, messages. Now requires either:
    - ?pass=PASSWORD query param, or
    - Authorization: Bearer PASSWORD header
    Falls back to open if ADMIN_PASSWORD env var is not set (dev mode).

    NOTE: kept as a sync check using the env-var password only, for all the
    existing call sites below. The DB-stored (resettable) password is
    checked by _check_admin_auth_async, used at the login/stats entry point
    so a password reset via WhatsApp OTP actually takes effect.

    ✅ SECURITY: uses secrets.compare_digest instead of `==` so this can't
    leak timing information about how many leading characters of the
    password were guessed correctly.
    """
    if not ADMIN_PASSWORD:
        return True  # dev mode: no password set
    token = req.args.get("pass") or req.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    return secrets.compare_digest(token or "", ADMIN_PASSWORD)


async def _check_admin_auth_async(req) -> bool:
    """
    Same as _check_admin_auth, but also:
    - accepts a password that was reset via the "forgot password" WhatsApp
      OTP flow (stored hashed in admin_settings)
    - enforces the brute-force lockout described above

    Deliberately returns a plain False for both "wrong password" and
    "locked out" (never distinguishing the two in the response) so an
    attacker can't use the error message to detect when they're being
    rate-limited vs just guessing wrong.
    """
    ip = _client_ip(req)
    now = time.time()
    entry = _admin_login_failures.get(ip)
    if entry and entry.get("locked_until", 0) > now:
        return False

    token = req.args.get("pass") or req.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    stored_hash = await _get_admin_setting("password_hash")
    if stored_hash:
        ok = _verify_password(token or "", stored_hash)
    elif not ADMIN_PASSWORD:
        ok = True  # dev mode: no password set, and no reset has ever happened
    else:
        ok = secrets.compare_digest(token or "", ADMIN_PASSWORD)

    if ok:
        _admin_login_failures.pop(ip, None)
        return True

    if not entry or now - entry.get("window_start", now) > ADMIN_LOCKOUT_WINDOW_SECONDS:
        entry = {"fails": 0, "window_start": now}
    entry["fails"] = entry.get("fails", 0) + 1
    if entry["fails"] >= ADMIN_LOCKOUT_THRESHOLD:
        entry["locked_until"] = now + ADMIN_LOCKOUT_DURATION_SECONDS
    _admin_login_failures[ip] = entry
    return False


@app.route("/admin/forgot-password", methods=["POST"])
async def admin_forgot_password():
    """
    ✅ NEW: "forgot admin password" — sends a one-time 6-digit reset code
    to the BOT OWNER'S OWN WhatsApp number (OWNER_NUMBER), reusing the same
    send_otp_whatsapp() delivery path already used for user registration.
    Deliberately does NOT accept any phone number from the requester — the
    code always goes to the fixed owner number configured on the server,
    so this can't be abused to send codes to an attacker-controlled number.
    """
    global _last_reset_request_time
    now = time.time()
    if now - _last_reset_request_time < RESET_REQUEST_COOLDOWN_SECONDS:
        wait = int(RESET_REQUEST_COOLDOWN_SECONDS - (now - _last_reset_request_time))
        return jsonify({"success": False, "error": f"Please wait {wait}s before requesting another code."}), 429

    owner_number = await _get_effective_owner_number()
    if not owner_number:
        return jsonify({"success": False, "error": "No OWNER_NUMBER configured on the server — password reset isn't available. Set it manually via ADMIN_PASSWORD instead."}), 400

    _last_reset_request_time = now
    otp = _generate_otp()
    await _set_admin_setting("reset_otp_hash", _hash_password(otp))
    await _set_admin_setting("reset_otp_expires", str(now + RESET_OTP_TTL_SECONDS))
    await _set_admin_setting("reset_otp_attempts", "0")

    result = await send_otp_whatsapp(owner_number, otp, "Admin", require_owner_session=True)
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error", "Couldn't send the reset code. Is the bot connected to WhatsApp?")}), 502

    return jsonify({"success": True, "message": "A reset code was sent to the owner's WhatsApp. It expires in 10 minutes."})


@app.route("/admin/reset-password", methods=["POST"])
async def admin_reset_password():
    """✅ NEW: verify the OTP from /admin/forgot-password and set a new admin password."""
    data = await request.get_json(force=True, silent=True) or {}
    otp = str(data.get("otp", "")).strip()
    new_password = str(data.get("new_password", ""))

    if len(new_password) < 8:
        return jsonify({"success": False, "error": "New password must be at least 8 characters."}), 400

    stored_hash = await _get_admin_setting("reset_otp_hash")
    expires_raw = await _get_admin_setting("reset_otp_expires")
    attempts_raw = await _get_admin_setting("reset_otp_attempts")
    if not stored_hash or not expires_raw:
        return jsonify({"success": False, "error": "No reset code was requested. Tap 'Forgot password' first."}), 400

    attempts = int(attempts_raw or "0")
    if attempts >= RESET_OTP_MAX_ATTEMPTS:
        await _clear_admin_settings("reset_otp_hash", "reset_otp_expires", "reset_otp_attempts")
        return jsonify({"success": False, "error": "Too many wrong attempts. Request a new code."}), 429

    if time.time() > float(expires_raw):
        await _clear_admin_settings("reset_otp_hash", "reset_otp_expires", "reset_otp_attempts")
        return jsonify({"success": False, "error": "That code expired. Request a new one."}), 400

    if not _verify_password(otp, stored_hash):
        await _set_admin_setting("reset_otp_attempts", str(attempts + 1))
        return jsonify({"success": False, "error": "Incorrect code."}), 401

    await _set_admin_setting("password_hash", _hash_password(new_password))
    await _clear_admin_settings("reset_otp_hash", "reset_otp_expires", "reset_otp_attempts")
    logger.info("🔑 Admin password was reset via WhatsApp OTP.")
    return jsonify({"success": True, "message": "Password updated. You can log in with your new password now."})


@app.route("/admin")
async def admin_panel():
    # FIX: this used to call _check_admin_auth() here too, which meant that
    # when ADMIN_PASSWORD was set, you got a bare 401 before the in-page
    # login form (the one inside admin.html) ever had a chance to load.
    # The page itself contains no sensitive data - auth is enforced on every
    # /admin/* data endpoint below instead, so this is safe to serve openly.
    admin_path = Path(__file__).parent / "admin.html"
    if admin_path.exists():
        return Response(admin_path.read_text(encoding="utf-8"), mimetype="text/html", headers=NO_CACHE_HEADERS)
    return jsonify({"error": "Admin panel not found"}), 404


@app.route("/admin/stats", methods=["GET"])
async def admin_stats():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT COUNT(*) FROM contacts") as c:
            contacts = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM messages") as c:
            messages = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM viewonce_media") as c:
            viewonce = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM scheduled_messages WHERE sent = 0") as c:
            scheduled_pending = (await c.fetchone())[0]
        async with db.execute(
            "SELECT name, sender, timestamp FROM contacts ORDER BY timestamp DESC LIMIT 20"
        ) as c:
            rows = await c.fetchall()
            recent_contacts = [
                {
                    "name": r[0],
                    "sender": r[1],
                    "time": time.strftime("%d/%m %H:%M", time.localtime(r[2]))
                } for r in rows
            ]

    # Session info from global registry
    session_list = []
    now_ts = time.time()
    # One query for every session's antiban_enabled column, instead of a
    # query-per-session inside the loop below.
    async with aiosqlite.connect(DB_FILE) as db3:
        async with db3.execute("SELECT session, antiban_enabled FROM session_subscriptions") as c3:
            antiban_by_session = {r[0]: bool(r[1]) for r in await c3.fetchall()}
    for name, info in SESSION_REGISTRY.items():
        last_active_ts = info.get("last_active_ts")
        expiry_ts = info.get("expiry_ts")
        session_list.append({
            "name": name,
            "number": info.get("number", ""),
            "online": info.get("online", False),
            "msg_count": info.get("msg_count", 0),
            "since": info.get("since", ""),
            "since_ts": info.get("since_ts"),
            "last_active": time.strftime("%d %b %Y, %H:%M", time.localtime(last_active_ts)) if last_active_ts else "N/A",
            "expiry_ts": expiry_ts,
            "expiry_display": time.strftime("%d %b %Y, %H:%M", time.localtime(expiry_ts)) if expiry_ts else None,
            "expired": bool(expiry_ts and now_ts >= expiry_ts),
            "expiry_message": info.get("expiry_message", DEFAULT_EXPIRY_MESSAGE),
            # Anti-ban health, pushed from the Node bridge on every
            # /admin/update-session call. Absent until that session has
            # sent at least one message post-connect.
            "antiban_risk": info.get("antiban_risk"),
            "antiban_warmup_day": info.get("antiban_warmup_day"),
            "antiban_warmup_total": info.get("antiban_warmup_total"),
            # ✅ NEW: per-session antiban on/off (defaults True if the
            # session has no subscription row yet, matching /admin/session-antiban).
            "antiban_enabled": antiban_by_session.get(name, True),
        })

    # Today's message count (for activity chart)
    today_start = time.time() - (time.time() % 86400)
    async with aiosqlite.connect(DB_FILE) as db2:
        async with db2.execute(
            "SELECT COUNT(*) FROM messages WHERE timestamp >= ?", (today_start,)
        ) as c:
            messages_today = (await c.fetchone())[0]

    return jsonify({
        "sessions": len([s for s in session_list if s["online"]]),
        "contacts": contacts,
        "messages": messages,
        "messages_today": messages_today,
        "viewonce": viewonce,
        "scheduled_pending": scheduled_pending,
        "session_list": session_list,
        "recent_contacts": recent_contacts,
        "server_time": time.strftime("%d %b %Y, %H:%M:%S", time.localtime()),
    })


@app.route("/admin/terminate", methods=["POST"])
async def admin_terminate():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    session_name = data.get("session", "")
    if session_name in SESSION_REGISTRY:
        SESSION_REGISTRY[session_name]["online"] = False
        SESSION_REGISTRY[session_name]["terminate"] = True
    return jsonify({"status": "terminated", "session": session_name})


@app.route("/admin/register-session", methods=["POST"])
async def register_session():
    # ✅ FIX: was missing the auth check every other /admin/* route has —
    # let anyone on the internet spoof/overwrite session registry entries.
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    name = data.get("name", "unknown")
    now = time.time()
    existing = SESSION_REGISTRY.get(name, {})
    SESSION_REGISTRY[name] = {
        "number": data.get("number", ""),
        "online": data.get("online", False),
        "msg_count": data.get("msg_count", 0),
        "since_ts": now,
        "since": time.strftime("%d %b %Y, %H:%M", time.localtime(now)),
        "last_active_ts": now,
        # ✅ Subscription expiry — preserved across re-registers/restarts
        "expiry_ts": existing.get("expiry_ts"),
        "expiry_message": existing.get("expiry_message", DEFAULT_EXPIRY_MESSAGE),
    }
    return jsonify({"status": "registered"})


@app.route("/admin/update-session", methods=["POST"])
async def update_session():
    # ✅ FIX: was missing the auth check every other /admin/* route has.
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    name = data.get("name", "")
    if name in SESSION_REGISTRY:
        SESSION_REGISTRY[name].update({
            "online": data.get("online", SESSION_REGISTRY[name].get("online")),
            "msg_count": data.get("msg_count", SESSION_REGISTRY[name].get("msg_count", 0)),
            "number": data.get("number", SESSION_REGISTRY[name].get("number", "")),
            "last_active_ts": time.time(),
            # Anti-ban health snapshot (optional — omitted entirely on
            # plain online/offline pings so it's never clobbered back to
            # null between the periodic stats pushes below).
            **({"antiban_risk": data["antiban_risk"]} if "antiban_risk" in data else {}),
            **({"antiban_warmup_day": data["antiban_warmup_day"]} if "antiban_warmup_day" in data else {}),
            **({"antiban_warmup_total": data["antiban_warmup_total"]} if "antiban_warmup_total" in data else {}),
        })
    return jsonify({"status": "updated"})


@app.route("/admin/set-expiry", methods=["POST"])
async def admin_set_expiry():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    session_name = data.get("session", "")
    expiry_ts = data.get("expiry_ts")  # epoch seconds, or null/0 to clear
    expiry_message = data.get("expiry_message") or DEFAULT_EXPIRY_MESSAGE
    if session_name not in SESSION_REGISTRY:
        return jsonify({"error": "Unknown session"}), 404
    SESSION_REGISTRY[session_name]["expiry_ts"] = float(expiry_ts) if expiry_ts else None
    SESSION_REGISTRY[session_name]["expiry_message"] = expiry_message
    return jsonify({
        "status": "ok",
        "session": session_name,
        "expiry_ts": SESSION_REGISTRY[session_name]["expiry_ts"],
        "expiry_message": expiry_message,
    })


@app.route("/admin/check-terminate", methods=["POST"])
async def check_terminate():
    # ✅ FIX: was missing the auth check every other /admin/* route has.
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    name = data.get("name", "")
    info = SESSION_REGISTRY.get(name, {})
    should_terminate = info.get("terminate", False)
    expiry_ts = info.get("expiry_ts")
    now = time.time()
    expired = bool(expiry_ts and now >= expiry_ts)

    # ✅ NEW: fire a one-time reminder when expiry is within 3 days, so
    # customers get a heads-up before they're cut off instead of finding
    # out only once already-expired. reminder_sent guards against re-firing
    # on every 30s poll; reset automatically whenever expiry_ts changes
    # (i.e. a fresh .setexpiry/renewal), via the "for this expiry_ts" check.
    remind_expiry = False
    remind_message = None
    if expiry_ts and not expired:
        days_left = (expiry_ts - now) / 86400
        already_sent_for = info.get("reminder_sent_for_expiry")
        if days_left <= 3 and already_sent_for != expiry_ts:
            remind_expiry = True
            days_display = max(0, round(days_left, 1))
            remind_message = f"⏳ Your subscription expires in ~{days_display} day(s). Renew soon to avoid interruption."
            info["reminder_sent_for_expiry"] = expiry_ts
            SESSION_REGISTRY[name] = info

    return jsonify({
        "terminate": should_terminate,
        "expired": expired,
        "expiry_message": info.get("expiry_message", DEFAULT_EXPIRY_MESSAGE),
        "remind_expiry": remind_expiry,
        "remind_message": remind_message,
    })


# ── Paid Pairing / Activation Keys ───────────────────────────────────────────
# Every newly-paired customer session (via /pair or .pair in chat) starts
# LOCKED. It stays locked until the customer requests a key (".pair key"),
# the admin approves it (from WhatsApp with a plain yes/no, or from
# /admin → 🔑 Activation), and the customer redeems the key (".key XXXXXX")
# within its 10-minute window. Activating sets an expiry based on however
# many days the admin granted; re-approving/extending just pushes that
# expiry further out without breaking the already-connected session.
#
# All routes below are called internally by client_bridge.js (Bearer token,
# same pattern as every other /admin/* internal call) OR by the /admin web
# panel (?pass= / Bearer, same _check_admin_auth_async as everything else)
# — there's no distinction, both are equally "admin" by design so the admin
# can approve from WhatsApp or the panel interchangeably.

ACTIVATION_KEY_TTL_SECONDS = 600  # 10 minutes to redeem an issued key
DEFAULT_ACTIVATION_SETTINGS = {
    "activation_default_days": "30",
    "activation_bypass_key": "",  # empty until admin sets one (or auto-generated below)
    # ✅ NEW: kesh price per extra day of bot-subscription time, purchasable
    # straight from the customer's own wallet balance via the panel — NOT
    # related to the .pricing / .setprice config-reselling text above, this
    # is specifically "buy more days of my own bot staying activated".
    "subscription_kesh_per_day": "10",
}


def _gen_activation_key() -> str:
    # Short, easy to type over WhatsApp — 8 uppercase alnum chars.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I ambiguity
    return "".join(secrets.choice(alphabet) for _ in range(8))


async def _get_activation_settings() -> dict:
    out = dict(DEFAULT_ACTIVATION_SETTINGS)
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT key, value FROM admin_settings WHERE key IN "
            "('activation_default_days','activation_bypass_key','subscription_kesh_per_day')"
        ) as c:
            rows = await c.fetchall()
        got = {k: v for k, v in rows}
        if not got.get("activation_bypass_key"):
            # Auto-generate one on first use so there's always a working
            # master bypass, without forcing the admin to configure it
            # before the feature works at all.
            bypass = _gen_activation_key() + _gen_activation_key()
            await db.execute(
                "INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('activation_bypass_key', ?)",
                (bypass,)
            )
            await db.commit()
            got["activation_bypass_key"] = bypass
        out.update({k: v for k, v in got.items() if v is not None})
    return out


async def _get_subscription(session: str):
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT session, phone, activated, activated_at, expiry_ts, subscription_days, "
            "request_status, requester_chat, pending_key, pending_key_expires_at, handled_by FROM session_subscriptions WHERE session = ?",
            (session,)
        ) as c:
            row = await c.fetchone()
    if not row:
        return None
    return {
        "session": row[0], "phone": row[1], "activated": bool(row[2]), "activated_at": row[3],
        "expiry_ts": row[4], "subscription_days": row[5], "request_status": row[6],
        "requester_chat": row[7], "pending_key": row[8], "pending_key_expires_at": row[9],
        "handled_by": row[10],
    }


@app.route("/admin/activation-status", methods=["POST"])
async def activation_status():
    """Called right after a session connects. Auto-creates its subscription
    row on first sight. A session whose phone number matches OWNER_NUMBER
    (the reseller's own main bot) is auto-activated with no expiry — this
    lock is for paying customers, not the admin's own number."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    phone = (data.get("phone") or "").strip()
    if not session:
        return jsonify({"error": "session required"}), 400

    owner_number = await _get_effective_owner_number()
    now = time.time()
    # ✅ NEW: flag this session as the owner's own personal number whenever
    # it matches OWNER_NUMBER — kept in sync on every reconnect in case
    # OWNER_NUMBER changes (e.g. via .ownerrecovery) or a session gets
    # re-paired to a different number.
    is_owner_session = 1 if bool(owner_number and phone and phone == owner_number) else 0
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT activated, expiry_ts FROM session_subscriptions WHERE session = ?", (session,)) as c:
            row = await c.fetchone()
        if not row:
            auto_activate = bool(is_owner_session)
            await db.execute(
                "INSERT INTO session_subscriptions (session, phone, activated, activated_at, expiry_ts, request_status, is_owner_session, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, NULL, 'none', ?, ?, ?)",
                (session, phone, 1 if auto_activate else 0, now if auto_activate else None, is_owner_session, now, now)
            )
            await db.commit()
            activated, expiry_ts = (1 if auto_activate else 0), None
        else:
            activated, expiry_ts = row
            # keep phone/number fresh in case it changed on a re-pair
            await db.execute(
                "UPDATE session_subscriptions SET phone = ?, is_owner_session = ?, updated_at = ? WHERE session = ?",
                (phone, is_owner_session, now, session)
            )
            await db.commit()

    live_active = bool(activated) and (not expiry_ts or now < expiry_ts)
    return jsonify({"activated": live_active, "expiry_ts": expiry_ts, "is_owner_session": bool(is_owner_session)})


@app.route("/admin/activation-request", methods=["POST"])
async def activation_request():
    """Customer sent '.pair key' — mark a request pending so the admin
    panel/WhatsApp approval flow has something to act on."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    phone = (data.get("phone") or "").strip()
    requester_chat = (data.get("requester_chat") or "").strip()
    if not session:
        return jsonify({"error": "session required"}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT request_status FROM session_subscriptions WHERE session = ?", (session,)) as c:
            row = await c.fetchone()
        if row and row[0] == "pending":
            return jsonify({"success": True, "already_pending": True})
        now = time.time()
        if row:
            await db.execute(
                "UPDATE session_subscriptions SET request_status = 'pending', requester_chat = ?, phone = ?, pending_key = NULL, updated_at = ? WHERE session = ?",
                (requester_chat, phone, now, session)
            )
        else:
            await db.execute(
                "INSERT INTO session_subscriptions (session, phone, activated, request_status, requester_chat, created_at, updated_at) "
                "VALUES (?, ?, 0, 'pending', ?, ?, ?)",
                (session, phone, requester_chat, now, now)
            )
        await db.commit()
    settings = await _get_activation_settings()
    return jsonify({"success": True, "already_pending": False, "default_days": settings["activation_default_days"]})


@app.route("/admin/activation-approve", methods=["POST"])
async def activation_approve():
    """Admin said yes (via WhatsApp reply or /admin panel button). Issues a
    random key valid for 10 minutes; the customer's session stays locked
    until they redeem it with '.key XXXXXX'."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    if not session:
        return jsonify({"error": "session required"}), 400
    settings = await _get_activation_settings()
    try:
        days = int(data.get("days") or settings["activation_default_days"])
    except (TypeError, ValueError):
        days = int(settings["activation_default_days"])
    days = max(1, days)

    key = _gen_activation_key()
    now = time.time()
    # ✅ NEW: whoever approves a still-unclaimed request (owner, co-owner,
    # or sub-admin) becomes its handler. COALESCE below means an existing
    # handler is never overwritten by a later approval.
    approver = (data.get("handled_by") or "").strip() or None
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT requester_chat, phone FROM session_subscriptions WHERE session = ?", (session,)) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"error": "No pending request for this session."}), 404
        requester_chat, phone = row
        await db.execute(
            "UPDATE session_subscriptions SET request_status = 'approved', pending_key = ?, pending_key_expires_at = ?, "
            "subscription_days = ?, handled_by = COALESCE(handled_by, ?), updated_at = ? WHERE session = ?",
            (key, now + ACTIVATION_KEY_TTL_SECONDS, days, approver, now, session)
        )
        await db.commit()
    return jsonify({
        "success": True, "key": key, "days": days,
        "expires_in": ACTIVATION_KEY_TTL_SECONDS,
        "requester_chat": requester_chat, "phone": phone,
        "handled_by": approver,
    })


@app.route("/admin/activation-deny", methods=["POST"])
async def activation_deny():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    if not session:
        return jsonify({"error": "session required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT requester_chat FROM session_subscriptions WHERE session = ?", (session,)) as c:
            row = await c.fetchone()
        await db.execute(
            "UPDATE session_subscriptions SET request_status = 'denied', pending_key = NULL, updated_at = ? WHERE session = ?",
            (time.time(), session)
        )
        await db.commit()
    return jsonify({"success": True, "requester_chat": row[0] if row else None})


@app.route("/admin/activation-redeem", methods=["POST"])
async def activation_redeem():
    """Customer sent '.key XXXXXX'. Also accepts the master bypass key
    (set/viewed from /admin → 🔑 Activation), which activates instantly
    with no expiry, no pending request needed — this is the admin's own
    override for pairing sessions without going through approval at all."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    phone = (data.get("phone") or "").strip()
    submitted_key = (data.get("key") or "").strip().upper()
    if not session or not submitted_key:
        return jsonify({"success": False, "reason": "session and key required"}), 400

    settings = await _get_activation_settings()
    now = time.time()

    if settings["activation_bypass_key"] and secrets.compare_digest(submitted_key, settings["activation_bypass_key"].upper()):
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute(
                "INSERT INTO session_subscriptions (session, phone, activated, activated_at, expiry_ts, request_status, pending_key, created_at, updated_at) "
                "VALUES (?, ?, 1, ?, NULL, 'none', NULL, ?, ?) "
                "ON CONFLICT(session) DO UPDATE SET activated=1, activated_at=excluded.activated_at, expiry_ts=NULL, request_status='none', pending_key=NULL, updated_at=excluded.updated_at",
                (session, phone, now, now, now)
            )
            await db.commit()
        return jsonify({"success": True, "bypass": True, "expiry_ts": None})

    sub = await _get_subscription(session)
    if not sub or not sub["pending_key"]:
        return jsonify({"success": False, "reason": "No key was issued for this session. Send *.pair key* to request one."})
    if not secrets.compare_digest(submitted_key, sub["pending_key"].upper()):
        return jsonify({"success": False, "reason": "That key doesn't match. Double-check and try again."})
    if not sub["pending_key_expires_at"] or now > sub["pending_key_expires_at"]:
        return jsonify({"success": False, "reason": "That key has expired (10-minute window). Send *.pair key* to request a new one."})

    days = sub["subscription_days"] or int(settings["activation_default_days"])
    base = sub["expiry_ts"] if (sub["expiry_ts"] and sub["expiry_ts"] > now) else now
    new_expiry = base + days * 86400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "UPDATE session_subscriptions SET activated = 1, activated_at = ?, expiry_ts = ?, request_status = 'none', pending_key = NULL, updated_at = ? WHERE session = ?",
            (now, new_expiry, now, session)
        )
        await db.commit()
    return jsonify({"success": True, "bypass": False, "expiry_ts": new_expiry, "days": days})


@app.route("/admin/activation-extend", methods=["POST"])
async def activation_extend():
    """/admin panel action: re-subscribe / add more days to a session
    without the WhatsApp request-and-key dance — for renewals the admin
    wants to push through directly. Doesn't touch the connected session at
    all, just extends (or sets, if none yet) its expiry.

    ✅ NEW: this same endpoint is now also called by the WhatsApp ".extend
    <days>" command (run in a customer's own chat by a bot admin — see
    plugins/general.js). Two optional fields, unused by the panel, enable
    that: `handled_by` (the acting admin's number) and `actor_is_subadmin`.
    When actor_is_subadmin is true, a sub-admin may only extend a session
    that's unclaimed or already handled by them — everyone else (panel,
    owner, co-owners) behaves exactly as before.
    """
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    try:
        days = max(1, int(data.get("days") or 30))
    except (TypeError, ValueError):
        return jsonify({"error": "days must be a number"}), 400
    now = time.time()
    sub = await _get_subscription(session)

    actor_is_subadmin = bool(data.get("actor_is_subadmin"))
    actor_number = (data.get("handled_by") or "").strip() or None
    if actor_is_subadmin and sub and sub.get("handled_by") and actor_number and sub["handled_by"] != actor_number:
        return jsonify({"success": False, "error": "This customer is handled by a different sub-admin."}), 403

    base = sub["expiry_ts"] if (sub and sub["expiry_ts"] and sub["expiry_ts"] > now) else now
    new_expiry = base + days * 86400
    new_handled_by = (sub.get("handled_by") if sub else None) or actor_number
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO session_subscriptions (session, activated, activated_at, expiry_ts, subscription_days, request_status, handled_by, created_at, updated_at) "
            "VALUES (?, 1, ?, ?, ?, 'none', ?, ?, ?) "
            "ON CONFLICT(session) DO UPDATE SET activated=1, activated_at=excluded.activated_at, expiry_ts=excluded.expiry_ts, subscription_days=excluded.subscription_days, handled_by=COALESCE(session_subscriptions.handled_by, excluded.handled_by), updated_at=excluded.updated_at",
            (session, now, new_expiry, days, new_handled_by, now, now)
        )
        await db.commit()
    return jsonify({"success": True, "expiry_ts": new_expiry, "handled_by": new_handled_by})


@app.route("/admin/activation-list", methods=["GET"])
async def activation_list():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    now = time.time()
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT session, phone, activated, expiry_ts, subscription_days, request_status, updated_at "
            "FROM session_subscriptions ORDER BY updated_at DESC LIMIT 300"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"sessions": [
        {
            "session": r[0], "phone": r[1], "activated": bool(r[2]),
            "expiry_ts": r[3],
            "expiry_display": time.strftime("%d %b %Y, %H:%M", time.localtime(r[3])) if r[3] else None,
            "expired": bool(r[3] and now >= r[3]),
            "subscription_days": r[4], "request_status": r[5],
            "updated_at": r[6],
        } for r in rows
    ]})


@app.route("/admin/owner-number", methods=["GET", "POST"])
async def admin_owner_number():
    """Lets the main admin change the bot owner number at runtime, from the
    Admin Panel, with no redeploy needed. GET returns the effective number
    and where it came from; POST sets/clears a DB override.
    POST body: {"owner_number": "2547XXXXXXXX"} to set, or {"owner_number": ""}
    (or omit it) to clear the override and fall back to the OWNER_NUMBER env var.

    POST accepts two independent forms of auth:
      1. Normal admin auth (Admin Panel — ADMIN_PASSWORD / reset DB hash)
      2. A matching OWNER_RECOVERY_SECRET in the body ("owner_recovery_secret")
    (2) exists so the .ownerrecovery WhatsApp command can persist its change
    here directly — it's gated by its own separate secret, deliberately not
    the admin password, so an emergency owner change doesn't depend on
    whoever currently controls /admin. Before this, .ownerrecovery only set
    an in-memory flag inside the Node process, invisible to this backend and
    wiped on every restart — this endpoint is now the single source of truth
    either path writes to."""
    data = await request.get_json(silent=True) or {}

    is_admin = await _check_admin_auth_async(request)
    if not is_admin and request.method == "POST":
        is_admin = await _check_owner_recovery_secret(request, str(data.get("owner_recovery_secret", "")))

    if not is_admin:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        override = await _get_admin_setting("owner_number_override")
        env_value = os.environ.get("OWNER_NUMBER", "").replace("+", "").replace(" ", "")
        effective = override or env_value
        return jsonify({
            "owner_number": effective,
            "source": "override" if override else ("env" if env_value else "unset"),
            "env_value": env_value,
        })

    raw = (data.get("owner_number") or "").strip()
    cleaned = raw.replace("+", "").replace(" ", "")

    if not cleaned:
        # Empty value clears the override, reverting to the env var.
        await _clear_admin_settings("owner_number_override")
        return jsonify({"success": True, "owner_number": os.environ.get("OWNER_NUMBER", ""), "source": "env"})

    if not cleaned.isdigit() or not (7 <= len(cleaned) <= 15):
        return jsonify({"error": "owner_number must be digits only, in international format (e.g. 254712345678)"}), 400

    await _set_admin_setting("owner_number_override", cleaned)
    return jsonify({"success": True, "owner_number": cleaned, "source": "override"})


@app.route("/admin/activation-settings", methods=["GET", "POST"])
async def activation_settings():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    if request.method == "GET":
        settings = await _get_activation_settings()
        return jsonify(settings)
    data = await request.get_json(silent=True) or {}
    updates = {}
    if "activation_default_days" in data:
        try:
            updates["activation_default_days"] = str(max(1, int(data["activation_default_days"])))
        except (TypeError, ValueError):
            return jsonify({"error": "activation_default_days must be a number"}), 400
    if "activation_bypass_key" in data:
        new_key = (data["activation_bypass_key"] or "").strip().upper()
        if new_key:
            updates["activation_bypass_key"] = new_key
    if "subscription_kesh_per_day" in data:
        raw = data["subscription_kesh_per_day"]
        if raw not in (None, ""):
            try:
                updates["subscription_kesh_per_day"] = str(max(0, int(raw)))
            except (TypeError, ValueError):
                return jsonify({"error": "subscription_kesh_per_day must be a number"}), 400
    if not updates:
        return jsonify({"error": "nothing to update"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        for k, v in updates.items():
            await db.execute("INSERT OR REPLACE INTO admin_settings (key, value) VALUES (?, ?)", (k, v))
        await db.commit()
    return jsonify({"success": True, **updates})



@app.route("/admin/session-detail", methods=["GET"])
async def session_detail():
    # ✅ FIX: this was the one /admin/* route with NO auth check at all —
    # anyone with the URL could read up to 100 real chat messages for any
    # session. Now requires the same admin password as every other route.
    if not await _check_admin_auth_async(request):
        return "Unauthorized", 401
    session_name = request.args.get("session", "")
    try:
        async with aiosqlite.connect(DB_FILE) as db:
            async with db.execute(
                "SELECT sender, name, body, timestamp FROM messages WHERE sender LIKE ? ORDER BY timestamp DESC LIMIT 100",
                (f"%{session_name}%",)
            ) as cursor:
                rows = await cursor.fetchall()
        msgs = [{"sender": r[0], "name": r[1], "body": r[2], "time": r[3]} for r in rows]
    except Exception:
        msgs = []
    # ✅ FIX: message name/body/session_name are user-controlled (they come
    # straight from WhatsApp chats) and were being dropped into this HTML
    # unescaped — a message containing "<script>" became stored XSS on this
    # page. Everything user-controlled is now html.escape()'d before it's
    # inserted into the template.
    safe_session_name = html.escape(session_name)
    html_body = "".join(
        f'<div class="msg"><div class="meta">{html.escape(m["name"] or "")} ({html.escape(m["sender"] or "")}) · '
        f'{time.strftime("%Y-%m-%d %H:%M", time.localtime(m["time"]))}</div>'
        f'<div class="body">{html.escape(m["body"] or "")}</div></div>'
        for m in msgs
    ) if msgs else '<p style="color:#555">No messages found for this session.</p>'
    html_page = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>Session: {safe_session_name}</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#08090f;color:#e2eaf4;font-family:'Segoe UI',sans-serif;padding:20px}}
h2{{color:#a78bfa;margin-bottom:16px}}
.msg{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:12px;margin-bottom:10px}}
.meta{{font-size:11px;color:#555;margin-bottom:4px}}
.body{{font-size:14px;color:#ccc;word-break:break-word}}
a{{color:#a78bfa;text-decoration:none}}</style></head>
<body><h2>📋 Session Messages — {safe_session_name}</h2>
<p style="color:#555;font-size:12px;margin-bottom:16px">Last 100 messages · <a href="/admin">← Back to Admin</a></p>
{html_body}
</body></html>"""
    return html_page, 200, {"Content-Type": "text/html; charset=utf-8"}


# ── ✅ NEW: Blacklist management ─────────────────────────────────────────────
@app.route("/admin/registrations", methods=["GET"])
async def admin_registrations():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("""
            SELECT phone, name, email, verified, credits, badge, created_at, verified_at
            FROM registrations ORDER BY created_at DESC
        """) as c:
            rows = await c.fetchall()
    return jsonify({"registrations": [
        {"phone": r[0], "name": r[1], "email": r[2], "verified": bool(r[3]),
         "credits": r[4], "badge": r[5], "created_at": r[6], "verified_at": r[7]}
        for r in rows
    ]})


@app.route("/admin/registrations/add-credit", methods=["POST"])
async def admin_add_credit():
    """
    Admin tops up a verified user's kesh credit manually — just phone + name.
    If the number isn't registered yet, creates a verified record for it
    (the main bot already has the contact saved, so identity is trusted).
    """
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("+", "")
    name = (data.get("name") or "").strip()
    amount = data.get("amount")

    if not phone or not phone.isdigit():
        return jsonify({"success": False, "error": "Valid phone number required."}), 400
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Amount must be a number."}), 400

    now = time.time()
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT phone FROM registrations WHERE phone = ?", (phone,)) as c:
            exists = await c.fetchone()
        if exists:
            await db.execute("UPDATE registrations SET credits = credits + ?, name = COALESCE(NULLIF(?, ''), name) WHERE phone = ?",
                              (amount, name, phone))
        else:
            await db.execute("""
                INSERT INTO registrations (phone, name, email, otp, otp_expiry, verified, credits, badge, created_at, verified_at)
                VALUES (?, ?, '', '', 0, 1, ?, 'Trusted', ?, ?)
            """, (phone, name, amount, now, now))
        await db.commit()

    return jsonify({"success": True, "message": f"{amount} kesh added to {phone}."})


# ── ✅ NEW: Wallet top-up review queue ───────────────────────────────────────
@app.route("/admin/payments", methods=["GET"])
async def admin_get_payments():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "unauthorized"}), 401
    status_filter = (request.args.get("status") or "").strip().lower()
    query = "SELECT id, phone, amount, mpesa_code, screenshot_path, status, admin_note, created_at, reviewed_at FROM payments"
    params = ()
    if status_filter in ("pending", "approved", "rejected"):
        query += " WHERE status = ?"
        params = (status_filter,)
    query += " ORDER BY created_at DESC LIMIT 200"
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(query, params) as c:
            rows = await c.fetchall()
    return jsonify({"payments": [
        {
            "id": r[0], "phone": r[1], "amount": r[2], "mpesa_code": r[3],
            "has_screenshot": bool(r[4]), "status": r[5], "admin_note": r[6],
            "created_at": r[7], "reviewed_at": r[8],
        } for r in rows
    ]})


@app.route("/admin/payment-proof/<int:payment_id>", methods=["GET"])
async def admin_payment_proof(payment_id):
    """Serves the uploaded screenshot for one payment — gated behind admin
    auth so users' M-Pesa screenshots (which can contain phone numbers and
    names) aren't sitting at a guessable public URL."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT screenshot_path FROM payments WHERE id = ?", (payment_id,)) as c:
            row = await c.fetchone()
    if not row or not row[0]:
        return jsonify({"error": "No screenshot for this payment."}), 404
    fpath = PAYMENT_PROOFS_DIR / row[0]
    if not fpath.exists():
        return jsonify({"error": "Screenshot file missing on disk."}), 404
    return await app.send_file(fpath)


@app.route("/admin/payments/review", methods=["POST"])
async def admin_review_payment():
    """Approve or reject a top-up request. Approving is the ONLY way kesh
    credits get added from a user-submitted M-Pesa code — this is the human
    verification step standing in for a real payment-gateway integration.
    Always cross-check the code/amount against your own M-Pesa statement
    before approving; the screenshot is supporting evidence, not proof."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    payment_id = data.get("id")
    action = (data.get("action") or "").strip().lower()
    note = (data.get("note") or "").strip()
    if action not in ("approve", "reject"):
        return jsonify({"success": False, "error": "action must be 'approve' or 'reject'."}), 400

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT phone, amount, status FROM payments WHERE id = ?", (payment_id,)
        ) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Payment request not found."}), 404
        phone, amount, status = row
        if status != "pending":
            return jsonify({"success": False, "error": f"Already reviewed (status: {status})."}), 400

        now = time.time()
        new_status = "approved" if action == "approve" else "rejected"
        await db.execute(
            "UPDATE payments SET status = ?, admin_note = ?, reviewed_at = ? WHERE id = ?",
            (new_status, note, now, payment_id)
        )
        if action == "approve":
            await db.execute(
                "UPDATE registrations SET credits = credits + ? WHERE phone = ?",
                (amount, phone)
            )
        await db.commit()

    # Best-effort notify the user of the outcome
    try:
        if action == "approve":
            text = f"✅ Your top-up of {amount} kesh has been approved and added to your wallet! Send *.profile* to check your balance."
        else:
            text = f"❌ Your top-up request was rejected.{(' Reason: ' + note) if note else ''} Reply to the bot if you think this is a mistake."
        async with httpx.AsyncClient(timeout=4) as client:
            await client.post(f"{NODE_PAIR_URL}/notify-user", headers=_node_headers(), json={"phone": phone, "text": text})
    except Exception:
        pass

    return jsonify({"success": True, "status": new_status})


@app.route("/admin/blacklist", methods=["GET"])
async def admin_get_blacklist():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT sender FROM blacklist") as c:
            rows = await c.fetchall()
    return jsonify({"blacklist": [r[0] for r in rows]})


@app.route("/admin/blacklist/add", methods=["POST"])
async def admin_add_blacklist():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    sender = data.get("sender", "").strip()
    if not sender:
        return jsonify({"status": "error", "message": "No sender provided"}), 400
    if "@" not in sender:
        sender = f"{sender}@s.whatsapp.net"
    async with aiosqlite.connect(DB_FILE) as db:
        try:
            await db.execute("INSERT INTO blacklist VALUES (?)", (sender,))
            await db.commit()
        except aiosqlite.IntegrityError:
            pass
    return jsonify({"status": "blacklisted", "sender": sender})


@app.route("/admin/blacklist/remove", methods=["POST"])
async def admin_remove_blacklist():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    sender = data.get("sender", "").strip()
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM blacklist WHERE sender = ?", (sender,))
        await db.commit()
    return jsonify({"status": "removed", "sender": sender})


# ── ✅ NEW: Search messages ──────────────────────────────────────────────────
@app.route("/admin/search-messages", methods=["GET"])
async def admin_search_messages():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"results": []})
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT sender, name, body, timestamp FROM messages WHERE body LIKE ? ORDER BY timestamp DESC LIMIT 50",
            (f"%{q}%",)
        ) as c:
            rows = await c.fetchall()
    results = [
        {"sender": r[0], "name": r[1], "body": r[2],
         "time": time.strftime("%d %b %Y, %H:%M", time.localtime(r[3]))}
        for r in rows
    ]
    return jsonify({"results": results})


# ── ✅ NEW: Manual broadcast queue (bot polls and sends) ────────────────────
BROADCAST_QUEUE = []

@app.route("/admin/broadcast", methods=["POST"])
async def admin_broadcast():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    target = data.get("target", "all_contacts")  # all_contacts | all_groups | custom
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"status": "error", "message": "Empty message"}), 400
    BROADCAST_QUEUE.append({
        "target": target,
        "message": message,
        "queued_at": time.time(),
        "sent": False,
    })
    return jsonify({"status": "queued", "queue_size": len(BROADCAST_QUEUE)})


@app.route("/admin/broadcast/pending", methods=["GET"])
async def admin_broadcast_pending():
    """Polled by the Node bridge to pick up queued broadcasts.
    ✅ FIX: was missing auth — anyone could hit this and silently drain the
    queue (marks broadcasts sent=True) before the real bridge polled it.
    The Node bridge already sends the admin password on its other calls, so
    this doesn't change how legitimate polling works."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    pending = [b for b in BROADCAST_QUEUE if not b["sent"]]
    for b in pending:
        b["sent"] = True
    return jsonify({"broadcasts": pending})


@app.route("/admin/contacts/all", methods=["GET"])
async def admin_contacts_all():
    """Full, unlimited contact list — used by the broadcast sender so an
    .announce isn't silently capped at the 20 shown on the dashboard
    preview. Requires the same admin auth as other /admin/* routes."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT sender, name FROM contacts ORDER BY timestamp DESC") as c:
            rows = await c.fetchall()
    return jsonify({"contacts": [{"sender": r[0], "name": r[1]} for r in rows]})


# ── ✅ NEW: Restart / health controls ────────────────────────────────────────
@app.route("/admin/uptime", methods=["GET"])
async def admin_uptime():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    uptime_seconds = time.time() - PROCESS_START_TIME
    return jsonify({
        "uptime_seconds": uptime_seconds,
        "uptime_human": f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m",
        "started_at": time.strftime("%d %b %Y, %H:%M:%S", time.localtime(PROCESS_START_TIME)),
    })


@app.route("/admin/keywords", methods=["GET"])
async def admin_get_keywords():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT trigger, reply, match_type, enabled FROM keywords ORDER BY trigger"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"keywords": [
        {"trigger": r[0], "reply": r[1], "match_type": r[2], "enabled": bool(r[3])} for r in rows
    ]})


@app.route("/admin/keywords/add", methods=["POST"])
async def admin_add_keyword():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    trigger = (data.get("trigger") or "").strip()
    reply = (data.get("reply") or "").strip()
    match_type = (data.get("match_type") or "contains").strip()
    if match_type not in ("contains", "exact", "starts_with"):
        match_type = "contains"
    if not trigger or not reply:
        return jsonify({"error": "trigger and reply are required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """INSERT INTO keywords (trigger, reply, match_type, enabled, timestamp)
               VALUES (?, ?, ?, 1, ?)
               ON CONFLICT(trigger) DO UPDATE SET reply=excluded.reply,
                   match_type=excluded.match_type, timestamp=excluded.timestamp""",
            (trigger, reply, match_type, time.time())
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/keywords/remove", methods=["POST"])
async def admin_remove_keyword():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    trigger = (data.get("trigger") or "").strip()
    if not trigger:
        return jsonify({"error": "trigger is required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM keywords WHERE trigger = ?", (trigger,))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/keywords/toggle", methods=["POST"])
async def admin_toggle_keyword():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    trigger = (data.get("trigger") or "").strip()
    enabled = 1 if data.get("enabled") else 0
    if not trigger:
        return jsonify({"error": "trigger is required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE keywords SET enabled = ? WHERE trigger = ?", (enabled, trigger))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/features", methods=["GET"])
async def admin_get_features():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT name, enabled FROM features ORDER BY name") as c:
            rows = await c.fetchall()
    return jsonify({"features": [{"name": r[0], "enabled": bool(r[1])} for r in rows]})


@app.route("/admin/features/toggle", methods=["POST"])
async def admin_toggle_feature():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    name = (data.get("name") or "").strip()
    enabled = 1 if data.get("enabled") else 0
    if not name:
        return jsonify({"error": "name is required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO features (name, enabled) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled",
            (name, enabled)
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/auto-save", methods=["POST"])
async def register_profile():
    data = await request.get_json() or {}
    sender = data.get("sender", "").strip()
    name = data.get("name", "User").strip()
    if not sender:
        return jsonify({"status": "error"}), 400
    if await check_db_blacklist(sender):
        return jsonify({"status": "blacklisted"})
    async with aiosqlite.connect(DB_FILE) as db:
        try:
            await db.execute("INSERT INTO contacts VALUES (?, ?, ?)", (sender, name, time.time()))
            await db.commit()
            # ✅ Auto-welcome DM removed on request — contact is still saved
            # silently, but no message gets sent to the stranger anymore.
            return jsonify({"status": "new_user_registered"})
        except aiosqlite.IntegrityError:
            return jsonify({"status": "already_indexed"})


@app.route("/log-message", methods=["POST"])
async def log_message():
    data = await request.get_json() or {}
    msg_id = data.get("msg_id")
    sender = data.get("sender")
    name = data.get("name", "User")
    body = data.get("body", "")
    if not msg_id or not sender:
        return jsonify({"status": "ignored"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR REPLACE INTO messages VALUES (?, ?, ?, ?, ?)",
            (msg_id, sender, name, body, time.time())
        )
        await db.commit()
    return jsonify({"status": "logged"})


@app.route("/log-viewonce", methods=["POST"])
async def log_viewonce():
    data = await request.get_json() or {}
    sender = data.get("sender")
    name = data.get("name", "User")
    filename = data.get("filename")
    media_type = data.get("mediaType", "imageMessage")
    caption = data.get("caption", "")
    timestamp = data.get("timestamp", time.time())
    if not sender or not filename:
        return jsonify({"status": "ignored"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO viewonce_media (sender, name, filename, media_type, caption, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (sender, name, filename, media_type, caption, timestamp)
        )
        await db.commit()
    return jsonify({"status": "saved"})


@app.route("/scheduler/load", methods=["GET"])
async def scheduler_load():
    """Internal — client_bridge.js calls this once on boot to rehydrate
    global.scheduledMessages so a restart/redeploy doesn't drop pending
    scheduled messages."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, to_jid, message, next_run, repeat, sent, created_by FROM scheduled_messages"
        ) as c:
            rows = await c.fetchall()
    return jsonify({
        "messages": [
            {
                "id": r[0], "to": r[1], "message": r[2],
                "nextRun": r[3], "repeat": r[4],
                "sent": bool(r[5]), "createdBy": r[6],
            }
            for r in rows
        ]
    })


@app.route("/scheduler/save", methods=["POST"])
async def scheduler_save():
    """Internal — client_bridge.js calls this after every add/delete/clear
    so the schedule survives process restarts. Full-list replace is simplest
    and safe here since scheduling volume is low (personal/small-business
    use, not a high-throughput queue)."""
    data = await request.get_json() or {}
    messages = data.get("messages", [])
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM scheduled_messages")
        for m in messages:
            await db.execute(
                "INSERT INTO scheduled_messages (id, to_jid, message, next_run, repeat, sent, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (m.get("id"), m.get("to"), m.get("message"), m.get("nextRun"),
                 m.get("repeat"), int(bool(m.get("sent"))), m.get("createdBy")),
            )
        await db.commit()
    return jsonify({"status": "saved", "count": len(messages)})


@app.route("/admin/scheduler", methods=["GET"])
async def admin_scheduler():
    """Admin panel view of pending scheduled messages (the .schedule command).
    Read-only mirror of the scheduled_messages table client_bridge.js persists to."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, to_jid, message, next_run, repeat, sent, created_by FROM scheduled_messages ORDER BY next_run ASC"
        ) as c:
            rows = await c.fetchall()
    return jsonify({
        "messages": [
            {
                "id": r[0], "to": r[1], "message": r[2],
                "next_run": time.strftime("%d %b %Y, %H:%M", time.localtime(r[3])) if r[3] else None,
                "repeat": r[4], "sent": bool(r[5]), "created_by": r[6],
            }
            for r in rows
        ]
    })


@app.route("/admin/scheduler/<msg_id>", methods=["DELETE"])
async def admin_scheduler_delete(msg_id):
    """Lets the admin cancel a scheduled message from the panel instead of
    needing WhatsApp access to run .schedule del."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM scheduled_messages WHERE id = ?", (msg_id,))
        await db.commit()
    return jsonify({"success": True})


@app.route("/activity/log", methods=["POST"])
async def activity_log_write():
    """Internal-only — client_bridge.js calls this on every command dispatch
    (category='command'), every failure (category='error'), and every
    owner/admin-tier action (category='sensitive'). No ADMIN_PASSWORD check
    here on purpose: this is called from the Node bridge on 127.0.0.1, same
    trust boundary as /scheduler/save and /auto-save. Row count is capped on
    write so a busy bot can't grow this table unbounded."""
    data = await request.get_json() or {}
    category = (data.get("category") or "").strip().lower()
    if category not in ("command", "error", "sensitive"):
        return jsonify({"success": False, "error": "category must be command|error|sensitive"}), 400
    event_type = (data.get("type") or "").strip()[:80]
    actor = (data.get("actor") or "").strip()[:64]
    detail = (data.get("detail") or "").strip()[:2000]
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO activity_log (category, type, actor, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
            (category, event_type, actor, detail, time.time()),
        )
        # Keep each category capped at the most recent 2000 rows so this
        # can't grow forever on a busy/high-traffic bot.
        await db.execute("""
            DELETE FROM activity_log WHERE category = ? AND id NOT IN (
                SELECT id FROM activity_log WHERE category = ? ORDER BY timestamp DESC LIMIT 2000
            )
        """, (category, category))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/activity-log", methods=["GET"])
async def admin_activity_log():
    """Admin panel feed — ?category=command|error|sensitive (required),
    optional ?limit= (default 100, max 500)."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    category = (request.args.get("category") or "").strip().lower()
    if category not in ("command", "error", "sensitive"):
        return jsonify({"error": "category must be command|error|sensitive"}), 400
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    except ValueError:
        limit = 100
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, type, actor, detail, timestamp FROM activity_log WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
            (category, limit),
        ) as c:
            rows = await c.fetchall()
    return jsonify({
        "events": [
            {
                "id": r[0], "type": r[1], "actor": r[2], "detail": r[3],
                "timestamp": time.strftime("%d %b %Y, %H:%M:%S", time.localtime(r[4])) if r[4] else None,
            }
            for r in rows
        ]
    })


@app.route("/admin/activity-log/export", methods=["GET"])
async def admin_activity_log_export():
    """✅ NEW: download the activity log as CSV — same filters as the JSON
    route (?category=command|error|sensitive, optional ?limit=), but ALL
    THREE categories combined by default if no category is given, since
    an export is usually meant as a full record, not a single tab's view."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    category = (request.args.get("category") or "").strip().lower()
    try:
        limit = min(max(int(request.args.get("limit", 1000)), 1), 5000)
    except ValueError:
        limit = 1000

    async with aiosqlite.connect(DB_FILE) as db:
        if category in ("command", "error", "sensitive"):
            async with db.execute(
                "SELECT category, type, actor, detail, timestamp FROM activity_log "
                "WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
                (category, limit),
            ) as c:
                rows = await c.fetchall()
        else:
            async with db.execute(
                "SELECT category, type, actor, detail, timestamp FROM activity_log "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ) as c:
                rows = await c.fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Category", "Type", "Actor", "Detail", "Timestamp"])
    for r in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[4])) if r[4] else ""
        writer.writerow([r[0], r[1], r[2], r[3], ts])

    filename = f"activity_log_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/activity-log", methods=["DELETE"])
async def admin_activity_log_clear():
    """Clear a single category's log from the panel. Doesn't touch the other
    two categories — clearing 'error' history, for instance, leaves the
    command/sensitive feeds untouched."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    category = (request.args.get("category") or "").strip().lower()
    if category not in ("command", "error", "sensitive"):
        return jsonify({"error": "category must be command|error|sensitive"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM activity_log WHERE category = ?", (category,))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/viewonce", methods=["GET"])
async def admin_viewonce():
    """Browse recently intercepted view-once media from the admin panel,
    instead of digging through the bot's own WhatsApp DMs for it."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, sender, name, filename, media_type, caption, timestamp FROM viewonce_media ORDER BY timestamp DESC LIMIT 50"
        ) as c:
            rows = await c.fetchall()
    return jsonify({
        "items": [
            {
                "id": r[0], "sender": r[1], "name": r[2], "filename": r[3],
                "media_type": r[4], "caption": r[5],
                "time": time.strftime("%d %b %Y, %H:%M", time.localtime(r[6])),
            }
            for r in rows
        ]
    })


@app.route("/admin/viewonce/file/<path:filename>", methods=["GET"])
async def admin_viewonce_file(filename):
    """Serves the actual saved view-once file. Gated behind admin auth for
    the same reason payment screenshots are — this is private content
    intercepted from other people's chats, not public static assets.
    Path is sanitized to the basename so this can't be used to read
    arbitrary files elsewhere on disk."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    safe_name = Path(filename).name  # strip any directory traversal attempt
    file_path = DATA_DIR / "viewonce_media" / safe_name
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    return Response(file_path.read_bytes(), mimetype="application/octet-stream")


@app.route("/bot/features", methods=["GET"])
async def bot_features():
    """Internal — called by client_bridge.js on every relevant message.
    Not part of the public admin API; returns just the on/off map."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT name, enabled FROM features") as c:
            rows = await c.fetchall()
    return jsonify({r[0]: bool(r[1]) for r in rows})


@app.route("/bot/owner-number", methods=["GET"])
async def bot_owner_number():
    """Internal — polled every 30s by client_bridge.js so an owner-number
    change made in the Admin Panel takes effect without a redeploy/restart.
    Not part of the public admin API (same convention as /bot/features)."""
    return jsonify({"owner_number": await _get_effective_owner_number()})


@app.route("/admin/session-antiban", methods=["GET"])
async def bot_session_antiban():
    """Internal — called once per session connect (same trust level as
    /bot/features). Returns whether THIS session's own antiban_enabled
    column is on — combined client-side with the global feature flag."""
    session = (request.args.get("session") or "").strip()
    if not session:
        return jsonify({"antiban_enabled": True})
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT antiban_enabled FROM session_subscriptions WHERE session = ?", (session,)
        ) as c:
            row = await c.fetchone()
    # No row yet (brand-new session, not registered) — default ON.
    return jsonify({"antiban_enabled": bool(row[0]) if row is not None else True})


@app.route("/admin/session-antiban/toggle", methods=["POST"])
async def admin_session_antiban_toggle():
    """Admin Panel: flip antiban on/off for one specific session, without
    touching the global switch (that's /admin/features/toggle)."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    enabled = 1 if data.get("enabled", True) else 0
    if not session:
        return jsonify({"error": "session required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE session_subscriptions SET antiban_enabled = ? WHERE session = ?", (enabled, session))
        await db.commit()
    return jsonify({"success": True, "antiban_enabled": bool(enabled)})


# ══════════════════════════════════════════════════════════════════════════
# ✅ NEW — .claude command. A separate, opt-in AI command (own API key,
# own model) distinct from the Groq-backed natural-chat/persona/translate
# features elsewhere. Bot-admin only (checked in the plugin, not here —
# this endpoint trusts the same Bearer auth every other bot-facing route
# does). Can return either a plain text reply, or — if the prompt implies
# multiple files (asks for "a project", "files", "a zip", etc.) — several
# named files bundled into a base64-encoded zip the WhatsApp side unpacks
# and sends as a document.
# ══════════════════════════════════════════════════════════════════════════

CLAUDE_FILE_DELIM_START = "---FILE:"
CLAUDE_FILE_DELIM_END = "---ENDFILE---"

CLAUDE_SYSTEM_PROMPT = (
    "You are Claude, answering a request sent from inside a WhatsApp bot via the .claude "
    "command. Two response modes:\n\n"
    "1. PLAIN REPLY — for questions, explanations, short code snippets, or anything that reads "
    "fine as a normal chat message. Just answer directly, no special formatting needed.\n\n"
    "2. MULTI-FILE — ONLY if the person is clearly asking you to generate one or more complete "
    "files (a script, a document, a small project, \"give me a file\", \"make me a zip\", etc). "
    "In that case, respond with ONLY this format, one block per file, nothing else outside the "
    "blocks:\n"
    f"{CLAUDE_FILE_DELIM_START} <relative/path/filename.ext>\n"
    "<full file content>\n"
    f"{CLAUDE_FILE_DELIM_END}\n\n"
    "Repeat that block for every file. Do not add any commentary before, between, or after the "
    "file blocks in MULTI-FILE mode — the bot parses these mechanically."
)


def _parse_claude_files(text: str):
    """Returns a list of (filename, content) if the response used the
    MULTI-FILE format, else None (meaning: treat as a plain reply)."""
    if CLAUDE_FILE_DELIM_START not in text:
        return None
    files = []
    parts = text.split(CLAUDE_FILE_DELIM_START)
    for part in parts[1:]:
        if CLAUDE_FILE_DELIM_END not in part:
            continue
        header, _, rest = part.partition("\n")
        content, _, _ = rest.partition(CLAUDE_FILE_DELIM_END)
        filename = header.strip()
        if filename:
            files.append((filename, content.strip("\n")))
    return files or None


@app.route("/claude/generate", methods=["POST"])
async def claude_generate():
    if not ANTHROPIC_API_KEY:
        return jsonify({"success": False, "error": "Claude isn't configured yet — set ANTHROPIC_API_KEY in your environment."}), 400
    data = await request.get_json(silent=True) or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"success": False, "error": "prompt required"}), 400

    try:
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 4096,
                    "system": CLAUDE_SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        if resp.status_code != 200:
            return jsonify({"success": False, "error": f"Claude API error ({resp.status_code}): {resp.text[:300]}"}), 502
        body = resp.json()
        full_text = "".join(block.get("text", "") for block in body.get("content", []) if block.get("type") == "text")
    except Exception as e:
        return jsonify({"success": False, "error": f"Request to Claude failed: {e}"}), 502

    files = _parse_claude_files(full_text)
    if files:
        # Build a zip in-memory, base64-encode it for the JSON response —
        # the Node side writes it straight to disk and sends it as a
        # WhatsApp document.
        import io as _io
        import zipfile as _zipfile
        import base64 as _base64
        buf = _io.BytesIO()
        with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as zf:
            for filename, content in files:
                zf.writestr(filename, content)
        zip_b64 = _base64.b64encode(buf.getvalue()).decode("ascii")
        return jsonify({"success": True, "mode": "files", "files": [f for f, _ in files], "zip_base64": zip_b64})

    return jsonify({"success": True, "mode": "text", "reply": full_text.strip()})


@app.route("/log-status", methods=["POST"])
async def log_status():
    data = await request.get_json() or {}
    sender = data.get("sender")
    name = data.get("name", "User")
    filename = data.get("filename")
    media_type = data.get("mediaType", "imageMessage")
    caption = data.get("caption", "")
    timestamp = data.get("timestamp", time.time())
    if not sender or not filename:
        return jsonify({"status": "ignored"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO status_media (sender, name, filename, media_type, caption, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (sender, name, filename, media_type, caption, timestamp)
        )
        await db.commit()
    return jsonify({"status": "saved"})


@app.route("/antilink/strike", methods=["POST"])
async def antilink_strike():
    """Records a strike for sender in group_id, returns the new count and
    whether the bot should kick them (3 strikes)."""
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    sender = data.get("sender")
    if not group_id or not sender:
        return jsonify({"error": "group_id and sender required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """INSERT INTO group_warnings (group_id, sender, count) VALUES (?, ?, 1)
               ON CONFLICT(group_id, sender) DO UPDATE SET count = count + 1""",
            (group_id, sender)
        )
        await db.commit()
        async with db.execute(
            "SELECT count FROM group_warnings WHERE group_id = ? AND sender = ?",
            (group_id, sender)
        ) as c:
            row = await c.fetchone()
    count = row[0] if row else 1
    should_kick = count >= 3
    if should_kick:
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("DELETE FROM group_warnings WHERE group_id = ? AND sender = ?", (group_id, sender))
            await db.commit()
    return jsonify({"count": count, "kick": should_kick})
# ✅ FIX: this route was missing its @app.route decorator entirely — the
# function existed but Quart never registered it as an endpoint, so every
# POST to /natural-chat 404'd silently (client_bridge.js swallows the error
# in an empty catch block). That meant the entire "AI DM chat" and "Group AI
# replies" features never worked, no matter how correct the rest of the
# code was. This one decorator is the actual fix.
@app.route("/natural-chat", methods=["POST"])
async def natural_chat():
    data = await request.get_json() or {}
    body = data.get("body", "").strip()
    name = data.get("name", "rafiki")
    context = data.get("context", "dm")  # dm | group | status
    # ✅ NEW: optional per-chat model override from .model, forwarded by
    # client_bridge.js. Falls back to the hardcoded default below if unset.
    model_pref = (data.get("model") or "").strip() or None
    if not body:
        return jsonify({"reply": None})
    if not GROQ_API_KEY:
        return jsonify({"reply": "❌ AI haijasetup. Weka GROQ_API_KEY kwenye .env"})

    if context == "status":
        system_prompt = (
            "You are Henry Ochibots, a friendly Kenyan WhatsApp bot. "
            "Someone posted a WhatsApp status and you want to leave a short, warm comment. "
            "Rules:\n"
            "1. Keep it under 2 sentences — like a real friend commenting on a status.\n"
            "2. Detect the language of the status and reply in the same language.\n"
            "   - Sheng → reply in Sheng\n"
            "   - Swahili → reply in Swahili\n"
            "   - English → reply in English\n"
            "   - Mix → mix your reply\n"
            "3. Be warm, encouraging, sometimes funny.\n"
            "4. Do NOT start with 'Hello' or 'Hi'.\n"
            "5. Use 1 emoji max."
        )
    elif context == "group":
        system_prompt = (
            f"You are Henry Ochibots, a Kenyan WhatsApp bot in a group chat. "
            f"You are talking to {name}. "
            "Someone mentioned you or called your name in the group. Reply naturally.\n"
            "Rules:\n"
            "1. Keep it SHORT — 1-2 sentences max. Group chats move fast.\n"
            "2. Detect language (Sheng/Swahili/English/mix) and reply in same.\n"
            "3. Be friendly and a bit playful — you're part of the group.\n"
            "4. Do NOT be formal. Be like a real member of the group.\n"
            "5. Use emoji occasionally."
        )
    elif context == "owner_sheng":
        # ✅ NEW: Henry's own number, personal auto-reply while he's away.
        # Reads like a friend covering for him, always in heavy Sheng — not
        # a generic "I'm a bot" assistant voice.
        system_prompt = (
            f"You are standing in for Henry (a real person) on his own WhatsApp, replying to {name} "
            "while he's away for a bit. You are NOT a generic assistant — you talk like a close Kenyan "
            "friend covering for him informally. ALWAYS reply in heavy, natural Sheng (Kenyan street "
            "slang), regardless of what language the incoming message is in.\n"
            "Style examples (match this energy exactly, don't copy the words):\n"
            "  - \"yoo rada inakaa nikaa Henry hayuko na akikam nitamshow ni @bot\"\n"
            "  - \"eeh boss amepotea kidogo, nikimuona nampigia story\"\n"
            "RULES:\n"
            "1. 1-2 sentences max, casual, zero formality, no 'Hello'/'Hi'/'Dear'.\n"
            "2. Make clear Henry isn't right here but will see the message and get back to them.\n"
            "3. Never claim to be an AI/bot outright — you're 'holding it down' for him.\n"
            "4. 1 emoji max, not required.\n"
            "5. Never share Henry's exact location, schedule, or any personal/financial details."
        )
    else:
        system_prompt = (
            f"You are Henry Ochibots, a friendly WhatsApp bot assistant. "
            f"You are talking to {name}. "
            "You are Kenyan and understand Swahili, Sheng (Kenyan street slang), and English. "
            "IMPORTANT RULES:\n"
            "1. Detect the language the user is writing in and ALWAYS reply in the same language.\n"
            "   - Sheng (e.g. 'niko fiti', 'nini mbaya', 'si unajua') → reply in Sheng.\n"
            "   - Swahili → reply in Swahili.\n"
            "   - English → reply in English.\n"
            "   - Mix (Kenglish) → mix your reply too.\n"
            "2. Keep replies SHORT and casual — like a real WhatsApp friend.\n"
            "3. 1–3 sentences max. No long essays.\n"
            "4. Be warm, friendly, sometimes funny — very human-like.\n"
            "5. Do NOT start every reply with 'Hello' or 'Hi'. Be natural.\n"
            "6. Use emoji occasionally but not excessively.\n"
            "7. Your creator is Henry Ochibots (@henrytech254)."
        )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": model_pref or "llama3-8b-8192",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": body}
                    ],
                    "max_tokens": 200
                }
            )
            data_r = response.json()
            if response.status_code == 200:
                reply = data_r["choices"][0]["message"]["content"].strip()
                return jsonify({"reply": reply})
            return jsonify({"reply": None})
    except Exception as e:
        return jsonify({"reply": None})


@app.route("/react", methods=["POST"])
async def process_sentiment():
    data = await request.get_json() or {}
    p = data.get("body", "").lower().strip()

    # React only 60% of the time — feels human
    if random.random() > 0.6:
        return jsonify({"emoji": None})

    if any(w in p for w in ["love", "heart", "perfect", "amazing", "beautiful", "cute", "sweet"]):
        return jsonify({"emoji": random.choice(["❤️", "😍", "🥰", "💕"])})
    if any(w in p for w in ["lol", "haha", "lmao", "funny", "joke", "hilarious", "😂"]):
        return jsonify({"emoji": random.choice(["😂", "🤣", "💀", "😭"])})
    if any(w in p for w in ["sad", "cry", "miss", "alone", "depressed", "pain", "hurt"]):
        return jsonify({"emoji": random.choice(["🥺", "😢", "💔", "🫂"])})
    if any(w in p for w in ["fire", "lit", "banger", "hard", "crazy", "insane", "🔥"]):
        return jsonify({"emoji": random.choice(["🔥", "💯", "🫡", "👏"])})
    if any(w in p for w in ["wow", "omg", "seriously", "really", "no way", "what"]):
        return jsonify({"emoji": random.choice(["😮", "😱", "🤯", "👀"])})
    if any(w in p for w in ["good", "nice", "cool", "great", "okay", "ok", "yes"]):
        return jsonify({"emoji": random.choice(["👍", "✅", "💪", "🙌"])})
    if any(w in p for w in ["money", "paid", "cash", "rich", "hustle", "business"]):
        return jsonify({"emoji": random.choice(["💰", "🤑", "💵", "📈"])})
    if any(w in p for w in ["food", "eat", "hungry", "delicious", "yummy"]):
        return jsonify({"emoji": random.choice(["😋", "🍽️", "🔥", "👌"])})
    if any(w in p for w in ["morning", "night", "sleep", "tired", "wake"]):
        return jsonify({"emoji": random.choice(["🌅", "😴", "🌙", "☀️"])})
    if any(w in p for w in ["fuck", "shit", "damn", "bro", "fam", "aye", "sema", "niaje", "maze", "si", "kweli", "aii", "oya"]):
        return jsonify({"emoji": random.choice(["💀", "😭", "🤣", "👀", "😂"])})
    # Sheng / Swahili positive vibes
    if any(w in p for w in ["niko fiti", "poa", "sawa", "safi", "fresh", "noma", "waoh", "wueh", "si poa", "moto"]):
        return jsonify({"emoji": random.choice(["🔥", "💯", "😎", "🤙", "👌"])})
        return jsonify({"emoji": random.choice(["💀", "😭", "🤣", "👀"])})

    return jsonify({"emoji": random.choice(["👍", "🙏", "💯", "😊", "🫡", None, None])})


# ── /pair proxy ──────────────────────────────────────────────────────────────
# Render (and any single-port host) only exposes one port — the $PORT Python
# binds to.  Node's pairing web server runs internally on WEB_PORT (3000).
# These two routes forward /pair traffic through Python so customers can reach
# the session-link page at your public Render/Railway URL.
# (NODE_PAIR_URL is defined earlier, alongside send_otp_whatsapp, which uses it too.)

@app.route("/pair-abandon", methods=["POST"])
async def pair_abandon_proxy():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{NODE_PAIR_URL}/pair-abandon")
            return Response(resp.content, status=resp.status_code, content_type="application/json")
    except Exception:
        return Response('{"ok":true}', status=200, content_type="application/json")

@app.route("/pair-reset", methods=["POST"])
async def pair_reset_proxy():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{NODE_PAIR_URL}/pair-reset")
            return Response(resp.content, status=resp.status_code, content_type="application/json")
    except Exception:
        return Response('{"ok":true}', status=200, content_type="application/json")

@app.route("/qr-reset", methods=["POST"])
async def qr_reset_proxy():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{NODE_PAIR_URL}/qr-reset")
            return Response(resp.content, status=resp.status_code, content_type="application/json")
    except Exception:
        return Response('{"ok":true}', status=200, content_type="application/json")

@app.route("/pair-status", methods=["GET"])
async def pair_status_proxy():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{NODE_PAIR_URL}/pair-status")
            return Response(resp.content, status=resp.status_code,
                            content_type="application/json")
    except Exception:
        return Response('{"code":null,"online":false}', status=200, content_type="application/json")

@app.route("/pair", methods=["GET"])
async def pair_proxy_get():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{NODE_PAIR_URL}/pair")
            return Response(resp.content, status=resp.status_code,
                            content_type=resp.headers.get("content-type", "text/html"))
    except Exception as e:
        return Response(
            f"<h2>⏳ Bot is starting up...</h2><p>Try again in 10 seconds.</p><p><small>{e}</small></p>",
            status=503, content_type="text/html"
        )

@app.route("/pair", methods=["POST"])
async def pair_proxy_post():
    try:
        body = await request.get_data()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{NODE_PAIR_URL}/pair",
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False
            )
            # Node now replies with 200 JSON {ok:true} — pass it through directly
            return Response(resp.content, status=resp.status_code,
                            content_type=resp.headers.get("content-type", "application/json"))
    except Exception as e:
        return Response(
            f"<h2>⏳ Bot is starting up...</h2><p>Try again in 10 seconds.</p><p><small>{e}</small></p>",
            status=503, content_type="text/html"
        )

# ─────────────────────────────────────────────────────────────────────────────

@app.route("/get-bio", methods=["GET"])
async def generate_auto_bio():
    bios = [
        f"🤖 Henry Ochibots v19™ | Online 24/7 | {time.strftime('%H:%M')} 🌐",
        f"⚡ Powered by Henry Ochibots | Always Active | {time.strftime('%H:%M')}",
        f"🔥 Henry Ochibots v19™ Running | {time.strftime('%d/%m %H:%M')} | DM me 📩",
        f"🔥 Henry Ochibots Automation | {time.strftime('%H:%M')} | All systems go",
    ]
    return jsonify({"bio": random.choice(bios)})


@app.route("/webhook", methods=["POST"])
async def process_command_pipeline():
    data = await request.get_json() or {}
    incoming_text = data.get("body", "").strip()
    sender = data.get("sender", "").strip()
    model_pref = data.get("model", "").strip() or None

    if await check_db_blacklist(sender):
        return jsonify({"reply": "❌ Access Denied. Your profile node remains blacklisted."})

    # 0. Keyword auto-reply — checked first so custom triggers (e.g. "price",
    #    "hi") work even when they don't start with a slash command.
    if await is_feature_enabled("keywords"):
        kw_reply = await match_keyword(incoming_text)
        if kw_reply:
            return jsonify({"reply": kw_reply})

    # 1. AI Command
    if incoming_text.startswith("/ask "):
        if not await is_feature_enabled("ai_chat"):
            return jsonify({"reply": "⚠️ AI chat is currently disabled by the admin."})
        prompt = incoming_text[5:].strip()
        if not prompt:
            return jsonify({"reply": "⚠️ Please provide a query after /ask"})
        reply = await call_groq_ai(prompt, model=model_pref)
        return jsonify({"reply": reply})

    # 2. Paint Command — sends actual image
    elif incoming_text.startswith("/paint "):
        prompt = incoming_text[7:].strip()
        if not prompt:
            return jsonify({"reply": "⚠️ Please provide text after /paint"})
        encoded = quote_plus(prompt)
        url = f"https://placehold.co/1200x630/0f172a/38bdf8?text={encoded}&font=montserrat"
        return jsonify({"type": "image", "url": url, "caption": f"🎨 {prompt}"})

    # 3. Video Download — sends actual video
    elif incoming_text.startswith("/download_video "):
        if not await is_feature_enabled("downloads"):
            return jsonify({"reply": "⚠️ Downloads are currently disabled by the admin."})
        url = incoming_text[16:].strip()
        if not url:
            return jsonify({"reply": "⚠️ Please provide a URL after /download_video"})
        result = await get_video_url(url)
        if result["success"] and result["url"]:
            return jsonify({
                "type": "video",
                "url": result["url"],
                "caption": f"🎬 {result.get('title', 'Video')} ({result.get('duration', '')})"
            })
        return jsonify({"reply": f"❌ Could not download video.\n{result.get('error', 'Unknown error')}"})

    # 4. Song Download — sends actual audio
    elif incoming_text.startswith("/download_song "):
        if not await is_feature_enabled("downloads"):
            return jsonify({"reply": "⚠️ Downloads are currently disabled by the admin."})
        url = incoming_text[15:].strip()
        if not url:
            return jsonify({"reply": "⚠️ Please provide a URL after /download_song"})
        result = await get_audio_url(url)
        if result["success"] and result["url"]:
            return jsonify({
                "type": "audio",
                "url": result["url"],
                "caption": f"🎵 {result.get('title', 'Audio')}"
            })
        return jsonify({"reply": f"❌ Could not extract audio.\n{result.get('error', 'Unknown error')}"})

    # 5. Recover Command
    elif incoming_text.startswith("/recover"):
        # 🔒 owner-only — any stranger could otherwise read deleted messages.
        # No hardcoded fallback number: resolves admin-panel override, then
        # OWNER_NUMBER env var, then denies everyone if neither is set.
        owner_number = await _get_effective_owner_number()
        sender_clean = sender.split("@")[0].split(":")[0]
        if not owner_number or sender_clean != owner_number:
            return jsonify({"reply": "❌ This command is owner-only."})
        parts = incoming_text.split(None, 1)
        target_jid = parts[1].strip() if len(parts) > 1 else ""
        if not target_jid:
            return jsonify({"reply": "⚠️ Please provide a contact number after /recover"})
        async with aiosqlite.connect(DB_FILE) as db:
            async with db.execute(
                "SELECT name, body, timestamp FROM messages WHERE sender LIKE ? ORDER BY timestamp DESC LIMIT 10",
                (f"%{target_jid}%",)
            ) as cursor:
                rows = await cursor.fetchall()
                if not rows:
                    return jsonify({"reply": f"❌ No cached messages found for {target_jid}\n\n💡 Messages are only saved while the bot is running."})
                lines = [f"🗑️ *Last messages from {target_jid}:*\n"]
                for row in rows:
                    t = time.strftime("%d/%m %H:%M", time.localtime(row[2]))
                    lines.append(f"👤 *{row[0]}* [{t}]:\n{row[1]}")
                return jsonify({"reply": "\n\n".join(lines)})

    # 6. Viewonce Command
    elif incoming_text.startswith("/viewonce"):
        # 🔒 owner-only — view-once media is private by definition. Same
        # no-hardcoded-fallback resolution as /recover above.
        owner_number = await _get_effective_owner_number()
        sender_clean = sender.split("@")[0].split(":")[0]
        if not owner_number or sender_clean != owner_number:
            return jsonify({"reply": "❌ This command is owner-only."})
        parts = incoming_text.split()
        target = parts[1].strip() if len(parts) > 1 else None
        async with aiosqlite.connect(DB_FILE) as db:
            if target:
                query = "SELECT name, filename, media_type, caption, timestamp FROM viewonce_media WHERE sender LIKE ? ORDER BY timestamp DESC LIMIT 10"
                params = (f"%{target}%",)
            else:
                query = "SELECT name, filename, media_type, caption, timestamp FROM viewonce_media ORDER BY timestamp DESC LIMIT 10"
                params = ()
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                if not rows:
                    return jsonify({"reply": f"❌ No view once media saved yet.\n\n💡 Send a view once photo/video to the bot number and it will be intercepted automatically."})
                lines = ["👁️ *Saved View Once Media:*\n"]
                for row in rows:
                    name_r, filename, mtype, cap, ts = row
                    mtype_clean = mtype.replace("Message", "")
                    time_str = time.strftime("%d/%m %H:%M", time.localtime(ts/1000 if ts > 1e12 else ts))
                    lines.append(f"• {mtype_clean.upper()} from *{name_r}* at {time_str}" + (f"\n  Caption: {cap}" if cap else ""))
                return jsonify({"reply": "\n".join(lines)})

    return jsonify({"reply": "ℹ️ Unknown command. Type /ask, /paint, /download_video, /download_song, /recover or /viewonce"})



# ══════════════════════════════════════════════════════════════════════════
# ✅ NEW — extended-commands update. All routes below are additive and only
# called internally by client_bridge.js / plugins/extended.js (same trust
# level as /log-message, /bot/features, etc. — no panel cookie required).
# Nothing above this banner was modified except: call_groq_ai() gained an
# optional `system` kwarg, and init_db() gained new CREATE TABLE statements.
# ══════════════════════════════════════════════════════════════════════════

import re as _re
_STOPWORDS = {
    "the","a","an","is","are","was","were","and","or","but","to","of","in","on",
    "for","with","this","that","it","you","i","we","they","he","she","na","ni",
    "za","ya","wa","kwa","hii","hiyo","the","am","be","been","at","as","so",
}


# ── AI helpers: .persona / .translate ───────────────────────────────────────
@app.route("/ai/reply", methods=["POST"])
async def ai_reply():
    data = await request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    system = (data.get("system") or "").strip() or None
    model = (data.get("model") or "").strip() or None
    if not prompt:
        return jsonify({"reply": None})
    reply = await call_groq_ai(prompt, model=model, system=system)
    return jsonify({"reply": reply})


# ── Generic per-chat settings KV (persona, memory, silence, antidelete,
#    autoview, autoreact, fullpp) ────────────────────────────────────────────
@app.route("/chat-settings/set", methods=["POST"])
async def chat_settings_set():
    data = await request.get_json() or {}
    chat_id = (data.get("chat_id") or "").strip()
    key = (data.get("key") or "").strip()
    value = data.get("value", "")
    if not chat_id or not key:
        return jsonify({"error": "chat_id and key required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO chat_settings (chat_id, key, value) VALUES (?, ?, ?) "
            "ON CONFLICT(chat_id, key) DO UPDATE SET value=excluded.value",
            (chat_id, key, str(value))
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/chat-settings/get", methods=["GET"])
async def chat_settings_get():
    chat_id = (request.args.get("chat_id") or "").strip()
    key = (request.args.get("key") or "").strip()
    if not chat_id or not key:
        return jsonify({"error": "chat_id and key required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT value FROM chat_settings WHERE chat_id = ? AND key = ?", (chat_id, key)
        ) as c:
            row = await c.fetchone()
    return jsonify({"value": row[0] if row else None})


@app.route("/chat-settings/all", methods=["GET"])
async def chat_settings_all():
    chat_id = (request.args.get("chat_id") or "").strip()
    if not chat_id:
        return jsonify({"error": "chat_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT key, value FROM chat_settings WHERE chat_id = ?", (chat_id,)
        ) as c:
            rows = await c.fetchall()
    return jsonify({"settings": {r[0]: r[1] for r in rows}})


@app.route("/chat-settings/delete", methods=["POST"])
async def chat_settings_delete():
    data = await request.get_json() or {}
    chat_id = (data.get("chat_id") or "").strip()
    key = (data.get("key") or "").strip()
    if not chat_id or not key:
        return jsonify({"error": "chat_id and key required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM chat_settings WHERE chat_id = ? AND key = ?", (chat_id, key))
        await db.commit()
    return jsonify({"success": True})


# ── Autoreply: chat-facing wrapper around the EXISTING `keywords` table
#    (same table the admin panel's Keywords tab already uses) — no new
#    storage, just a WhatsApp-command interface onto it. ────────────────────
@app.route("/bot/autoreply/list", methods=["GET"])
async def bot_autoreply_list():
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT trigger, reply, match_type, enabled FROM keywords ORDER BY trigger"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"keywords": [
        {"trigger": r[0], "reply": r[1], "match_type": r[2], "enabled": bool(r[3])} for r in rows
    ]})


@app.route("/bot/autoreply/add", methods=["POST"])
async def bot_autoreply_add():
    data = await request.get_json() or {}
    trigger = (data.get("trigger") or "").strip()
    reply = (data.get("reply") or "").strip()
    match_type = (data.get("match_type") or "contains").strip()
    if match_type not in ("contains", "exact", "starts_with"):
        match_type = "contains"
    if not trigger or not reply:
        return jsonify({"error": "trigger and reply are required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """INSERT INTO keywords (trigger, reply, match_type, enabled, timestamp)
               VALUES (?, ?, ?, 1, ?)
               ON CONFLICT(trigger) DO UPDATE SET reply=excluded.reply,
                   match_type=excluded.match_type, timestamp=excluded.timestamp""",
            (trigger, reply, match_type, time.time())
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/bot/autoreply/remove", methods=["POST"])
async def bot_autoreply_remove():
    data = await request.get_json() or {}
    trigger = (data.get("trigger") or "").strip()
    if not trigger:
        return jsonify({"error": "trigger is required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM keywords WHERE trigger = ?", (trigger,))
        await db.commit()
    return jsonify({"success": True})


# ── Group intelligence: .analyze .activity .topics .influence .track
#    .active .detector .clearrelations ──────────────────────────────────────
@app.route("/group-intel/log", methods=["POST"])
async def group_intel_log():
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    sender = data.get("sender")
    name = data.get("name", "User")
    body = data.get("body", "")
    timestamp = data.get("timestamp", time.time())
    if not group_id or not sender:
        return jsonify({"status": "ignored"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO group_activity (group_id, sender, name, body, timestamp) VALUES (?, ?, ?, ?, ?)",
            (group_id, sender, name, body, timestamp)
        )
        # Lightweight relation signal: whoever posted immediately before this
        # sender, in the same group, gets their pair-weight bumped by 1 —
        # a simple proxy for "who talks around whom" without needing to
        # parse reply-to/mentions.
        async with db.execute(
            "SELECT sender FROM group_activity WHERE group_id = ? AND sender != ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (group_id, sender)
        ) as c:
            prev = await c.fetchone()
        if prev:
            a, b = sorted([sender, prev[0]])
            await db.execute(
                """INSERT INTO group_relations (group_id, user_a, user_b, weight) VALUES (?, ?, ?, 1)
                   ON CONFLICT(group_id, user_a, user_b) DO UPDATE SET weight = weight + 1""",
                (group_id, a, b)
            )
        await db.commit()
    return jsonify({"status": "logged"})


@app.route("/group-intel/stats", methods=["GET"])
async def group_intel_stats():
    group_id = request.args.get("group_id")
    hours = float(request.args.get("hours", 24))
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    cutoff = time.time() - hours * 3600
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT sender, name, body, timestamp FROM group_activity WHERE group_id = ? AND timestamp >= ? "
            "ORDER BY timestamp DESC LIMIT 2000",
            (group_id, cutoff)
        ) as c:
            rows = await c.fetchall()

    total = len(rows)
    by_sender = {}
    words = {}
    for sender, name, body, ts in rows:
        by_sender.setdefault(sender, {"name": name, "count": 0})
        by_sender[sender]["count"] += 1
        for w in _re.findall(r"[a-zA-Z']{4,}", (body or "").lower()):
            if w in _STOPWORDS:
                continue
            words[w] = words.get(w, 0) + 1

    most_active = sorted(by_sender.items(), key=lambda x: -x[1]["count"])[:10]
    top_topics = sorted(words.items(), key=lambda x: -x[1])[:10]

    return jsonify({
        "group_id": group_id,
        "window_hours": hours,
        "total_messages": total,
        "unique_participants": len(by_sender),
        "most_active": [{"sender": s, "name": v["name"], "messages": v["count"]} for s, v in most_active],
        "top_topics": [{"word": w, "count": c} for w, c in top_topics],
    })


@app.route("/group-intel/relations", methods=["GET"])
async def group_intel_relations():
    group_id = request.args.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT user_a, user_b, weight FROM group_relations WHERE group_id = ? ORDER BY weight DESC LIMIT 15",
            (group_id,)
        ) as c:
            rows = await c.fetchall()
    return jsonify({"relations": [{"a": r[0], "b": r[1], "weight": r[2]} for r in rows]})


@app.route("/group-intel/clear", methods=["POST"])
async def group_intel_clear():
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM group_relations WHERE group_id = ?", (group_id,))
        await db.commit()
    return jsonify({"success": True})


# ── Moderation: .warn (reuses the EXISTING group_warnings table/antilink
#    strike counter — same 3-strike logic, just callable manually by an
#    admin instead of only auto-triggering on links), .report, .silence
#    (silence lives in chat_settings above, no route needed) ────────────────
@app.route("/moderation/warn", methods=["POST"])
async def moderation_warn():
    """Manual version of the existing /antilink/strike — same table,
    same 3-strike/auto-kick-signal semantics, just admin-triggered."""
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    sender = data.get("target")
    if not group_id or not sender:
        return jsonify({"error": "group_id and target required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            """INSERT INTO group_warnings (group_id, sender, count) VALUES (?, ?, 1)
               ON CONFLICT(group_id, sender) DO UPDATE SET count = count + 1""",
            (group_id, sender)
        )
        await db.commit()
        async with db.execute(
            "SELECT count FROM group_warnings WHERE group_id = ? AND sender = ?",
            (group_id, sender)
        ) as c:
            row = await c.fetchone()
    count = row[0] if row else 1
    should_kick = count >= 3
    if should_kick:
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("DELETE FROM group_warnings WHERE group_id = ? AND sender = ?", (group_id, sender))
            await db.commit()
    return jsonify({"count": count, "kick": should_kick})


@app.route("/reports/create", methods=["POST"])
async def reports_create():
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    reporter = data.get("reporter")
    target = data.get("target")
    reason = (data.get("reason") or "").strip()
    if not reporter or not reason:
        return jsonify({"error": "reporter and reason required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO reports (group_id, reporter, target, reason, timestamp) VALUES (?, ?, ?, ?, ?)",
            (group_id, reporter, target, reason, time.time())
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/reports", methods=["GET"])
async def admin_reports():
    # Panel-authenticated, same pattern as admin_get_blacklist etc.
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, group_id, reporter, target, reason, timestamp, resolved FROM reports ORDER BY timestamp DESC LIMIT 200"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"reports": [
        {"id": r[0], "group_id": r[1], "reporter": r[2], "target": r[3], "reason": r[4], "timestamp": r[5], "resolved": bool(r[6])}
        for r in rows
    ]})


@app.route("/admin/reports/resolve", methods=["POST"])
async def admin_reports_resolve():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json() or {}
    report_id = data.get("id")
    if not report_id:
        return jsonify({"error": "id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE reports SET resolved = 1 WHERE id = ?", (report_id,))
        await db.commit()
    return jsonify({"success": True})


# ── Bans: .ban / .removeall audit trail (actual WA removal still happens
#    via the socket, same as the existing .kick — this just records it so
#    re-adds can be checked against it) ─────────────────────────────────────
@app.route("/bans/add", methods=["POST"])
async def bans_add():
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    number = data.get("number")
    reason = (data.get("reason") or "").strip()
    if not group_id or not number:
        return jsonify({"error": "group_id and number required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO group_bans (group_id, number, reason, banned_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(group_id, number) DO UPDATE SET reason=excluded.reason, banned_at=excluded.banned_at",
            (group_id, number, reason, time.time())
        )
        await db.commit()
    return jsonify({"success": True})


@app.route("/bans/check", methods=["GET"])
async def bans_check():
    group_id = request.args.get("group_id")
    number = request.args.get("number")
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT reason FROM group_bans WHERE group_id = ? AND number = ?", (group_id, number)
        ) as c:
            row = await c.fetchone()
    return jsonify({"banned": bool(row), "reason": row[0] if row else None})


@app.route("/admin/group-bans", methods=["GET"])
async def admin_group_bans():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT group_id, number, reason, banned_at FROM group_bans ORDER BY banned_at DESC LIMIT 300"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"bans": [{"group_id": r[0], "number": r[1], "reason": r[2], "banned_at": r[3]} for r in rows]})


@app.route("/admin/group-bans/remove", methods=["POST"])
async def admin_group_bans_remove():
    """✅ NEW: was missing entirely — /admin/group-bans could list bans but
    there was no way to lift one short of touching the DB directly."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    number = (data.get("number") or "").strip()
    if not group_id or not number:
        return jsonify({"error": "group_id and number required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM group_bans WHERE group_id = ? AND number = ?", (group_id, number))
        await db.commit()
    return jsonify({"success": True})


# ── Polls: .poll .vote .results .endpoll ────────────────────────────────────
@app.route("/polls/create", methods=["POST"])
async def polls_create():
    data = await request.get_json() or {}
    group_id = data.get("group_id")
    question = (data.get("question") or "").strip()
    options = data.get("options") or []
    created_by = data.get("created_by")
    if not group_id or not question or len(options) < 2:
        return jsonify({"error": "group_id, question, and 2+ options required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        cur = await db.execute(
            "INSERT INTO polls (group_id, question, options, created_by, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (group_id, question, json.dumps(options), created_by, time.time())
        )
        await db.commit()
        poll_id = cur.lastrowid
    return jsonify({"success": True, "poll_id": poll_id})


@app.route("/polls/vote", methods=["POST"])
async def polls_vote():
    data = await request.get_json() or {}
    poll_id = data.get("poll_id")
    voter = data.get("voter")
    option_index = data.get("option_index")
    if poll_id is None or not voter or option_index is None:
        return jsonify({"error": "poll_id, voter, option_index required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT active, options FROM polls WHERE id = ?", (poll_id,)) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"error": "poll not found"}), 404
        if not row[0]:
            return jsonify({"error": "poll has ended"}), 400
        options = json.loads(row[1])
        if not (0 <= option_index < len(options)):
            return jsonify({"error": "invalid option"}), 400
        await db.execute(
            "INSERT INTO poll_votes (poll_id, voter, option_index) VALUES (?, ?, ?) "
            "ON CONFLICT(poll_id, voter) DO UPDATE SET option_index=excluded.option_index",
            (poll_id, voter, option_index)
        )
        await db.commit()
    return jsonify({"success": True})


async def _poll_results(poll_id):
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT question, options, active FROM polls WHERE id = ?", (poll_id,)) as c:
            poll_row = await c.fetchone()
        if not poll_row:
            return None
        async with db.execute("SELECT option_index, COUNT(*) FROM poll_votes WHERE poll_id = ? GROUP BY option_index", (poll_id,)) as c:
            vote_rows = await c.fetchall()
    options = json.loads(poll_row[1])
    counts = {i: 0 for i in range(len(options))}
    for idx, cnt in vote_rows:
        counts[idx] = cnt
    return {
        "poll_id": poll_id,
        "question": poll_row[0],
        "active": bool(poll_row[2]),
        "results": [{"option": opt, "votes": counts.get(i, 0)} for i, opt in enumerate(options)],
        "total_votes": sum(counts.values()),
    }


@app.route("/polls/results", methods=["GET"])
async def polls_results():
    poll_id = request.args.get("poll_id", type=int)
    if not poll_id:
        return jsonify({"error": "poll_id required"}), 400
    result = await _poll_results(poll_id)
    if not result:
        return jsonify({"error": "poll not found"}), 404
    return jsonify(result)


@app.route("/polls/active", methods=["GET"])
async def polls_active():
    group_id = request.args.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, question FROM polls WHERE group_id = ? AND active = 1 ORDER BY created_at DESC LIMIT 1",
            (group_id,)
        ) as c:
            row = await c.fetchone()
    return jsonify({"poll": {"poll_id": row[0], "question": row[1]} if row else None})


@app.route("/polls/end", methods=["POST"])
async def polls_end():
    data = await request.get_json() or {}
    poll_id = data.get("poll_id")
    if not poll_id:
        return jsonify({"error": "poll_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE polls SET active = 0 WHERE id = ?", (poll_id,))
        await db.commit()
    result = await _poll_results(poll_id)
    return jsonify(result or {"success": True})



# ══════════════════════════════════════════════════════════════════════════
# ✅ NEW — customer chat panel. Anonymous-by-default public room + DMs for
# bot customers to talk to each other from the web panel. Identity is a
# client-generated/persisted anon_id (no login required); a nickname is
# optional. All additive — no existing routes/tables touched.
# ══════════════════════════════════════════════════════════════════════════

CHAT_MAX_MESSAGE_LEN = 1000
CHAT_MIN_SEND_INTERVAL_SECONDS = 1.2  # basic per-anon_id spam throttle
_chat_last_send = {}  # anon_id -> last send timestamp (in-memory, resets on restart)


def _chat_default_name(anon_id: str) -> str:
    return f"Anon-{anon_id[-4:].upper()}"


def _chat_dm_room(a: str, b: str) -> str:
    pair = sorted([a, b])
    return f"dm:{pair[0]}:{pair[1]}"


@app.route("/chat/identify", methods=["POST"])
async def chat_identify():
    """Called once per browser on first chat-panel load. If the client
    already has an anon_id saved (localStorage), pass it in to reattach to
    the same identity/nickname; otherwise a new one is minted."""
    data = await request.get_json(silent=True) or {}
    anon_id = (data.get("anon_id") or "").strip()
    now = time.time()
    async with aiosqlite.connect(DB_FILE) as db:
        if anon_id:
            async with db.execute("SELECT nickname, banned FROM chat_users WHERE anon_id = ?", (anon_id,)) as c:
                row = await c.fetchone()
            if row:
                if row[1]:
                    return jsonify({"success": False, "error": "This chat identity has been banned."}), 403
                await db.execute("UPDATE chat_users SET last_seen = ? WHERE anon_id = ?", (now, anon_id))
                await db.commit()
                return jsonify({"success": True, "anon_id": anon_id, "nickname": row[0] or _chat_default_name(anon_id)})
        # Mint a new identity
        anon_id = "anon_" + secrets.token_hex(5)
        await db.execute(
            "INSERT INTO chat_users (anon_id, nickname, created_at, last_seen, banned) VALUES (?, NULL, ?, ?, 0)",
            (anon_id, now, now)
        )
        await db.commit()
    return jsonify({"success": True, "anon_id": anon_id, "nickname": _chat_default_name(anon_id)})


@app.route("/chat/nickname", methods=["POST"])
async def chat_set_nickname():
    data = await request.get_json(silent=True) or {}
    anon_id = (data.get("anon_id") or "").strip()
    nickname = (data.get("nickname") or "").strip()[:24]
    if not anon_id:
        return jsonify({"success": False, "error": "anon_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT banned FROM chat_users WHERE anon_id = ?", (anon_id,)) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Unknown chat identity — call /chat/identify first."}), 404
        if row[0]:
            return jsonify({"success": False, "error": "This chat identity has been banned."}), 403
        await db.execute(
            "UPDATE chat_users SET nickname = ? WHERE anon_id = ?",
            (nickname or None, anon_id)
        )
        await db.commit()
    return jsonify({"success": True, "nickname": nickname or _chat_default_name(anon_id)})


@app.route("/chat/send", methods=["POST"])
async def chat_send():
    data = await request.get_json(silent=True) or {}
    anon_id = (data.get("anon_id") or "").strip()
    body = (data.get("body") or "").strip()
    to = (data.get("to") or "").strip() or None  # None = public room
    if not anon_id or not body:
        return jsonify({"success": False, "error": "anon_id and body required"}), 400
    if len(body) > CHAT_MAX_MESSAGE_LEN:
        return jsonify({"success": False, "error": f"Message too long (max {CHAT_MAX_MESSAGE_LEN} chars)."}), 400

    now = time.time()
    last = _chat_last_send.get(anon_id, 0)
    if now - last < CHAT_MIN_SEND_INTERVAL_SECONDS:
        return jsonify({"success": False, "error": "Sending too fast — slow down a little."}), 429

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT nickname, banned FROM chat_users WHERE anon_id = ?", (anon_id,)) as c:
            row = await c.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Unknown chat identity — call /chat/identify first."}), 404
        if row[0] is not None and row[1]:
            return jsonify({"success": False, "error": "This chat identity has been banned."}), 403
        sender_name = row[0] or _chat_default_name(anon_id)

        room = _chat_dm_room(anon_id, to) if to else "public"
        await db.execute(
            "INSERT INTO chat_messages (room, sender_id, sender_name, body, created_at, deleted) VALUES (?, ?, ?, ?, ?, 0)",
            (room, anon_id, sender_name, body, now)
        )
        if to:
            await db.execute(
                "INSERT INTO chat_dm_index (room, user_a, user_b, last_message_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(room) DO UPDATE SET last_message_at=excluded.last_message_at",
                (room, *sorted([anon_id, to]), now)
            )
        await db.commit()
    _chat_last_send[anon_id] = now
    return jsonify({"success": True, "room": room})


@app.route("/chat/messages", methods=["GET"])
async def chat_messages():
    """Polling endpoint. Public room: pass room=public. DM: pass anon_id +
    to, the canonical DM room is derived server-side so a client can only
    ever read a DM thread it's actually part of."""
    anon_id = (request.args.get("anon_id") or "").strip()
    to = (request.args.get("to") or "").strip() or None
    since_id = int(request.args.get("since_id") or 0)
    limit = min(int(request.args.get("limit") or 50), 200)
    if not anon_id:
        return jsonify({"error": "anon_id required"}), 400

    room = _chat_dm_room(anon_id, to) if to else "public"
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, sender_id, sender_name, body, created_at FROM chat_messages "
            "WHERE room = ? AND id > ? AND deleted = 0 ORDER BY id ASC LIMIT ?",
            (room, since_id, limit)
        ) as c:
            rows = await c.fetchall()
    return jsonify({"room": room, "messages": [
        {"id": r[0], "sender_id": r[1], "sender_name": r[2], "body": r[3], "created_at": r[4], "is_me": r[1] == anon_id}
        for r in rows
    ]})


@app.route("/chat/dm/threads", methods=["GET"])
async def chat_dm_threads():
    """Sidebar list of a user's DM conversations, most recent first."""
    anon_id = (request.args.get("anon_id") or "").strip()
    if not anon_id:
        return jsonify({"error": "anon_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT room, user_a, user_b, last_message_at FROM chat_dm_index "
            "WHERE user_a = ? OR user_b = ? ORDER BY last_message_at DESC LIMIT 100",
            (anon_id, anon_id)
        ) as c:
            rows = await c.fetchall()
        threads = []
        for room, ua, ub, last_ts in rows:
            other_id = ub if ua == anon_id else ua
            async with db.execute("SELECT nickname FROM chat_users WHERE anon_id = ?", (other_id,)) as c2:
                nrow = await c2.fetchone()
            other_name = (nrow[0] if nrow and nrow[0] else _chat_default_name(other_id))
            threads.append({"room": room, "other_id": other_id, "other_name": other_name, "last_message_at": last_ts})
    return jsonify({"threads": threads})


# ── Admin moderation (panel-authenticated) ──────────────────────────────────
@app.route("/admin/chat/recent", methods=["GET"])
async def admin_chat_recent():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT id, room, sender_id, sender_name, body, created_at, deleted FROM chat_messages "
            "ORDER BY id DESC LIMIT 300"
        ) as c:
            rows = await c.fetchall()
    return jsonify({"messages": [
        {"id": r[0], "room": r[1], "sender_id": r[2], "sender_name": r[3], "body": r[4], "created_at": r[5], "deleted": bool(r[6])}
        for r in rows
    ]})


@app.route("/admin/chat/delete", methods=["POST"])
async def admin_chat_delete():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    msg_id = data.get("id")
    if not msg_id:
        return jsonify({"error": "id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE chat_messages SET deleted = 1 WHERE id = ?", (msg_id,))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/chat/ban", methods=["POST"])
async def admin_chat_ban():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    anon_id = (data.get("anon_id") or "").strip()
    banned = 1 if data.get("banned", True) else 0
    if not anon_id:
        return jsonify({"error": "anon_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE chat_users SET banned = ? WHERE anon_id = ?", (banned, anon_id))
        await db.commit()
    return jsonify({"success": True})


@app.route("/admin/owner-chats", methods=["GET"])
async def admin_owner_chats():
    """Admin Panel: list every chat Henry's own number has seen (from
    owner_first_seen markers), with the current owner_ai_allowed toggle."""
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT chat_id FROM chat_settings WHERE key = 'owner_first_seen'"
        ) as c:
            chat_ids = [r[0] for r in await c.fetchall()]
        chats = []
        for cid in chat_ids:
            async with db.execute(
                "SELECT value FROM chat_settings WHERE chat_id = ? AND key = 'owner_ai_allowed'", (cid,)
            ) as c2:
                row = await c2.fetchone()
            chats.append({"chat_id": cid, "ai_allowed": bool(row and row[0] == "on")})
    return jsonify({"chats": chats})


@app.route("/admin/owner-chats/toggle", methods=["POST"])
async def admin_owner_chats_toggle():
    if not await _check_admin_auth_async(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = await request.get_json(silent=True) or {}
    chat_id = (data.get("chat_id") or "").strip()
    allowed = bool(data.get("allowed"))
    if not chat_id:
        return jsonify({"error": "chat_id required"}), 400
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO chat_settings (chat_id, key, value) VALUES (?, 'owner_ai_allowed', ?) "
            "ON CONFLICT(chat_id, key) DO UPDATE SET value = excluded.value",
            (chat_id, "on" if allowed else "off")
        )
        await db.commit()
    return jsonify({"success": True})



# ══════════════════════════════════════════════════════════════════════════
# ✅ NEW: Command Console — lets a customer who has an ACTIVATED session log
# in with their paired phone number (proved via a WhatsApp OTP, same pattern
# as registration) and then send messages / set status / set bio / set name
# on their own linked WhatsApp account from the website.
#
# Deliberately NOT included here (see chat for why):
#   - Full inbox/message history — needs a persistent message store this
#     bot doesn't have yet.
#   - "Change number" — WhatsApp's real number migration is an official
#     in-app flow; there's no safe way to do it through an unofficial
#     library without real risk of the account getting permanently banned.
#
# Auth model: request-otp/verify-otp issue a short-lived opaque Bearer token
# (kept in memory, not the DB — it's just a login session, same spirit as
# the Bearer-password admin auth already used elsewhere in this file). The
# owner can additionally act on ANY session using the admin Bearer password.
# ══════════════════════════════════════════════════════════════════════════
_console_challenges: dict = {}   # session_id -> {otp, expires, phone}
_console_tokens: dict = {}       # token -> {session_id, phone, expires}
CONSOLE_OTP_TTL = 300     # 5 minutes to enter the OTP
CONSOLE_TOKEN_TTL = 3600  # 1 hour login

async def _get_session_phone_if_activated(session_id: str):
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT phone, activated, expiry_ts FROM session_subscriptions WHERE session = ?", (session_id,)
        ) as c:
            row = await c.fetchone()
    if not row or not row[0] or not row[1]:
        return None
    phone, activated, expiry_ts = row
    if expiry_ts and time.time() >= expiry_ts:
        return None
    return phone


async def _console_authed_phone(req, session_id: str):
    """Returns the authenticated phone for this session_id, or None.
    Accepts either: a valid console Bearer token for exactly this session,
    or the admin Bearer password (owner override, any session)."""
    token = req.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        return None
    if await _check_admin_auth_async(req):
        return await _get_session_phone_if_activated(session_id) or "owner"
    entry = _console_tokens.get(token)
    if not entry or entry["session_id"] != session_id:
        return None
    if time.time() >= entry["expires"]:
        _console_tokens.pop(token, None)
        return None
    return entry["phone"]


@app.route("/api/console/request-otp", methods=["POST"])
async def console_request_otp():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    if not session_id:
        return jsonify({"success": False, "error": "session is required"}), 400
    phone = await _get_session_phone_if_activated(session_id)
    if not phone:
        return jsonify({"success": False, "error": "This session isn't an activated, paid session yet."}), 403
    otp = _generate_otp()
    _console_challenges[session_id] = {"otp": otp, "expires": time.time() + CONSOLE_OTP_TTL, "phone": phone}
    result = await send_otp_whatsapp(phone, otp, "there")
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error")}), 503
    masked = ("•" * max(0, len(phone) - 4)) + phone[-4:]
    return jsonify({"success": True, "sent_to": masked})


@app.route("/api/console/verify-otp", methods=["POST"])
async def console_verify_otp():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    otp = (data.get("otp") or "").strip()
    challenge = _console_challenges.get(session_id)
    if not challenge or time.time() >= challenge["expires"]:
        _console_challenges.pop(session_id, None)
        return jsonify({"success": False, "error": "Code expired — request a new one."}), 400
    if otp != challenge["otp"]:
        return jsonify({"success": False, "error": "Incorrect code."}), 400
    _console_challenges.pop(session_id, None)
    token = secrets.token_urlsafe(32)
    _console_tokens[token] = {
        "session_id": session_id, "phone": challenge["phone"], "expires": time.time() + CONSOLE_TOKEN_TTL
    }
    return jsonify({"success": True, "token": token, "expires_in": CONSOLE_TOKEN_TTL})


@app.route("/api/console/send", methods=["POST"])
async def console_send():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    if not await _console_authed_phone(request, session_id):
        return jsonify({"success": False, "error": "Not logged in to this session."}), 401
    to = (data.get("to") or "").strip()
    text = (data.get("text") or "").strip()
    if not to or not text:
        return jsonify({"success": False, "error": "to and text are required"}), 400
    result = await _call_node_internal("/internal/action", {
        "sessionId": session_id, "action": "send-message", "to": to, "text": text
    })
    return jsonify(result), (200 if result.get("success") else 503)


@app.route("/api/console/status", methods=["POST"])
async def console_status():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    if not await _console_authed_phone(request, session_id):
        return jsonify({"success": False, "error": "Not logged in to this session."}), 401
    text = data.get("text", "")
    result = await _call_node_internal("/internal/action", {
        "sessionId": session_id, "action": "set-status", "text": text
    })
    return jsonify(result), (200 if result.get("success") else 503)


# WhatsApp only has one "About"/status text field — "bio" here is an alias
# of the same action, kept as its own route so the console UI can label it
# "Bio" without confusing customers about what "status" (disappearing
# updates) usually means elsewhere.
@app.route("/api/console/bio", methods=["POST"])
async def console_bio():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    if not await _console_authed_phone(request, session_id):
        return jsonify({"success": False, "error": "Not logged in to this session."}), 401
    text = data.get("text", "")
    result = await _call_node_internal("/internal/action", {
        "sessionId": session_id, "action": "set-bio", "text": text
    })
    return jsonify(result), (200 if result.get("success") else 503)


@app.route("/api/console/name", methods=["POST"])
async def console_name():
    data = await request.get_json(silent=True) or {}
    session_id = (data.get("session") or "").strip()
    if not await _console_authed_phone(request, session_id):
        return jsonify({"success": False, "error": "Not logged in to this session."}), 401
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "name is required"}), 400
    result = await _call_node_internal("/internal/action", {
        "sessionId": session_id, "action": "set-name", "name": name
    })
    return jsonify(result), (200 if result.get("success") else 503)


@app.route("/console")
async def console_page():
    return Response((Path(__file__).parent / "console.html").read_text(encoding="utf-8"), mimetype="text/html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
