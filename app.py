import os
import re
import secrets
import sqlite3
import string
import time
import math
import json
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import Flask, Response, abort, jsonify, redirect, render_template_string, request, session, url_for, flash

APP_NAME = "XITEXE KEY VERIFICATION"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://xitexekey-production.up.railway.app").rstrip("/")
DATABASE = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "xitexe.sqlite3"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "xit")
VPLINK_TOKEN = os.getenv("VPLINK_TOKEN", "6feb48cdd4034b0c323bc1c1353561921c708592")
VPLINK_API_URL = os.getenv("VPLINK_API_URL", "https://vplink.in/api")
KEY_TTL_HOURS = int(os.getenv("KEY_TTL_HOURS", "5"))
MAX_KEY_TTL_HOURS = int(os.getenv("MAX_KEY_TTL_HOURS", "50000000"))
MAINTENANCE = os.getenv("MAINTENANCE", "0") == "1"
TELEGRAM_URL = os.getenv("TELEGRAM_URL", "https://t.me/xitexez")
WHATSAPP_URL = os.getenv("WHATSAPP_URL", "https://whatsapp.com/channel/0029Vb7LRGS3AzNbOj5ZIV1r")
APK_UPDATE_URL = os.getenv("APK_UPDATE_URL", "").strip()
KEY_CALLBACK_MIN_WAIT_SECONDS = 60
BYPASS_DETECTED_MESSAGE = "bypass link detected pls start all over do not bypass."
BYPASS_DETECTED_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="robots" content="noindex,nofollow">
<title></title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}
body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;color:#f8fafc;background:radial-gradient(ellipse at 18% 10%,rgba(248,78,95,.13),transparent 38%),radial-gradient(ellipse at 90% 90%,rgba(111,38,53,.16),transparent 40%),#080a0f}
main{position:relative;isolation:isolate;overflow:hidden;width:min(100%,680px);padding:clamp(28px,6vw,56px);border:1px solid rgba(248,113,113,.25);border-radius:22px;background:linear-gradient(145deg,rgba(25,27,36,.98),rgba(15,17,24,.98));box-shadow:0 28px 80px rgba(0,0,0,.48),0 0 42px rgba(248,78,95,.08);text-align:center}
main:before{position:absolute;z-index:-1;top:0;left:12%;right:12%;height:2px;content:"";background:linear-gradient(90deg,transparent,#fb7185,transparent)}
p{margin:0;font-size:clamp(1.22rem,4vw,1.8rem);font-weight:800;line-height:1.5;letter-spacing:.015em;text-wrap:balance;color:#fff}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
</style></head><body><main role="alert"><p>bypass link detected pls start all over do not bypass.</p></main></body></html>"""

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
# Set SESSION_COOKIE_SECURE=1 when the panel is HTTPS-only. Keep it 0 for
# direct HTTP/IP access, otherwise the browser will not send the admin session.
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def parse_expiry(value):
    """Parse stored expiry values, including malformed split fractions."""
    if not value:
        return None
    text = str(value).strip()
    # Repairs values such as 2026-09-18T13:55:02.0660 94+00:00.
    text = re.sub(r"(?<=\d)\s+(?=\d|[+-]\d{2}:?\d{2}$)", "", text)
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def expiry_payload(value):
    parsed = parse_expiry(value)
    if parsed is None:
        return None, None
    normalized = parsed.isoformat(timespec="seconds")
    return normalized, int(parsed.timestamp())


def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY, created_at TEXT NOT NULL, verified_at TEXT,
      callback_nonce TEXT NOT NULL UNIQUE, callback_used INTEGER NOT NULL DEFAULT 0,
      issued_key_id INTEGER, link_issued_at TEXT,
      blocked_early INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      max_devices INTEGER NOT NULL DEFAULT 1, used_devices INTEGER NOT NULL DEFAULT 0,
      custom INTEGER NOT NULL DEFAULT 0, note TEXT
    );
    CREATE TABLE IF NOT EXISTS device_uses (
      key_id INTEGER NOT NULL, device_id TEXT NOT NULL, first_seen TEXT NOT NULL,
      PRIMARY KEY(key_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS api_challenges (
      nonce TEXT PRIMARY KEY, device_pubkey TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_tokens (
      refresh_token TEXT PRIMARY KEY, access_token TEXT NOT NULL, lease TEXT NOT NULL,
      key_id INTEGER NOT NULL, device_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_keys_status_expiry ON keys(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_keys_value_upper ON keys(value COLLATE NOCASE);
    """)
    # Migrate databases created before the callback-delay fields were added.
    session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)")}
    if "link_issued_at" not in session_columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN link_issued_at TEXT")
    if "blocked_early" not in session_columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN blocked_early INTEGER NOT NULL DEFAULT 0")
    conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('maintenance','0')")
    conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('apk_maintenance','0')")
    conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('apk_notice_version','0')")
    conn.commit()
    conn.close()


def setting(name):
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (name,)).fetchone()
    conn.close()
    return row["value"] if row else "0"


def maintenance_enabled():
    return setting("maintenance") == "1"


def apk_maintenance_enabled():
    return setting("apk_maintenance") == "1"


def require_admin(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def make_key(prefix="XIT-EXE", groups=3):
    """Generate a human-readable key; uniqueness is enforced by the DB too."""
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(groups)
    )


def _insert_unique_key(conn, max_devices=1, hours=None, custom_value=None, note="", unlimited_devices=False):
    try:
        parsed_hours = float(hours if hours is not None else KEY_TTL_HOURS)
        parsed_devices = 0 if unlimited_devices else int(max_devices)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Hours must be a valid number and devices must be a whole number.") from exc
    if not math.isfinite(parsed_hours) or parsed_hours < 1 / 3600 or parsed_hours > MAX_KEY_TTL_HOURS:
        raise ValueError(f"Hours must be between 0.001 and {MAX_KEY_TTL_HOURS:,}.")
    if parsed_devices < 0 or parsed_devices > 1000000:
        raise ValueError("Device limit must be between 1 and 1000000, or unlimited.")
    hours = parsed_hours
    devices = parsed_devices
    custom_supplied = custom_value is not None and str(custom_value).strip() != ""
    custom = str(custom_value).strip().upper() if custom_supplied else None
    note = str(note or "").strip()
    if custom_supplied and not custom:
        raise ValueError("Enter a custom key or leave the field blank to generate one.")
    if custom and len(custom) > 120:
        raise ValueError("Custom keys must be 120 characters or fewer.")
    if custom and conn.execute(
        "SELECT 1 FROM keys WHERE UPPER(TRIM(value))=UPPER(TRIM(?)) LIMIT 1", (custom,)
    ).fetchone():
        raise ValueError("That custom key already exists (key matching is case-insensitive).")
    for _ in range(20):
        value = custom or make_key()
        created = now()
        try:
            expires = created + timedelta(hours=hours)
        except OverflowError as exc:
            raise ValueError(f"The expiry is too far in the future; maximum is {MAX_KEY_TTL_HOURS:,} hours.") from exc
        try:
            cur = conn.execute(
                "INSERT INTO keys(value,created_at,expires_at,max_devices,note,custom) VALUES(?,?,?,?,?,?)",
                (value, iso(created), iso(expires), devices, note, 1 if custom else 0)
            )
            return cur.lastrowid, value, expires
        except sqlite3.IntegrityError as exc:
            if custom:
                raise ValueError("That custom key already exists.") from exc
    raise RuntimeError("Could not generate a unique key. Please try again.")


def issue_key(max_devices=1, hours=None, custom_value=None, note="", unlimited_devices=False):
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        result = _insert_unique_key(conn, max_devices, hours, custom_value, note, unlimited_devices)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def device_limit_reached(row, existing):
    """Return true only for finite limits; max_devices=0 means unlimited."""
    return not existing and row["max_devices"] > 0 and row["used_devices"] >= row["max_devices"]


def remaining_devices(row, used_devices):
    """Use None for unlimited so API clients can distinguish it from zero."""
    return None if row["max_devices"] == 0 else max(0, row["max_devices"] - used_devices)


def expire_old_keys():
    conn = db()
    active_keys = conn.execute("SELECT id, expires_at FROM keys WHERE status='active'").fetchall()
    current_time = now()
    for key_row in active_keys:
        try:
            exp_dt = parse_expiry(key_row["expires_at"])
            if exp_dt is not None and exp_dt <= current_time:
                conn.execute("UPDATE keys SET status='expired' WHERE id=?", (key_row["id"],))
        except Exception:
            pass
    conn.commit()
    conn.close()


def vplink_for_session(session_id, nonce):
    callback_url = f"{PUBLIC_BASE_URL}/vplink/callback?{urlencode({'session': session_id, 'nonce': nonce})}"
    if not VPLINK_API_URL:
        raise RuntimeError("VPLINK_API_URL is not configured")
    params = {"api": VPLINK_TOKEN, "url": callback_url, "format": "json"}
    response = requests.get(VPLINK_API_URL, params=params, headers={"Accept": "application/json"}, timeout=15)
    response.raise_for_status()
    data = response.json()
    if data.get("status") not in (None, "success"):
        raise RuntimeError(data.get("message") or "VPlink rejected request")
    return data.get("shortenedUrl") or data.get("short_url") or data.get("url") or data.get("link") or abort(502, "VPlink missing link")


@app.before_request
def common():
    expire_old_keys()
    if request.path.startswith("/static") or request.path.startswith("/admin") or request.path.startswith("/vplink") or request.path.startswith("/api") or request.path in {"/s", "/s.php", "/l.php", "/getkey"}:
        return
    native_api = request.path == "/" and request.args.get("api") in {"challenge", "activate"}
    if maintenance_enabled() and request.endpoint not in {"home", "health"} and not native_api:
        body = render_template_string(MAINTENANCE_PAGE, telegram=TELEGRAM_URL, whatsapp=WHATSAPP_URL)
        return render_template_string(PAGE, title="Maintenance", body=body), 503


@app.get("/")
def home():
    body = render_template_string(HOME_PAGE, telegram=TELEGRAM_URL, whatsapp=WHATSAPP_URL)
    return render_template_string(PAGE, title=APP_NAME, body=body)


@app.get("/getkey")
def apk_original_getkey():
    """Compatibility endpoint for FakePingV3 1.0's original login flow.

    The APK sends GET /getkey?key=<key>&hwid=<android_id>&app=fakelag
    and expects an outer JSON object containing a JSON-string payload.
    """
    value = (request.args.get("key") or "").strip()
    device_id = (request.args.get("hwid") or "").strip()
    if not value or not device_id:
        payload = {"ok": 0, "exp": 0, "message": "key and hwid are required"}
        return jsonify(p=json.dumps(payload, separators=(",", ":")), s=""), 400

    row, error = _native_key(value, device_id)
    if error:
        payload = {"ok": 0, "exp": 0, "message": "invalid or expired key"}
        return jsonify(p=json.dumps(payload, separators=(",", ":")), s=""), error[1]

    _, expires_unix = expiry_payload(row["expires_at"])
    payload = {"ok": 1, "exp": expires_unix}
    return jsonify(p=json.dumps(payload, separators=(",", ":")), s="")



@app.route("/api_check.php", methods=["GET", "POST"])
def apk_api_check_compat():
    """Compatibility endpoint for the APK's second legacy validation request.

    The APK may send key/user_key/user/pass plus hwid/uid/device_id/serial.
    It expects HTTP JSON with an outer p/s object and a JSON payload in p.
    Always return HTTP 200 so the legacy client can parse the payload.
    """
    data = request.get_json(silent=True) or request.form or request.args or {}
    value = str(data.get("key") or data.get("license_key") or data.get("user_key") or data.get("user") or data.get("pass") or "").strip()
    device_id = str(data.get("hwid") or data.get("uid") or data.get("device_id") or data.get("serial") or data.get("android_id") or "").strip()
    if not device_id:
        device_id = "legacy-" + (value[:80] if value else "unknown")
    row, error = _native_key(value, device_id)
    if error:
        payload = {"ok": 0, "valid": 0, "authorized": 0, "exp": 0, "message": "invalid or expired key"}
        return jsonify(p=json.dumps(payload, separators=(",", ":")), s="")
    _, expires_unix = expiry_payload(row["expires_at"])
    payload = {"ok": 1, "valid": 1, "authorized": 1, "exp": expires_unix, "key": row["value"]}
    return jsonify(p=json.dumps(payload, separators=(",", ":")), s="")

@app.get("/get-key")
def get_key():
    sid = secrets.token_urlsafe(18)
    nonce = secrets.token_urlsafe(24)
    conn = db()
    conn.execute("INSERT INTO sessions(id,created_at,callback_nonce) VALUES(?,?,?)", (sid, iso(now()), nonce))
    conn.commit()
    conn.close()
    try:
        link = vplink_for_session(sid, nonce)
    except Exception as exc:
        app.logger.exception("VPlink create failed")
        return render_template_string(PAGE, title="VPlink error", body=f"<section class='card'><h1>Verification unavailable</h1><p>{str(exc)}</p><a class='button' href='/'>Try again</a></section>"), 502
    # Start the wait window only after the short link has been created.
    conn = db()
    conn.execute("UPDATE sessions SET link_issued_at=? WHERE id=?", (iso(now()), sid))
    conn.commit()
    conn.close()
    body = render_template_string(VERIFY_PAGE, verify_link=link)
    return render_template_string(PAGE, title="Verify", body=body)


def callback(sid, nonce):
    conn = db()
    try:
        # Serialize callbacks for this session so retries/races cannot issue
        # multiple keys or skip the minimum wait.
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row:
            conn.rollback()
            abort(404)
        if nonce and not secrets.compare_digest(nonce, row["callback_nonce"]):
            conn.rollback()
            abort(403)
        if row["blocked_early"]:
            conn.commit()
            return Response(BYPASS_DETECTED_PAGE, status=403, content_type="text/html; charset=utf-8")
        if row["callback_used"] or row["issued_key_id"]:
            keyrow = conn.execute("SELECT * FROM keys WHERE id=?", (row["issued_key_id"],)).fetchone()
            conn.commit()
            if not keyrow:
                abort(410)
        else:
            issued_at = parse_expiry(row["link_issued_at"]) or parse_expiry(row["created_at"])
            elapsed = (now() - issued_at).total_seconds() if issued_at else -1
            if elapsed < KEY_CALLBACK_MIN_WAIT_SECONDS:
                # Permanently invalidate this session so an early callback
                # requires the visitor to start a fresh verification flow.
                conn.execute(
                    "UPDATE sessions SET blocked_early=1 WHERE id=? AND callback_used=0 AND issued_key_id IS NULL",
                    (sid,),
                )
                conn.commit()
                return Response(BYPASS_DETECTED_PAGE, status=403, content_type="text/html; charset=utf-8")
            key_id, _, _ = _insert_unique_key(conn, 1, KEY_TTL_HOURS, None, "")
            cur = conn.execute(
                "UPDATE sessions SET callback_used=1,verified_at=?,issued_key_id=? "
                "WHERE id=? AND callback_used=0 AND issued_key_id IS NULL",
                (iso(now()), key_id, sid),
            )
            if cur.rowcount != 1:
                conn.rollback()
                abort(409)
            conn.commit()
            keyrow = conn.execute("SELECT * FROM keys WHERE id=?", (key_id,)).fetchone()
    finally:
        conn.close()
    body = render_template_string(KEY_PAGE, keyrow=keyrow)
    return render_template_string(PAGE, title="Your key", body=body)

@app.get("/vplink/callback")
def vplink_callback():
    return callback(request.args.get("session", ""), request.args.get("nonce"))


@app.get("/health")
def health():
    return jsonify(ok=True, service=APP_NAME, maintenance=maintenance_enabled())


@app.get("/api/mobile-notice")
def mobile_notice():
    """Public notice payload polled by the APK while its main screen is open."""
    response = jsonify(
        enabled=apk_maintenance_enabled(),
        notice_id=setting("apk_notice_version"),
        title="This APK is under maintenance",
        message="Join our Telegram and WhatsApp channels for more updates.",
        update_url=APK_UPDATE_URL,
        whatsapp=WHATSAPP_URL,
        telegram=TELEGRAM_URL,
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


def _native_json():
    return request.get_json(silent=True) or request.form or request.args or {}


def _native_tokens(key_id, device_id):
    access = "access_" + secrets.token_urlsafe(32)
    refresh = "refresh_" + secrets.token_urlsafe(40)
    # The APK only needs the lease as an opaque server-issued value during the
    # normal refresh path; it is retained for compatibility with its protocol.
    lease = "lease_" + secrets.token_urlsafe(32)
    conn = db()
    conn.execute(
        "INSERT INTO auth_tokens(refresh_token,access_token,lease,key_id,device_id,created_at) VALUES(?,?,?,?,?,?)",
        (refresh, access, lease, key_id, device_id, iso(now())),
    )
    conn.commit()
    conn.close()
    return access, refresh, lease


def _native_key(value, device_id):
    value = (value or "").strip().upper()
    device_id = (device_id or "").strip()
    if not value or not device_id:
        return None, (jsonify(detail="license_key and device_pubkey are required"), 400)
    conn = db()
    row = conn.execute("SELECT * FROM keys WHERE UPPER(TRIM(value))=?", (value,)).fetchone()
    if not row:
        conn.close()
        return None, (jsonify(detail="That license key is invalid or revoked."), 403)
    exp = parse_expiry(row["expires_at"]) or (now() - timedelta(seconds=1))
    if row["status"] != "active" or exp <= now():
        conn.close()
        return None, (jsonify(detail="That license key is invalid or revoked."), 403)
    existing = conn.execute("SELECT 1 FROM device_uses WHERE key_id=? AND device_id=?", (row["id"], device_id)).fetchone()
    if device_limit_reached(row, existing):
        conn.close()
        return None, (jsonify(detail="This license is already active on the maximum number of devices."), 409)
    if not existing:
        conn.execute("INSERT INTO device_uses VALUES(?,?,?)", (row["id"], device_id, iso(now())))
        conn.execute("UPDATE keys SET used_devices=used_devices+1 WHERE id=?", (row["id"],))
        conn.commit()
    conn.close()
    return row, None


@app.post("/")
def native_root_api():
    """Compatibility API for the APK's signed challenge/activation protocol."""
    api = request.args.get("api", "")
    data = _native_json()
    if api == "challenge":
        # The APK decodes this challenge nonce as hexadecimal before signing it.
        # token_urlsafe() can contain '-'/'_' and is not accepted by the client.
        nonce = secrets.token_hex(32)
        device_pubkey = str(data.get("device_pubkey") or "")
        if not device_pubkey:
            return jsonify(detail="device_pubkey is required"), 400
        conn = db()
        conn.execute("INSERT INTO api_challenges VALUES(?,?,?)", (nonce, device_pubkey, iso(now())))
        conn.commit()
        conn.close()
        return jsonify(nonce=nonce)
    if api == "activate":
        if maintenance_enabled():
            return jsonify(detail="XITEXE is temporarily under maintenance. Please join our WhatsApp channel for more updates: https://whatsapp.com/channel/0029Vb7LRGS3AzNbOj5ZIV1r"), 418
        value = data.get("license_key")
        fp = data.get("fingerprint_inputs") or {}
        device_id = data.get("device_pubkey") or fp.get("device_pubkey")
        nonce = data.get("challenge_nonce")
        if not nonce:
            return jsonify(detail="challenge_nonce is required"), 400
        conn = db()
        challenge = conn.execute("SELECT * FROM api_challenges WHERE nonce=?", (nonce,)).fetchone()
        if challenge:
            conn.execute("DELETE FROM api_challenges WHERE nonce=?", (nonce,))
            conn.commit()
        conn.close()
        if not challenge or challenge["device_pubkey"] != str(device_id or ""):
            return jsonify(detail="Invalid or expired challenge."), 403
        row, error = _native_key(value, str(device_id))
        if error:
            return error
        access, refresh, lease = _native_tokens(row["id"], str(device_id))
        return jsonify(access_token=access, refresh_token=refresh, lease=lease, tier="standard", config_version=1)
    return jsonify(detail="Unknown API"), 404


@app.post("/v1/auth/key-login")
def apk_key_login():
    """Compatibility adapter for the recovered APK's original login URL.

    Accepts the recovered client's JSON/form field variants and maps them to
    the server's existing key, expiry, and device-limit checks.
    """
    data = _native_json()
    value = (data.get("key") or data.get("license_key") or data.get("user_key") or data.get("user") or "").strip()
    device_id = str(data.get("hwid") or data.get("device_pubkey") or data.get("device_id") or data.get("serial") or "").strip()
    if not value or not device_id:
        return jsonify(ok=False, valid=False, authorized=False, detail="key and hwid are required"), 400
    row, error = _native_key(value, device_id)
    if error:
        return error
    access, refresh, lease = _native_tokens(row["id"], device_id)
    normalized_expiry, expires_unix = expiry_payload(row["expires_at"])
    return jsonify(
        ok=True, valid=True, authorized=True,
        access_token=access, refresh_token=refresh, lease=lease,
        session_id=access, key=row["value"], hwid=device_id,
        expires_at=normalized_expiry, expires_unix=expires_unix,
        exp=expires_unix, tier="standard", config_version=1,
    )


@app.post("/v1/auth/heartbeat")
def apk_heartbeat():
    """Compatibility adapter for the recovered APK's periodic lease check."""
    data = _native_json()
    access = str(data.get("access_token") or data.get("session_id") or data.get("token") or "")
    refresh = str(data.get("refresh_token") or "")
    lease = str(data.get("lease") or "")
    device_id = str(data.get("hwid") or data.get("device_pubkey") or data.get("device_id") or data.get("serial") or "")
    conn = db()
    token = None
    if refresh:
        token = conn.execute("SELECT * FROM auth_tokens WHERE refresh_token=?", (refresh,)).fetchone()
    if not token and access:
        token = conn.execute("SELECT * FROM auth_tokens WHERE access_token=?", (access,)).fetchone()
    if not token or (device_id and token["device_id"] != device_id) or (lease and token["lease"] != lease):
        conn.close()
        return jsonify(ok=False, valid=False, authorized=False, detail="Session expired. Sign in again."), 401
    key = conn.execute("SELECT * FROM keys WHERE id=?", (token["key_id"],)).fetchone()
    conn.close()
    if not key or key["status"] != "active" or (parse_expiry(key["expires_at"]) or now()) <= now():
        return jsonify(ok=False, valid=False, authorized=False, detail="License expired or revoked."), 401
    normalized_expiry, expires_unix = expiry_payload(key["expires_at"])
    return jsonify(ok=True, valid=True, authorized=True, alive=True,
                   access_token=token["access_token"], refresh_token=token["refresh_token"],
                   lease=token["lease"], expires_at=normalized_expiry, expires_unix=expires_unix,
                   exp=expires_unix)


@app.post("/a")
def apk_key_login_short():
    """Short target used by the compact APK URL patch."""
    return apk_key_login()


@app.post("/h")
def apk_heartbeat_short():
    """Short target used by the compact APK URL patch."""
    return apk_heartbeat()


@app.post("/auth/refresh")
def native_refresh():
    data = _native_json()
    refresh = str(data.get("refresh_token") or "")
    fp = data.get("fingerprint_inputs") or {}
    device_id = str(data.get("device_pubkey") or fp.get("device_pubkey") or "")
    conn = db()
    token = conn.execute("SELECT * FROM auth_tokens WHERE refresh_token=?", (refresh,)).fetchone()
    if not token or token["device_id"] != device_id:
        conn.close()
        return jsonify(detail="Session expired. Sign in again."), 401
    key = conn.execute("SELECT * FROM keys WHERE id=?", (token["key_id"],)).fetchone()
    conn.close()
    if not key or key["status"] != "active" or (parse_expiry(key["expires_at"]) or now()) <= now():
        return jsonify(detail="Session expired. Sign in again."), 401
    return jsonify(access_token=token["access_token"], refresh_token=token["refresh_token"], lease=token["lease"], tier="standard", config_version=1)


@app.route("/s", methods=["GET", "POST"])
@app.route("/s.php", methods=["GET", "POST"])
@app.route("/l.php", methods=["GET", "POST"])
def legacy_login():
    """Compatibility endpoint for the recovered APK's native login client.

    The original POST contract remains unchanged. The recovered APK uses the
    older GET contract (user/pass/uid), so accept that shape here as well.
    """
    def legacy_error(message, status_code):
        # The recovered APK treats non-200 responses as a network failure.
        # Keep the original POST status codes for other clients, but return
        # parser-visible JSON with HTTP 200 for the APK GET contract.
        code = status_code if request.method == "POST" else 200
        return jsonify(status=False, authorized=False, valid=False, message=message), code

    if request.method == "GET":
        data = request.args
        game = (data.get("game") or "com.dts.freefireth").strip()
        # The APK has used both user and pass positions across builds. Try
        # user first, then pass, without changing the established POST API.
        user_value = (data.get("user") or "").strip().upper()
        pass_value = (data.get("pass") or "").strip().upper()
        value = user_value or pass_value
        device = (data.get("uid") or "").strip()
    else:
        data = request.form
        game = (data.get("game") or "").strip()
        value = (data.get("user_key") or "").strip().upper()
        device = (data.get("serial") or "").strip()

    if not game or not value or not device:
        return legacy_error("Missing game, user_key, or serial", 400)

    conn = db()
    row = conn.execute(
        "SELECT * FROM keys WHERE UPPER(TRIM(value))=?", (value,)
    ).fetchone()
    if not row and request.method == "GET" and pass_value and pass_value != value:
        value = pass_value
        row = conn.execute(
            "SELECT * FROM keys WHERE UPPER(TRIM(value))=?", (value,)
        ).fetchone()
    if not row:
        conn.close()
        return legacy_error("Invalid key", 404)

    normalized_expiry, expires_unix = expiry_payload(row["expires_at"])
    expires = parse_expiry(row["expires_at"]) or (now() - timedelta(seconds=1))

    if row["status"] != "active" or expires <= now():
        conn.close()
        return legacy_error("Expired or revoked key", 403)

    existing = conn.execute(
        "SELECT 1 FROM device_uses WHERE key_id=? AND device_id=?",
        (row["id"], device)
    ).fetchone()
    if device_limit_reached(row, existing):
        conn.close()
        return legacy_error("Device limit reached", 403)

    if not existing:
        conn.execute(
            "INSERT INTO device_uses VALUES (?, ?, ?)",
            (row["id"], device, iso(now()))
        )
        conn.execute(
            "UPDATE keys SET used_devices=used_devices+1 WHERE id=?",
            (row["id"],)
        )
        conn.commit()

    used = row["used_devices"] + (0 if existing else 1)
    remaining = remaining_devices(row, used)
    conn.close()
    return jsonify(status=True, authorized=True, valid=True, module=True,
                    moco=0, targets=0, key=row["value"],
                    expires_at=normalized_expiry, expires_unix=expires_unix, remaining_devices=remaining,
                    message="Online authentication accepted; native lease active")


@app.errorhandler(404)
def apk_legacy_fallback(error):
    """Handle an APK-shaped GET even if a legacy path has a slash variant."""
    if request.method == "GET" and (
        request.args.get("user") or request.args.get("pass")
    ) and request.args.get("uid"):
        return legacy_login()
    return error


@app.post("/api/v1/verify-key")
def verify_key():
    data = request.get_json(silent=True) or request.form or request.args or {}
    value = (data.get("key") or "").strip().upper()
    device = (data.get("device_id") or "").strip()

    if not value or not device:
        return jsonify(valid=False, error="key and device_id are required"), 400

    conn = db()
    row = conn.execute("SELECT * FROM keys WHERE UPPER(TRIM(value))=?", (value,)).fetchone()

    if not row:
        conn.close()
        return jsonify(valid=False, error="invalid key"), 404

    exp_dt = parse_expiry(row["expires_at"]) or (now() - timedelta(seconds=1))

    if row["status"] != "active" or exp_dt <= now():
        conn.close()
        return jsonify(valid=False, error="expired or revoked"), 403

    existing = conn.execute("SELECT 1 FROM device_uses WHERE key_id=? AND device_id=?", (row["id"], device)).fetchone()

    if device_limit_reached(row, existing):
        conn.close()
        return jsonify(valid=False, error="device limit reached"), 403

    if not existing:
        conn.execute("INSERT INTO device_uses VALUES(?,?,?)", (row["id"], device, iso(now())))
        conn.execute("UPDATE keys SET used_devices=used_devices+1 WHERE id=?", (row["id"],))
        conn.commit()

    used_count = row["used_devices"] + (0 if existing else 1)
    remaining = remaining_devices(row, used_count)
    conn.close()

    normalized_expiry, expires_unix = expiry_payload(row["expires_at"])
    return jsonify(valid=True, key=row["value"], expires_at=normalized_expiry, expires_unix=expires_unix, remaining_devices=remaining)


@app.post("/api.php")
def nikumods_auth_api():
    """Compatibility adapter for NIKUMODS 1.0.3's JSON login/check flow."""
    data = request.get_json(silent=True) or {}
    action = str(data.get("action") or "").strip().lower()
    value = str(data.get("key") or "").strip()

    if action == "login":
        device_id = str(data.get("hwid") or "").strip()
        if not value or not device_id:
            return jsonify(success=False, error="key and hwid are required"), 200
        row, error = _native_key(value, device_id)
        if error:
            message = error[0].get_json(silent=True) or {}
            return jsonify(success=False, error=message.get("detail", "invalid key")), 200
        return jsonify(success=True), 200

    if action == "check":
        if not value:
            return jsonify(valid=False), 200
        conn = db()
        row = conn.execute(
            "SELECT status, expires_at FROM keys WHERE UPPER(TRIM(value))=?",
            (value.upper(),),
        ).fetchone()
        conn.close()
        expiry = parse_expiry(row["expires_at"]) if row else None
        valid = bool(row and row["status"] == "active" and expiry and expiry > now())
        return jsonify(valid=valid), 200

    return jsonify(error="unsupported action"), 200


@app.post("/api/check.php")
def psapp_check():
    """Compatibility endpoint for PS App's keyauth client."""
    data = request.get_json(silent=True) or request.form or request.args or {}
    value = (data.get("key") or "").strip().upper()
    device = (data.get("hwid") or "").strip()
    if not value or not device:
        return jsonify(status="failed", message="key and hwid are required"), 400

    conn = db()
    row = conn.execute("SELECT * FROM keys WHERE UPPER(TRIM(value))=?", (value,)).fetchone()
    if not row:
        conn.close()
        return jsonify(status="failed", message="Invalid key"), 404

    normalized_expiry, expires_unix = expiry_payload(row["expires_at"])
    expires = parse_expiry(row["expires_at"]) or (now() - timedelta(seconds=1))
    if row["status"] != "active" or expires <= now():
        conn.close()
        return jsonify(status="failed", message="Expired or revoked key"), 403

    existing = conn.execute(
        "SELECT 1 FROM device_uses WHERE key_id=? AND device_id=?",
        (row["id"], device),
    ).fetchone()
    if device_limit_reached(row, existing):
        conn.close()
        return jsonify(status="failed", message="Device limit reached"), 403
    if not existing:
        conn.execute("INSERT INTO device_uses VALUES (?, ?, ?)", (row["id"], device, iso(now())))
        conn.execute("UPDATE keys SET used_devices=used_devices+1 WHERE id=?", (row["id"],))
        conn.commit()
    used = row["used_devices"] + (0 if existing else 1)
    conn.close()
    return jsonify(
        status="success",
        message="Login aprovado!",
        expira_em=normalized_expiry,
        validade=normalized_expiry,
        expires_unix=expires_unix,
        devices_used=used,
        max_devices=row["max_devices"],
        vendedor="XITEXE",
        versao_nome="PS App",
        versao_numero="1.0",
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect(request.args.get("next") or url_for("admin"))
        flash("Incorrect password")
    body = render_template_string(ADMIN_LOGIN_PAGE)
    return render_template_string(PAGE, title="Admin login", body=body)


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


@app.get("/admin")
@require_admin
def admin():
    expire_old_keys()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1
    allowed_page_sizes = {25, 50, 100, 200}
    try:
        requested_size = int(request.args.get("per_page", "50"))
    except (TypeError, ValueError):
        requested_size = 50
    per_page = requested_size if requested_size in allowed_page_sizes else 50
    query = request.args.get("q", "").strip()[:120]
    status = request.args.get("status", "all").strip().lower()
    if status not in {"all", "active", "expired", "revoked"}:
        status = "all"

    conn = db()
    where, params = [], []
    if query:
        where.append("(value LIKE ? OR note LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if status != "all":
        where.append("status=?")
        params.append(status)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute("SELECT COUNT(*) FROM keys" + clause, params).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    rows = conn.execute(
        "SELECT * FROM keys" + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()
    stats = conn.execute("""
        SELECT COUNT(*) AS total,
               COALESCE(SUM(status='active'),0) AS active,
               COALESCE(SUM(status='expired'),0) AS expired,
               COALESCE(SUM(status='revoked'),0) AS revoked,
               COALESCE(SUM(custom=1),0) AS custom
        FROM keys
    """).fetchone()
    conn.close()
    body = render_template_string(
        ADMIN_PAGE, rows=rows, maintenance=maintenance_enabled(),
        apk_maintenance=apk_maintenance_enabled(),
        public_url=PUBLIC_BASE_URL, page=page, per_page=per_page,
        total=total, query=query, status=status, pages=pages,
        page_sizes=sorted(allowed_page_sizes), stats=stats,
        max_key_ttl_hours=MAX_KEY_TTL_HOURS
    )
    return render_template_string(PAGE, title="Admin console", body=body)

@app.post("/admin/action")
@require_admin
def admin_action():
    action = request.form.get("action", "")
    back_query = request.form.get("q", "")[:120]
    back_status = request.form.get("status", "all")
    back_page = request.form.get("page", "1")

    if action == "generate":
        try:
            _, value, expires = issue_key(
                request.form.get("max_devices", 1),
                request.form.get("hours", KEY_TTL_HOURS),
                request.form.get("custom") or None,
                request.form.get("note", "")[:200],
                request.form.get("unlimited_devices") == "1",
            )
            flash(f"Key created: {value} · expires {expires.strftime('%Y-%m-%d %H:%M UTC')}")
        except (ValueError, TypeError, OverflowError) as exc:
            flash(f"Key not created: {exc}")
        except sqlite3.Error:
            app.logger.exception("Database error while creating an admin key")
            flash("The database could not save this key. No key was created; check available storage and the panel logs.")
        except Exception:
            app.logger.exception("Unexpected error while creating an admin key")
            flash("The key could not be created due to an unexpected server error. No key was created; check the panel logs.")
        return redirect(url_for("admin"))

    conn = db()
    try:
        if action == "maintenance":
            enabled = "1" if request.form.get("value") == "1" else "0"
            conn.execute("UPDATE settings SET value=? WHERE key='maintenance'", (enabled,))
            flash("Maintenance mode enabled." if enabled == "1" else "Maintenance mode disabled.")
        elif action == "apk_maintenance":
            enabled = "1" if request.form.get("value") == "1" else "0"
            conn.execute("UPDATE settings SET value=? WHERE key='apk_maintenance'", (enabled,))
            conn.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='apk_notice_version'")
            flash("APK maintenance dialog enabled." if enabled == "1" else "APK maintenance dialog disabled.")
        elif action == "delete_all":
            removed = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
            conn.execute("DELETE FROM auth_tokens")
            conn.execute("DELETE FROM device_uses")
            conn.execute("DELETE FROM keys")
            flash(f"Deleted {removed} key(s) and their device/session records.")
        elif action == "revoke_all":
            changed = conn.execute("UPDATE keys SET status='revoked' WHERE status='active'").rowcount
            flash(f"Revoked {changed} active key(s).")
        elif action in {"revoke", "delete", "renew", "reset_devices"}:
            key_id = int(request.form["id"])
            row = conn.execute("SELECT value FROM keys WHERE id=?", (key_id,)).fetchone()
            if not row:
                flash("That key no longer exists.")
            elif action == "revoke":
                conn.execute("UPDATE keys SET status='revoked' WHERE id=?", (key_id,))
                flash(f"Revoked {row['value']}.")
            elif action == "delete":
                conn.execute("DELETE FROM auth_tokens WHERE key_id=?", (key_id,))
                conn.execute("DELETE FROM device_uses WHERE key_id=?", (key_id,))
                conn.execute("DELETE FROM keys WHERE id=?", (key_id,))
                flash(f"Deleted {row['value']}.")
            elif action == "renew":
                hours = float(request.form.get("hours", KEY_TTL_HOURS))
                if not math.isfinite(hours) or hours < 1 / 3600 or hours > MAX_KEY_TTL_HOURS:
                    raise ValueError(f"Renewal hours must be between 0.001 and {MAX_KEY_TTL_HOURS:,}.")
                conn.execute(
                    "UPDATE keys SET status='active',expires_at=? WHERE id=?",
                    (iso(now() + timedelta(hours=hours)), key_id)
                )
                flash(f"Renewed {row['value']} for {hours:g} hour(s).")
            else:
                conn.execute("DELETE FROM auth_tokens WHERE key_id=?", (key_id,))
                conn.execute("DELETE FROM device_uses WHERE key_id=?", (key_id,))
                conn.execute("UPDATE keys SET used_devices=0 WHERE id=?", (key_id,))
                flash(f"Reset device activations and sessions for {row['value']}.")
        else:
            flash("Unknown admin action.")
        conn.commit()
    except (ValueError, TypeError, OverflowError, sqlite3.Error) as exc:
        conn.rollback()
        app.logger.exception("Admin action failed")
        flash(str(exc))
    finally:
        conn.close()
    return redirect(url_for("admin", q=back_query, status=back_status, page=back_page))

HOME_PAGE = '<section class="hero-wrap">\n  <div class="hero-copy">\n    <div class="eyebrow"><span class="live-dot"></span> XITEXE ACCESS PORTAL</div>\n    <h1>Access, <span>unlocked.</span></h1>\n    <p class="hero-lede">Get your secure access key in a few quick steps. Keys are private, device-bound, and expire automatically.</p>\n    <div class="actions hero-actions">\n      <a class="button primary" href="/get-key">Get access key <span aria-hidden="true">↗</span></a>\n      <a class="button ghost" href="{{whatsapp}}" target="_blank" rel="noopener">WhatsApp channel</a>\n      <a class="button ghost" href="{{telegram}}" target="_blank" rel="noopener">Telegram channel</a>\n    </div>\n    <div class="trust-note"><span class="shield">✓</span> Secure verification <span class="divider">·</span> Automatic expiry <span class="divider">·</span> Device-bound</div>\n  </div>\n  <aside class="hero-panel">\n    <div class="panel-top"><span class="panel-mark">X</span><span class="pill">ACCESS SYSTEM <i></i></span></div>\n    <div class="panel-orbit"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="orbit-core">X</div></div>\n    <div class="panel-caption"><strong>Protected access</strong><span>Your key stays yours.</span></div>\n    <div class="panel-rule"><span></span></div>\n    <div class="panel-footer"><span>PRIVATE BY DESIGN</span><span>● ONLINE</span></div>\n  </aside>\n</section>\n<section class="feature-grid">\n  <article class="feature-card"><span class="feature-icon">01</span><div><h3>Quick verification</h3><p>Complete one short verification step to receive your key.</p></div></article>\n  <article class="feature-card"><span class="feature-icon">02</span><div><h3>Time-limited</h3><p>Keys expire automatically to keep access controlled.</p></div></article>\n  <article class="feature-card"><span class="feature-icon">03</span><div><h3>Device-bound</h3><p>Your key is checked against the device using it.</p></div></article>\n</section>\n<section class="portal-foot"><span>XITEXE</span><span>Use only your own valid key. Never share your verification link.</span></section>'
VERIFY_PAGE = '<section class="card center flow-card"><div class="step-mark">02 <span>/ 02</span></div><div class="eyebrow">SECURE VERIFICATION</div><h1>One last step.</h1><p>Continue to the verification page. Once complete, you’ll return here and your private key will be issued.</p><a class="button primary" href="{{verify_link}}">Continue verification <span>↗</span></a><p class="micro-note"><strong>Don&#39;t know how to get key? <a href="https://t.me/xitfile/169" target="_blank" rel="noopener noreferrer">Tap here</a>.</strong></p><p class="micro-note">Keep your verification link private.</p></section>'
KEY_PAGE = '<section class="card center flow-card"><div class="step-mark">✓ <span>COMPLETE</span></div><div class="eyebrow">VERIFICATION PASSED</div><h1>Your key is ready.</h1><p class="muted">Copy it now and keep it private. It expires at the time shown below.</p><div class="keybox" id="key">{{keyrow[\'value\']}}</div><button class="button primary" onclick="navigator.clipboard.writeText(document.getElementById(\'key\').innerText);this.innerText=\'Copied ✓\'">Copy access key</button><div class="timer" data-expiry="{{keyrow[\'expires_at\']}}"></div><p class="micro-note">This page is refresh-safe and will not issue another key.</p></section><script>const t=document.querySelector(\'.timer\'),e=new Date(t.dataset.expiry);function tick(){let s=Math.max(0,Math.floor((e-new Date())/1000)),h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;t.textContent=s?`Expires in ${h}h ${m}m ${x}s`:\'Expired\'}tick();setInterval(tick,1000)</script>'
MAINTENANCE_PAGE = '<section class="card center flow-card"><div class="eyebrow">TEMPORARILY UNAVAILABLE</div><h1>We’re tuning things up.</h1><p>The access portal is under maintenance. Follow the official channels for updates.</p><div class="actions center-actions"><a class="button ghost" href="{{telegram}}" target="_blank" rel="noopener">Telegram</a><a class="button primary" href="{{whatsapp}}" target="_blank" rel="noopener">WhatsApp</a></div></section>'
ADMIN_LOGIN_PAGE = '<section class="card center login-card"><div class="brand-lockup"><span class="brand-emblem">X</span><span>XITEXE <small>CONTROL</small></span></div><div class="eyebrow">RESTRICTED AREA</div><h1>Admin sign in</h1><p class="muted">Use your server-configured admin password to access key management.</p>{% with messages = get_flashed_messages() %}{% if messages %}<div class="notice">{% for message in messages %}<div>{{message}}</div>{% endfor %}</div>{% endif %}{% endwith %}<form class="login-form" method="post"><label for="admin-password">Admin password</label><input id="admin-password" type="password" name="password" placeholder="Enter your password" autocomplete="current-password" required autofocus><button class="button primary" type="submit">Sign in <span>↗</span></button></form></section>'
ADMIN_PAGE = '<header class="admin-topbar">\n  <a class="brand-lockup" href="/admin"><span class="brand-emblem">X</span><span>XITEXE <small>CONTROL</small></span></a>\n  <div class="topbar-right"><span class="server-pill"><i></i> PANEL ONLINE</span><a class="button ghost small" href="{{public_url}}" target="_blank" rel="noopener">Open portal ↗</a><a class="button ghost small" href="/admin/logout">Sign out</a></div>\n</header>\n<section class="admin-intro"><div><div class="eyebrow">CONTROL CENTER / LICENSES</div><h1>Key management</h1><p>Issue keys, control access, and review activations from one place.</p></div><div class="intro-chip"><span class="intro-chip-icon">⌁</span><span><b>{{total}}</b><small>matching keys</small></span></div></section>\n{% with messages = get_flashed_messages() %}{% if messages %}<div class="notice">{% for message in messages %}<div>{{message}}</div>{% endfor %}</div>{% endif %}{% endwith %}\n<section class="stats-grid">\n  <article class="metric-card"><span class="metric-label">TOTAL KEYS</span><strong>{{stats[\'total\'] or 0}}</strong><span class="metric-foot">All records</span></article>\n  <article class="metric-card metric-red"><span class="metric-label">ACTIVE</span><strong>{{stats[\'active\'] or 0}}</strong><span class="metric-foot">Currently valid</span></article>\n  <article class="metric-card"><span class="metric-label">EXPIRED</span><strong>{{stats[\'expired\'] or 0}}</strong><span class="metric-foot">Past expiry</span></article>\n  <article class="metric-card"><span class="metric-label">REVOKED</span><strong>{{stats[\'revoked\'] or 0}}</strong><span class="metric-foot">Manually disabled</span></article>\n  <article class="metric-card"><span class="metric-label">CUSTOM</span><strong>{{stats[\'custom\'] or 0}}</strong><span class="metric-foot">Named keys</span></article>\n</section>\n<div class="admin-workspace">\n  <section class="card create-card"><div class="section-heading"><div><div class="eyebrow">ISSUE ACCESS</div><h2>Create a key</h2><p>Generate a secure key or choose your own custom value.</p></div><span class="section-icon">＋</span></div>\n    <form class="create-form" method="post" action="/admin/action"><input type="hidden" name="action" value="generate">\n      <label>Validity <span class="input-with-suffix"><input name="hours" type="number" min="0.001" max="{{max_key_ttl_hours}}" step="0.001" value="5" required><em>hours</em></span></label>\n      <label>Device limit <input id="max-devices" name="max_devices" type="number" min="1" max="1000000" value="1" required></label>\n      <label class="check-label"><input id="unlimited-devices" name="unlimited_devices" value="1" type="checkbox" onchange="document.getElementById(&quot;max-devices&quot;).disabled=this.checked;document.getElementById(&quot;max-devices&quot;).required=!this.checked"> Unlimited devices</label>\n      <label class="span-two">Custom key <input name="custom" maxlength="120" placeholder="Leave blank to generate a secure key"></label>\n      <label class="span-two">Internal note <input name="note" maxlength="200" placeholder="Optional label, customer, or order reference"></label>\n      <button class="button primary span-two" type="submit">Create key <span>↗</span></button>\n    </form>\n  </section>\n  <section class="card ops-card"><div class="section-heading"><div><div class="eyebrow">SYSTEM CONTROLS</div><h2>Operations</h2><p>Manage portal availability and access in bulk.</p></div><span class="section-icon">⌘</span></div>\n    <div class="operation-row"><div><b>Maintenance mode</b><small>Pause public access while keeping admin controls available.</small></div><form method="post" action="/admin/action"><input type="hidden" name="action" value="maintenance"><input type="hidden" name="value" value="{{0 if maintenance else 1}}"><button class="button {{\'ghost\' if maintenance else \'primary\'}} small" type="submit">{{\'Turn off\' if maintenance else \'Turn on\'}}</button></form></div>\n    <div class="operation-row"><div><b>APK maintenance dialog</b><small>Show the in-app maintenance notice with Telegram and WhatsApp links.</small></div><form method="post" action="/admin/action"><input type="hidden" name="action" value="apk_maintenance"><input type="hidden" name="value" value="{{0 if apk_maintenance else 1}}"><button class="button {{\'ghost\' if apk_maintenance else \'primary\'}} small" type="submit">{{\'Turn off\' if apk_maintenance else \'Turn on\'}}</button></form></div>\n    <div class="operation-row"><div><b>Revoke all active keys</b><small>Disable valid keys without deleting their history.</small></div><form method="post" action="/admin/action" onsubmit="return confirm(\'Revoke all active keys? This cannot be undone in bulk.\')"><input type="hidden" name="action" value="revoke_all"><button class="button ghost small" type="submit">Revoke active</button></form></div>\n    <div class="operation-row danger-row"><div><b>Delete every key</b><small>Permanently remove keys, device activations, and sessions.</small></div><form method="post" action="/admin/action" onsubmit="return confirm(\'This permanently deletes every key and its records. Continue?\') && prompt(\'Type DELETE ALL to confirm\')===\'DELETE ALL\'"><input type="hidden" name="action" value="delete_all"><button class="button danger small" type="submit">Delete all</button></form></div>\n  </section>\n</div>\n<section class="card inventory-card"><div class="inventory-heading"><div><div class="eyebrow">LICENSE INVENTORY</div><h2>All keys</h2><p>Search, filter, renew, revoke, or remove individual keys.</p></div><span class="count-pill">{{total}} result{{\'\' if total == 1 else \'s\'}}</span></div>\n  <form class="filterbar" method="get" action="/admin"><label class="search-field"><span>⌕</span><input name="q" value="{{query}}" placeholder="Search key or internal note"></label><select name="status" aria-label="Filter by status"><option value="all" {{\'selected\' if status==\'all\' else \'\'}}>All statuses</option><option value="active" {{\'selected\' if status==\'active\' else \'\'}}>Active</option><option value="expired" {{\'selected\' if status==\'expired\' else \'\'}}>Expired</option><option value="revoked" {{\'selected\' if status==\'revoked\' else \'\'}}>Revoked</option></select><select name="per_page" aria-label="Rows per page">{% for size in page_sizes %}<option value="{{size}}" {{\'selected\' if per_page==size else \'\'}}>{{size}} / page</option>{% endfor %}</select><button class="button primary small" type="submit">Apply filters</button>{% if query or status != \'all\' %}<a class="button ghost small" href="/admin">Clear</a>{% endif %}</form>\n  <div class="table-shell"><table class="key-table"><thead><tr><th>KEY / NOTE</th><th>STATUS</th><th>EXPIRES (UTC)</th><th>DEVICES</th><th>RENEW</th><th>MANAGE</th></tr></thead><tbody>\n  {% for r in rows %}<tr><td><code>{{r[\'value\']}}</code><div class="row-note">{{r[\'note\'] or (\'Custom key\' if r[\'custom\'] else \'Generated key\')}}</div></td><td><span class="status-badge {{r[\'status\']}}"><i></i>{{r[\'status\']}}</span></td><td class="expiry-cell">{{r[\'expires_at\']|replace(\'T\',\' \')|replace(\'+00:00\',\' UTC\')}}</td><td><span class="device-count">{{r[\'used_devices\']}} <small>/ {{\'Unlimited\' if r[\'max_devices\'] == 0 else r[\'max_devices\']}}</small></span></td><td><form class="renew-form" method="post" action="/admin/action"><input type="hidden" name="action" value="renew"><input type="hidden" name="id" value="{{r[\'id\']}}"><input type="hidden" name="q" value="{{query}}"><input type="hidden" name="status" value="{{status}}"><input type="hidden" name="page" value="{{page}}"><input type="number" name="hours" min="0.001" max="{{max_key_ttl_hours}}" step="0.001" value="5" aria-label="Renewal hours"><button type="submit" class="mini-button">Renew</button></form></td><td><div class="manage-actions"><form method="post" action="/admin/action"><input type="hidden" name="action" value="reset_devices"><input type="hidden" name="id" value="{{r[\'id\']}}"><input type="hidden" name="q" value="{{query}}"><input type="hidden" name="status" value="{{status}}"><input type="hidden" name="page" value="{{page}}"><button class="mini-button" type="submit" title="Reset device activations">Reset</button></form><form method="post" action="/admin/action"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="{{r[\'id\']}}"><input type="hidden" name="q" value="{{query}}"><input type="hidden" name="status" value="{{status}}"><input type="hidden" name="page" value="{{page}}"><button class="mini-button" type="submit">Revoke</button></form><form method="post" action="/admin/action" onsubmit="return confirm(\'Permanently delete this key and its activation records?\')"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{r[\'id\']}}"><input type="hidden" name="q" value="{{query}}"><input type="hidden" name="status" value="{{status}}"><input type="hidden" name="page" value="{{page}}"><button class="mini-button mini-danger" type="submit">Delete</button></form></div></td></tr>\n  {% else %}<tr><td colspan="6" class="empty-state"><span>⌕</span><b>No matching keys</b><small>Try another search or clear your filters.</small></td></tr>{% endfor %}\n  </tbody></table></div>\n  <footer class="table-footer"><span>Showing {{(page-1)*per_page+1 if total else 0}}–{{[page*per_page,total]|min}} of {{total}}</span><nav class="pagination" aria-label="Key pages"><a class="button ghost small {{\'disabled\' if page<=1 else \'\'}}" href="{{url_for(\'admin\',q=query,status=status,per_page=per_page,page=page-1)}}" {{\'aria-disabled=true\' if page<=1 else \'\'}}>← Previous</a><span>Page <b>{{page}}</b> of {{pages}}</span><a class="button ghost small {{\'disabled\' if page>=pages else \'\'}}" href="{{url_for(\'admin\',q=query,status=status,per_page=per_page,page=page+1)}}" {{\'aria-disabled=true\' if page>=pages else \'\'}}>Next →</a></nav></footer>\n</section>\n<footer class="admin-foot"><span>XITEXE CONTROL CENTER</span><span>Portal: <a href="{{public_url}}" target="_blank" rel="noopener">{{public_url}}</a></span></footer>'

PAGE = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#100b10"><title>{{title}}</title>\n<style>\n@import url(\'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap\');\n:root{color-scheme:dark;--bg:#0c090d;--panel:#151015;--panel2:#1c151b;--line:#38252d;--text:#f7f3f4;--muted:#aa9da3;--red:#e33e55;--red2:#ff6678;--red-dark:#8f2538;--green:#50d4a2;--blue:#8ba5ff;--shadow:0 24px 70px #0006}\n*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;color:var(--text);font-family:\'DM Sans\',system-ui,sans-serif;background:radial-gradient(ellipse at 13% 0%,#3b121c 0,transparent 37%),radial-gradient(ellipse at 95% 12%,#261018 0,transparent 32%),linear-gradient(145deg,#100b10,#0b090c 65%)}a{color:inherit}main{width:min(100% - 44px,1480px);margin:0 auto;padding:30px 0 64px}h1,h2,h3,p{margin-top:0}h1,h2{font-family:\'Space Grotesk\',sans-serif;letter-spacing:-.035em}h1{font-size:clamp(2.8rem,6vw,5.3rem);line-height:.99;margin:18px 0 22px}h2{font-size:1.55rem;margin:0 0 8px}h3{font-size:1rem;margin:0 0 7px}.eyebrow{font-size:.72rem;font-weight:700;letter-spacing:.17em;color:#ff7888}.muted,.hero-lede,.section-heading p,.inventory-heading p{color:var(--muted)}.button,button{font:inherit;display:inline-flex;align-items:center;justify-content:center;gap:11px;min-height:44px;padding:11px 17px;border:1px solid transparent;border-radius:11px;color:white;background:linear-gradient(135deg,var(--red2),var(--red));font-weight:700;text-decoration:none;cursor:pointer;transition:transform .18s ease,filter .18s ease,border-color .18s ease}.button:hover,button:hover{transform:translateY(-1px);filter:brightness(1.08)}.button.ghost{background:#ffffff05;border-color:#ffffff1c;color:#eee4e8}.button.danger{background:#67202c;border-color:#a93346;color:#ffe7eb}.button.small{min-height:37px;padding:8px 12px;font-size:.82rem;border-radius:9px}.actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.hero-wrap{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(310px,.75fr);gap:clamp(36px,8vw,120px);align-items:center;min-height:570px;padding:52px 2px 72px}.hero-copy{max-width:720px}.hero-copy h1 span{color:var(--red2)}.hero-lede{font-size:1.12rem;line-height:1.75;max-width:590px}.hero-actions{margin-top:30px}.trust-note{margin-top:25px;color:#b9aab0;font-size:.84rem}.shield{display:inline-grid;place-items:center;width:19px;height:19px;border-radius:50%;background:#321820;color:#ff8492;margin-right:5px;font-weight:700}.divider{padding:0 7px;color:#60424b}.hero-panel{position:relative;max-width:460px;width:100%;justify-self:center;padding:25px;border:1px solid #61303b;border-radius:26px;background:linear-gradient(145deg,#24161d,#130f14 75%);box-shadow:0 30px 100px #e33e5518,inset 0 1px #ffffff0a;overflow:hidden}.panel-top,.panel-footer{display:flex;justify-content:space-between;align-items:center}.panel-mark,.brand-emblem{display:grid;place-items:center;font-family:\'Space Grotesk\';font-weight:700;color:#fff;background:linear-gradient(145deg,#ff7182,#aa243a);box-shadow:0 8px 24px #e33e5538}.panel-mark{width:38px;height:38px;border-radius:12px}.pill,.server-pill{display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid #ffffff18;border-radius:100px;font-size:.62rem;letter-spacing:.12em;color:#bfb3b8}.pill i,.server-pill i{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #50d4a2}.panel-orbit{position:relative;height:250px;display:grid;place-items:center;overflow:hidden}.orbit{position:absolute;border:1px solid #ff6e8024;border-radius:50%;transform:rotate(-28deg)}.orbit-one{width:220px;height:145px}.orbit-two{width:155px;height:210px;transform:rotate(38deg);border-color:#ff6e801c}.orbit-core{display:grid;place-items:center;width:91px;height:91px;border-radius:28px;background:linear-gradient(145deg,#e74c62,#8e2538);box-shadow:0 0 75px #e33e5555,inset 0 1px #ffffff45;font:700 2rem \'Space Grotesk\'}.panel-caption{text-align:center}.panel-caption strong,.panel-caption span{display:block}.panel-caption span{margin-top:5px;color:var(--muted);font-size:.85rem}.panel-rule{height:1px;margin:24px 0;background:#ffffff10}.panel-rule span{display:block;width:39%;height:1px;background:var(--red2);box-shadow:0 0 12px var(--red)}.panel-footer{font-size:.62rem;letter-spacing:.12em;color:#90818a}.panel-footer span:last-child{color:#80d9ae}.feature-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.feature-card{display:flex;gap:16px;padding:22px;border:1px solid var(--line);border-radius:17px;background:linear-gradient(145deg,#191217,#130f13)}.feature-icon{flex:0 0 38px;height:38px;display:grid;place-items:center;border:1px solid #67313d;border-radius:11px;color:#ff7b8a;font-size:.72rem;font-weight:700}.feature-card p{margin:0;color:var(--muted);font-size:.85rem;line-height:1.6}.portal-foot,.admin-foot{display:flex;justify-content:space-between;gap:18px;padding:30px 2px 0;color:#796c72;font-size:.72rem;letter-spacing:.08em}.portal-foot span:first-child,.admin-foot span:first-child{color:#bdadb4;font-weight:700}.card{border:1px solid var(--line);border-radius:20px;background:linear-gradient(145deg,#1b1419ed,#120f13f2);box-shadow:var(--shadow);padding:clamp(23px,4vw,40px)}.center{max-width:680px;margin:65px auto;text-align:center}.flow-card{position:relative;overflow:hidden}.flow-card:before{content:\'\';position:absolute;top:0;left:12%;right:12%;height:1px;background:linear-gradient(90deg,transparent,var(--red2),transparent)}.flow-card h1{font-size:clamp(2.4rem,6vw,4rem)}.flow-card p{color:var(--muted);line-height:1.7}.step-mark{margin:0 auto 24px;width:54px;height:54px;display:grid;place-items:center;border:1px solid #753442;border-radius:16px;background:#351821;color:#ff8997;font-weight:700}.step-mark span{font-size:.65rem}.micro-note{margin:22px 0 0;font-size:.78rem;color:#81737a}.keybox{margin:24px 0;padding:19px 22px;border:1px dashed #9d4250;border-radius:13px;background:#100c10;color:#fff;font:700 1.2rem \'Space Grotesk\';letter-spacing:.08em;word-break:break-all}.timer{margin:18px 0;color:#ff8896;font-weight:700}.center-actions{justify-content:center}.login-card{max-width:500px;text-align:left}.brand-lockup{display:flex;align-items:center;gap:10px;text-decoration:none;font:700 .9rem \'Space Grotesk\';letter-spacing:.04em}.brand-lockup small{display:block;margin-top:2px;color:#ff7d8c;font:700 .55rem \'DM Sans\';letter-spacing:.2em}.brand-emblem{width:40px;height:40px;border-radius:12px}.login-card .brand-lockup{margin:0 0 32px}.login-card h1{font-size:2.5rem}.login-card .eyebrow{margin-top:25px}.login-form{display:grid;gap:10px;margin-top:25px}.login-form label,.create-form label{display:grid;gap:8px;color:#d8cbd0;font-size:.82rem;font-weight:600}.login-form input{margin-bottom:9px}.notice{margin:18px 0;padding:13px 16px;border:1px solid #8d3c49;border-radius:12px;background:#3a1720;color:#ffe1e5}.notice div+div{margin-top:6px}input,select{width:100%;min-width:0;min-height:42px;padding:10px 12px;border:1px solid #403039;border-radius:10px;background:#100c10;color:var(--text);font:inherit;outline:none}input:focus,select:focus{border-color:#d44b60;box-shadow:0 0 0 3px #e33e551c}input::placeholder{color:#766a70}select{cursor:pointer}.admin-topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:5px 0 25px;border-bottom:1px solid #ffffff12}.topbar-right{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.server-pill{font-size:.62rem}.admin-intro{display:flex;align-items:flex-end;justify-content:space-between;gap:22px;padding:36px 0 27px}.admin-intro h1{font-size:clamp(2.4rem,4vw,3.7rem);margin:9px 0}.admin-intro p{margin:0;color:var(--muted)}.intro-chip{display:flex;align-items:center;gap:12px;padding:12px 16px;border:1px solid var(--line);border-radius:13px;background:#ffffff05}.intro-chip-icon{display:grid;place-items:center;width:37px;height:37px;border-radius:10px;background:#3a1922;color:#ff8290;font-size:1.2rem}.intro-chip b,.intro-chip small{display:block}.intro-chip small{color:var(--muted);font-size:.7rem}.stats-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:0 0 16px}.metric-card{padding:18px;border:1px solid var(--line);border-radius:15px;background:linear-gradient(145deg,#1b1419,#120f13)}.metric-label,.metric-foot{display:block;color:#a99ba1;font-size:.65rem;letter-spacing:.12em}.metric-card strong{display:block;margin:11px 0 5px;font:700 1.8rem \'Space Grotesk\'}.metric-foot{font-size:.72rem;letter-spacing:0}.metric-red strong{color:#ff7787}.admin-workspace{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:16px}.admin-workspace .card{margin:0;padding:24px}.section-heading,.inventory-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}.section-heading p,.inventory-heading p{margin:0;font-size:.82rem}.section-icon{display:grid;place-items:center;flex:0 0 36px;width:36px;height:36px;border-radius:10px;background:#371923;color:#ff8794;font-size:1.15rem}.create-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:23px}.span-two{grid-column:span 2}.input-with-suffix{position:relative}.input-with-suffix input{padding-right:56px}.input-with-suffix em{position:absolute;right:12px;top:12px;color:#9f9097;font-size:.75rem;font-style:normal}.create-form .button{width:100%;margin-top:3px}.operation-row{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:16px 0;border-bottom:1px solid #ffffff10}.operation-row:first-of-type{margin-top:8px}.operation-row:last-child{border-bottom:0;padding-bottom:0}.operation-row b,.operation-row small{display:block}.operation-row b{font-size:.84rem}.operation-row small{max-width:310px;margin-top:4px;color:var(--muted);font-size:.72rem;line-height:1.45}.inventory-card{margin:16px 0 0;padding:25px}.inventory-heading{align-items:center}.count-pill{padding:7px 11px;border:1px solid #ffffff16;border-radius:100px;color:#c3b7bc;font-size:.73rem}.filterbar{display:grid;grid-template-columns:minmax(200px,1fr) 160px 130px auto auto;gap:9px;align-items:center;margin:22px 0 15px}.search-field{position:relative}.search-field span{position:absolute;left:12px;top:9px;color:#a99ba1;font-size:1.15rem}.search-field input{padding-left:37px}.table-shell{overflow-x:auto;border:1px solid #ffffff12;border-radius:13px}.key-table{width:100%;min-width:1050px;border-collapse:collapse;text-align:left}.key-table th{padding:12px 13px;background:#ffffff06;color:#aa9ba2;font-size:.64rem;letter-spacing:.1em;font-weight:700}.key-table td{padding:13px;border-top:1px solid #ffffff0d;vertical-align:middle}.key-table tbody tr:hover{background:#ffffff04}.key-table code{display:inline-block;color:#fff;font:600 .8rem \'DM Sans\';letter-spacing:.02em}.row-note{max-width:230px;margin-top:5px;color:#887a81;font-size:.7rem;white-space:normal}.status-badge{display:inline-flex;align-items:center;gap:7px;padding:6px 9px;border-radius:100px;background:#ffffff0a;color:#c8bcc1;font-size:.68rem;text-transform:capitalize}.status-badge i{width:6px;height:6px;border-radius:50%;background:#a4999f}.status-badge.active{background:#123126;color:#92e3bd}.status-badge.active i{background:#50d4a2}.status-badge.expired{background:#342819;color:#e5bd7e}.status-badge.expired i{background:#dca94f}.status-badge.revoked{background:#351b22;color:#ef99a3}.status-badge.revoked i{background:#dc6474}.expiry-cell{color:#c9bdc2;font-size:.76rem;white-space:nowrap}.device-count{font-weight:700}.device-count small{color:#94868d;font-weight:400}.renew-form,.manage-actions{display:flex;align-items:center;gap:5px}.renew-form input{width:70px;min-height:32px;padding:5px 7px;font-size:.75rem}.mini-button{display:inline-flex;align-items:center;justify-content:center;min-height:31px;padding:5px 8px;border:1px solid #49313a;border-radius:8px;background:#21171d;color:#e5d9de;font-size:.7rem;font-weight:700;cursor:pointer}.mini-button:hover{border-color:#a74859;background:#351923}.mini-danger{color:#ff9ba5;border-color:#64313a}.empty-state{text-align:center;padding:42px!important;color:#b3a6ac}.empty-state span,.empty-state b,.empty-state small{display:block}.empty-state span{font-size:1.5rem;color:#ff7d8b}.empty-state b{margin:7px}.empty-state small{color:#8f8188}.table-footer{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:17px;color:var(--muted);font-size:.77rem}.pagination{display:flex;align-items:center;gap:10px}.pagination .disabled{opacity:.42;pointer-events:none}.pagination>span{white-space:nowrap}.admin-foot{border-top:1px solid #ffffff10;margin-top:20px}.admin-foot a{color:#d6c5cc;text-decoration:none;letter-spacing:0}.admin-foot a:hover{color:#ff8695}\n@media(max-width:1000px){main{width:min(100% - 32px,1480px)}.hero-wrap{gap:35px;min-height:500px}.stats-grid{grid-template-columns:repeat(3,1fr)}.admin-workspace{grid-template-columns:1fr}.filterbar{grid-template-columns:minmax(180px,1fr) 1fr 1fr auto}.filterbar .button.ghost{grid-column:4}}\n@media(max-width:680px){main{width:calc(100% - 28px);padding-top:18px}.hero-wrap{grid-template-columns:1fr;padding:58px 0 48px;min-height:0}.hero-panel{max-width:420px}.hero-copy h1{font-size:3.5rem}.feature-grid{grid-template-columns:1fr}.portal-foot,.admin-foot{flex-direction:column}.admin-topbar{align-items:flex-start}.topbar-right{justify-content:flex-end}.server-pill{display:none}.admin-intro{align-items:flex-start}.intro-chip{display:none}.stats-grid{grid-template-columns:repeat(2,1fr)}.stats-grid .metric-card:last-child{grid-column:span 2}.admin-workspace .card,.inventory-card{padding:18px}.create-form{grid-template-columns:1fr}.span-two{grid-column:auto}.filterbar{grid-template-columns:1fr 1fr}.search-field{grid-column:span 2}.filterbar .button{width:100%}.table-footer{align-items:flex-start;flex-direction:column}.pagination{width:100%;justify-content:space-between}.center{margin:35px auto}.card{border-radius:16px}.topbar-right .small{padding:7px 9px;font-size:.72rem}}\n@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important}}\n</style></head><body><main>{{body|safe}}</main></body></html>'

init_db()
if __name__=='__main__': app.run(host=os.getenv('HOST','0.0.0.0'),port=int(os.getenv('PORT','5555')),debug=False)
