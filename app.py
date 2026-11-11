import hashlib
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from decimal import Decimal, InvalidOperation

from werkzeug.exceptions import HTTPException

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "shop.db"))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE_DIR, "static", "uploads"))

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
RESET_HOURS = 11
MAX_RESETS_PER_HOUR = 3


def _secret_key():
    """Use SECRET_KEY from the environment, otherwise create and keep a random one."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes", "on"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=3 * 1024 * 1024,  # upload cap (each image is limited to 2 MB)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now():
    return datetime.now(timezone.utc)


# ================= Database =================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Columns added to "orders" for the checkout page (older databases are upgraded automatically)
ORDER_COLUMNS = {
    "subtotal": "REAL", "shipping": "REAL", "tax": "REAL",
    "contact_email": "TEXT", "contact_phone": "TEXT",
    "ship_name": "TEXT", "ship_address": "TEXT", "ship_district": "TEXT", "ship_city": "TEXT",
    "payment_method": "TEXT", "payment_status": "TEXT", "momo_number": "TEXT",
    "status": "TEXT DEFAULT 'Placed'", "cancelled_at": "TEXT",
}


def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DATABASE)), exist_ok=True)
    with sqlite3.connect(DATABASE) as db:
        with open(os.path.join(BASE_DIR, "schema.sql")) as f:
            db.executescript(f.read())
        existing = {r[1] for r in db.execute("PRAGMA table_info(orders)")}
        for col, typ in ORDER_COLUMNS.items():
            if col not in existing:
                db.execute(f"ALTER TABLE orders ADD COLUMN {col} {typ}")
        user_cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        if "email_verified" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE users SET email_verified = 1")  # accounts created before verification existed
        item_cols = {r[1] for r in db.execute("PRAGMA table_info(order_items)")}
        for col, typ in {"seller_id": "INTEGER", "status": "TEXT DEFAULT 'Placed'"}.items():
            if col not in item_cols:
                db.execute(f"ALTER TABLE order_items ADD COLUMN {col} {typ}")
        # older order lines: remember which seller owns them (needed once the product is deleted)
        db.execute("UPDATE order_items SET seller_id = (SELECT seller_id FROM products "
                   "WHERE products.id = order_items.product_id) WHERE seller_id IS NULL")
    db.close()


# ================= Security helpers =================
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid request (CSRF check failed).")


@app.before_request
def prefer_localhost():
    """Google/Facebook redirect to http://localhost:5000, so a session started on 127.0.0.1 would be lost."""
    if request.method == "GET" and request.host.split(":")[0] == "127.0.0.1":
        return redirect(request.url.replace("127.0.0.1", "localhost", 1))


@app.after_request
def security_headers(resp):
    # Stops the Back button from showing cached private pages after logout
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def valid_password(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


PASSWORD_RULE = "Password must be 8+ characters with letters and numbers."


def dashboard_for(role):
    return url_for(f"{role}_dashboard")


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def role_required(*roles):
    """Role-based access control. Wrong role -> back to own dashboard."""
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*a, **kw):
            if session.get("role") not in roles:
                flash("You do not have permission to open that page.", "error")
                return redirect(dashboard_for(session["role"]))
            return f(*a, **kw)
        return wrapper
    return decorator


def start_session(user):
    session.clear()  # fresh session on login (prevents session fixation)
    session.permanent = True
    session["user_id"] = user["id"]
    session["name"] = user["full_name"]
    session["role"] = user["role"]


# ================= Email =================
def _send_email(to, subject, text, html, reply_to=None):
    server = os.environ.get("MAIL_SERVER")
    if not server:
        # Development fallback: no SMTP configured, so print the email in the terminal.
        print(f"\n===== [DEV EMAIL - SMTP not configured] =====\nTo: {to}\n"
              f"Subject: {subject}\n\n{text}\n=============================================\n")
        return
    user = os.environ.get("MAIL_USERNAME", "")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("MAIL_FROM") or user
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    # Try the configured port first, then Gmail's other port (465), retrying a few times:
    # a flaky connection or a blocked port should not lose the email.
    port = int(os.environ.get("MAIL_PORT", "587"))
    ports = [port] + ([465] if port == 587 else [587] if port == 465 else [])
    password = os.environ.get("MAIL_PASSWORD", "").replace(" ", "")  # Google shows it in groups of 4
    timeout = int(os.environ.get("MAIL_TIMEOUT", "30"))
    errors = []
    for attempt in range(4):
        p = ports[attempt % len(ports)]
        try:
            if p == 465:
                with smtplib.SMTP_SSL(server, p, timeout=timeout) as conn:
                    conn.login(user, password)
                    conn.send_message(msg)
            else:
                with smtplib.SMTP(server, p, timeout=timeout) as conn:
                    conn.starttls()
                    conn.login(user, password)
                    conn.send_message(msg)
            print(f"[email] sent to {to}: {subject}" + (f" (after {attempt} retr{'y' if attempt == 1 else 'ies'}, port {p})" if attempt else ""))
            return
        except smtplib.SMTPAuthenticationError as exc:  # wrong App password: retrying cannot help
            app.logger.error("Could not send email to %s: login refused by the mail server (%s). "
                             "Check MAIL_USERNAME / MAIL_PASSWORD in .env.", to, exc)
            return
        except Exception as exc:  # never crash the request because of email problems
            errors.append(f"port {p}: {exc}")
            time.sleep(2 * (attempt + 1))
    app.logger.error("Could not send email to %s after %d attempts: %s", to, len(errors), "; ".join(errors))


def send_email(to, subject, text, html, reply_to=None):
    if app.config.get("TESTING"):
        _send_email(to, subject, text, html, reply_to)
    else:  # background thread: the page responds immediately, no timing leaks
        threading.Thread(target=_send_email, args=(to, subject, text, html, reply_to), daemon=True).start()


def site_link(endpoint, **values):
    base = os.environ.get("SITE_URL", "").rstrip("/")
    if base:
        return base + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)


# ================= Registration / Login =================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    products = get_db().execute("SELECT * FROM products ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("home.html", products=products)


@app.route("/catalog")
def catalog():
    q = request.args.get("q", "").strip()[:100]
    if q:
        products = get_db().execute("SELECT * FROM products WHERE name LIKE ? ORDER BY id DESC",
                                    (f"%{q}%",)).fetchall()
    else:
        products = get_db().execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("catalog.html", products=products, q=q)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    form = {"full_name": "", "email": "", "role": "buyer"}
    if request.method == "POST":
        form["full_name"] = request.form.get("full_name", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        form["role"] = request.form.get("role", "buyer")
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm_password", "")
        errors = []
        if len(form["full_name"]) < 2:
            errors.append("Full name must be at least 2 characters.")
        if not EMAIL_RE.match(form["email"]):
            errors.append("Enter a valid email address.")
        if not valid_password(pw):
            errors.append(PASSWORD_RULE)
        if pw != pw2:
            errors.append("Passwords do not match.")
        # Public sign-up can only create Buyer or Seller. Admins are created by script.
        if form["role"] not in ("buyer", "seller"):
            errors.append("Invalid role selected.")
        if not errors:
            db = get_db()
            existing = db.execute("SELECT * FROM users WHERE email = ?", (form["email"],)).fetchone()
            if existing and (existing["email_verified"] or not existing["is_active"]):
                errors.append("That email is already registered. Try logging in or use 'Forgot password'.")
            else:
                if existing:  # an earlier sign-up that was never verified: the new one replaces it
                    db.execute("UPDATE users SET full_name = ?, password_hash = ?, role = ?, failed_attempts = 0, "
                               "locked_until = NULL WHERE id = ?",
                               (form["full_name"], generate_password_hash(pw), form["role"], existing["id"]))
                    uid = existing["id"]
                else:
                    uid = db.execute(
                        "INSERT INTO users (full_name, email, password_hash, role, email_verified) VALUES (?,?,?,?,0)",
                        (form["full_name"], form["email"], generate_password_hash(pw), form["role"])).lastrowid
                db.commit()
                sent_ok = send_verification(db, db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())
                if sent_ok:
                    flash(f"Account created! We sent a verification link to {form['email']}. "
                          "Click it to activate your account, then log in. Nothing in your inbox? Check Spam, "
                          "or use 'Resend verification email' on the login page.", "success")
                else:
                    flash("Account created, but we already sent several verification emails to this address "
                          "in the last hour. Please check your inbox and Spam folder, or try again later.", "error")
                return redirect(url_for("login"))
        for e in errors:
            flash(e, "error")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    email = ""
    unverified = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > now():
            mins = int((datetime.fromisoformat(user["locked_until"]) - now()).total_seconds() // 60) + 1
            flash(f"Too many failed attempts. Try again in about {mins} minute(s), "
                  "or reset your password.", "error")
        elif user and user["password_hash"] and check_password_hash(user["password_hash"], pw):
            if not user["is_active"]:
                flash("This account has been deactivated. Contact the administrator.", "error")
            elif not user["email_verified"]:
                unverified = user["email"]  # only shown after the correct password was typed
                flash("Please verify your email address before logging in. "
                      "Open the link we emailed you, or request a new one below.", "error")
            else:
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                           (user["id"],))
                db.commit()
                start_session(user)
                return redirect(dashboard_for(user["role"]))  # role-based redirect
        else:
            if user:
                attempts = user["failed_attempts"] + 1
                locked = (now() + timedelta(minutes=LOCK_MINUTES)).isoformat() \
                    if attempts >= MAX_FAILED_ATTEMPTS else None
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (0 if locked else attempts, locked, user["id"]))
                db.commit()
            flash("Invalid email or password.", "error")  # same message on purpose
    return render_template("login.html", email=email, unverified=unverified)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ================= Email verification =================
VERIFY_HOURS = 24


def send_verification(db, user):
    """Email a fresh single-use verification link (at most 3 per hour per account)."""
    hour_ago = (now() - timedelta(hours=1)).isoformat()
    recent = db.execute("SELECT COUNT(*) FROM email_verifications WHERE user_id = ? AND created_at > ?",
                        (user["id"], hour_ago)).fetchone()[0]
    if recent >= MAX_RESETS_PER_HOUR:
        return False
    token = secrets.token_urlsafe(32)
    db.execute("UPDATE email_verifications SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
    db.execute("INSERT INTO email_verifications (user_id, token_hash, expires_at, created_at) VALUES (?,?,?,?)",
               (user["id"], _hash_token(token), (now() + timedelta(hours=VERIFY_HOURS)).isoformat(),
                now().isoformat()))
    db.commit()
    link = site_link("verify_email", token=token)
    name = user["full_name"].replace("<", "&lt;")
    send_email(user["email"], "Confirm your ShopHub email address",
               f"Hello {user['full_name']},\n\nWelcome to ShopHub! Open the link below, then select "
               f"'Confirm my email address' to activate your account. The link is valid for {VERIFY_HOURS} hours "
               f"and works once:\n\n{link}\n\n"
               "If you did not create a ShopHub account, you can ignore this email.",
               f"<p>Hello {name},</p><p>Welcome to <strong>ShopHub</strong>! Open the link below, then select "
               f"Confirm my email address to activate your account.</p><p><a href=\"{link}\" "
               f"style=\"background:#12704f;color:#fff;padding:10px 18px;border-radius:6px;"
               f"text-decoration:none\">Open verification page</a></p>"
               f"<p>The link works once and is valid for {VERIFY_HOURS} hours. If the button doesn't work, copy "
               f"this address into your browser:<br>{link}</p>"
               "<p>If you did not create a ShopHub account, you can ignore this email.</p>")
    return True


@app.route("/verify-email/<token>", methods=["GET", "POST"])
def verify_email(token):
    db = get_db()
    row = db.execute("SELECT * FROM email_verifications WHERE token_hash = ? AND used = 0",
                     (_hash_token(token),)).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) <= now():
        flash("This verification link is invalid or has expired. Enter your email and password on the "
              "login page to get a new one.", "error")
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("verify_email.html", token=token)

    claimed = db.execute("UPDATE email_verifications SET used = 1 WHERE id = ? AND used = 0",
                         (row["id"],))
    if claimed.rowcount != 1:
        flash("This verification link has already been used. You can log in or request a new one.", "error")
        return redirect(url_for("login"))
    db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],))
    db.commit()
    flash("Email verified! You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    email = request.form.get("email", "").strip().lower()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ? AND email_verified = 0 AND is_active = 1 "
                      "AND password_hash IS NOT NULL", (email,)).fetchone()
    if user:
        send_verification(db, user)
    # same answer for every address (prevents account discovery)
    flash("If that account is waiting for verification, a new link has been sent. Check your inbox and Spam "
          "folder (you can request up to 3 per hour).", "success")
    return redirect(url_for("login"))


# ================= Forgot / reset password =================
def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (email,)).fetchone()
        if user:
            hour_ago = (now() - timedelta(hours=1)).isoformat()
            recent = db.execute("SELECT COUNT(*) FROM password_resets WHERE user_id = ? AND created_at > ?",
                                (user["id"], hour_ago)).fetchone()[0]
            if recent < MAX_RESETS_PER_HOUR:  # protects against email flooding
                token = secrets.token_urlsafe(32)
                db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
                db.execute(
                    "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?,?,?,?)",
                    (user["id"], _hash_token(token),
                     (now() + timedelta(hours=RESET_HOURS)).isoformat(), now().isoformat()))
                db.commit()
                link = site_link("reset_password", token=token)
                text = (f"Hello {user['full_name']},\n\nWe received a request to reset your ShopHub password.\n"
                        f"Open this link to choose a new one (valid for {RESET_HOURS} hour):\n\n{link}\n\n"
                        "If you did not ask for this, you can ignore this email.")
                html = (f"<p>Hello {user['full_name']},</p><p>We received a request to reset your ShopHub password.</p>"
                        f"<p><a href=\"{link}\" style=\"background:#12704f;color:#fff;padding:10px 18px;"
                        f"border-radius:6px;text-decoration:none\">Reset my password</a></p>"
                        f"<p>This link is valid for {RESET_HOURS} hour. If the button doesn't work, copy this "
                        f"address into your browser:<br>{link}</p>"
                        "<p>If you did not ask for this, you can ignore this email.</p>")
                send_email(user["email"], "Reset your ShopHub password", text, html)
        # Same answer whether or not the email exists (prevents account discovery)
        flash("If that email is registered, a password reset link has been sent. Check your inbox.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


def _find_reset(token):
    row = get_db().execute("SELECT * FROM password_resets WHERE token_hash = ? AND used = 0",
                           (_hash_token(token),)).fetchone()
    if row and datetime.fromisoformat(row["expires_at"]) > now():
        return row
    return None


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    row = _find_reset(token)
    if not row:
        flash("This reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm_password", "")
        if not valid_password(pw):
            flash(PASSWORD_RULE, "error")
        elif pw != pw2:
            flash("Passwords do not match.", "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL, "
                       "email_verified = 1 WHERE id = ?", (generate_password_hash(pw), row["user_id"]))
            db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (row["user_id"],))
            db.commit()
            flash("Password updated. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# ================= Social sign-in (Google, LinkedIn, Facebook) =================
oauth = OAuth(app)
PROVIDER_NAMES = {"google": "Google", "linkedin": "LinkedIn", "facebook": "Facebook"}


def register_oauth_providers():
    env = os.environ.get
    if env("GOOGLE_CLIENT_ID") and env("GOOGLE_CLIENT_SECRET"):
        oauth.register(
            "google", client_id=env("GOOGLE_CLIENT_ID"), client_secret=env("GOOGLE_CLIENT_SECRET"),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"})
    if env("LINKEDIN_CLIENT_ID") and env("LINKEDIN_CLIENT_SECRET"):
        oauth.register(
            "linkedin", client_id=env("LINKEDIN_CLIENT_ID"), client_secret=env("LINKEDIN_CLIENT_SECRET"),
            server_metadata_url="https://www.linkedin.com/oauth/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile email"})
    if env("FACEBOOK_CLIENT_ID") and env("FACEBOOK_CLIENT_SECRET"):
        oauth.register(
            "facebook", client_id=env("FACEBOOK_CLIENT_ID"), client_secret=env("FACEBOOK_CLIENT_SECRET"),
            access_token_url="https://graph.facebook.com/oauth/access_token",
            authorize_url="https://www.facebook.com/dialog/oauth",
            api_base_url="https://graph.facebook.com/",
            client_kwargs={"scope": "email public_profile"})


register_oauth_providers()
# Buttons are shown only for providers whose keys are in .env, so users never hit a dead button
ENABLED_PROVIDERS = {p for p in PROVIDER_NAMES if oauth.create_client(p) is not None}


def social_login(provider, provider_id, email, name, email_verified):
    """Find / link / create the local user for a social identity.
    Returns (user, error_message)."""
    db = get_db()
    user = db.execute(
        "SELECT u.* FROM users u JOIN social_accounts s ON s.user_id = u.id "
        "WHERE s.provider = ? AND s.provider_id = ?", (provider, provider_id)).fetchone()
    if not user:
        email = (email or "").strip().lower()
        if not email:
            return None, (f"{PROVIDER_NAMES[provider]} did not share an email address, "
                          "so we cannot create your account.")
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            if not email_verified:  # never link accounts on an unverified email
                return None, ("An account with this email already exists. "
                              "Log in with your password first.")
            if not user["email_verified"]:
                # the password on a never-verified sign-up may have been typed by someone else: discard it
                db.execute("UPDATE users SET password_hash = NULL, email_verified = 1 WHERE id = ?", (user["id"],))
                db.commit()
                user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        else:
            role = session.get("signup_role", "buyer")
            if role not in ("buyer", "seller"):
                role = "buyer"
            cur = db.execute("INSERT INTO users (full_name, email, password_hash, role, email_verified) "
                             "VALUES (?,?,NULL,?,1)",
                             ((name or email.split("@")[0]).strip()[:100], email, role))
            user = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        db.execute("INSERT INTO social_accounts (provider, provider_id, user_id) VALUES (?,?,?)",
                   (provider, str(provider_id), user["id"]))
        db.commit()
    if not user["is_active"]:
        return None, "This account has been deactivated. Contact the administrator."
    return user, None


@app.route("/auth/<provider>")
def oauth_start(provider):
    if provider not in PROVIDER_NAMES:
        abort(404)
    client = oauth.create_client(provider)
    if client is None:
        flash(f"{PROVIDER_NAMES[provider]} sign-in is not set up yet. "
              "Add its keys to the .env file (see README).", "error")
        return redirect(request.referrer or url_for("login"))
    role = request.args.get("role", "buyer")
    session["signup_role"] = role if role in ("buyer", "seller") else "buyer"
    return client.authorize_redirect(url_for("oauth_callback", provider=provider, _external=True))


@app.route("/auth/<provider>/callback")
def oauth_callback(provider):
    if provider not in PROVIDER_NAMES:
        abort(404)
    client = oauth.create_client(provider)
    if client is None:
        return redirect(url_for("login"))
    try:
        token = client.authorize_access_token()
        if provider == "facebook":
            info = client.get("me?fields=id,name,email", token=token).json()
            pid, email, name, verified = info.get("id"), info.get("email"), info.get("name"), True
        else:  # Google and LinkedIn (OpenID Connect)
            info = token.get("userinfo") or client.userinfo(token=token)
            pid, email, name = info.get("sub"), info.get("email"), info.get("name")
            verified = bool(info.get("email_verified"))
        if not pid:
            raise ValueError("no provider id")
    except Exception as exc:
        app.logger.error("OAuth error (%s): %s", provider, exc)
        flash(f"{PROVIDER_NAMES[provider]} sign-in was cancelled or failed. Please try again.", "error")
        return redirect(url_for("login"))
    user, error = social_login(provider, pid, email, name, verified)
    if error:
        flash(error, "error")
        return redirect(url_for("login"))
    start_session(user)
    return redirect(dashboard_for(user["role"]))


# ================= Account management =================
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    uid = session["user_id"]
    if request.method == "POST":
        action = request.form.get("action")
        if action == "update_profile":
            name = request.form.get("full_name", "").strip()
            if len(name) < 2:
                flash("Name must be at least 2 characters.", "error")
            else:
                db.execute("UPDATE users SET full_name = ? WHERE id = ?", (name, uid))
                db.commit()
                session["name"] = name
                flash("Profile updated.", "success")
        elif action == "change_password":
            row = db.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
            cur = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            # Social-only users have no current password, so they can simply set one
            if row["password_hash"] and not check_password_hash(row["password_hash"], cur):
                flash("Current password is incorrect.", "error")
            elif not valid_password(new):
                flash(PASSWORD_RULE, "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(new), uid))
                db.commit()
                flash("Password saved.", "success")
        return redirect(url_for("profile"))
    user = db.execute("SELECT full_name, email, role, created_at, password_hash FROM users WHERE id = ?",
                      (uid,)).fetchone()
    providers = [PROVIDER_NAMES[r["provider"]] for r in
                 db.execute("SELECT provider FROM social_accounts WHERE user_id = ?", (uid,))]
    return render_template("profile.html", user=user, has_password=bool(user["password_hash"]),
                           providers=providers)


# ================= Role dashboards =================
@app.route("/admin/dashboard", methods=["GET", "POST"])
@role_required("admin")
def admin_dashboard():
    db = get_db()
    if request.method == "POST":
        target = request.form.get("user_id", type=int)
        action = request.form.get("action")
        if target == session["user_id"]:
            flash("You cannot modify your own account here.", "error")
        elif action == "toggle":
            db.execute("UPDATE users SET is_active = 1 - is_active WHERE id = ?", (target,))
            db.commit()
            flash("User status updated.", "success")
        elif action == "role" and request.form.get("role") in ("admin", "seller", "buyer"):
            db.execute("UPDATE users SET role = ? WHERE id = ?", (request.form["role"], target))
            db.commit()
            flash("User role updated.", "success")
        elif action == "verify":
            db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (target,))
            db.commit()
            flash("Email marked as verified.", "success")
        elif action == "unlock":
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (target,))
            db.commit()
            flash("Account unlocked.", "success")
        return redirect(url_for("admin_dashboard"))
    users = db.execute(
        "SELECT id, full_name, email, role, is_active, email_verified, locked_until, created_at "
        "FROM users ORDER BY created_at DESC").fetchall()
    counts = {r["role"]: r["c"] for r in db.execute("SELECT role, COUNT(*) AS c FROM users GROUP BY role")}
    locked_now = {u["id"] for u in users
                  if u["locked_until"] and datetime.fromisoformat(u["locked_until"]) > now()}
    return render_template("admin_dashboard.html", users=users, counts=counts, locked_now=locked_now)


# =====================================================================
#                     STAGE 2: PRODUCTS, CATALOG, CART
# =====================================================================
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_IMAGE_BYTES = 2 * 1024 * 1024
LOW_STOCK = 5


def fmt_money(value):
    value = float(value or 0)
    return f"RWF {value:,.0f}" if abs(value - round(value)) < 0.005 else f"RWF {value:,.2f}"


app.jinja_env.filters["money"] = fmt_money
app.jinja_env.globals["LOW_STOCK"] = LOW_STOCK


@app.route("/uploads/<path:filename>")
def product_image(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.context_processor
def inject_cart_count():
    """Cart counter shown in the navigation header (buyers only)."""
    n = 0
    if session.get("role") == "buyer" and "user_id" in session:
        n = get_db().execute("SELECT COALESCE(SUM(quantity),0) FROM cart_items WHERE user_id = ?",
                             (session["user_id"],)).fetchone()[0]
    return {"cart_count": n}


@app.errorhandler(413)
def too_large(_e):
    flash("The upload is too large. Product images must be 2 MB or smaller.", "error")
    return redirect(request.referrer or url_for("index"))


# ---------- image handling ----------
def detect_image_ext(data):
    """Identify the real file type from its first bytes (not from the file name)."""
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


def read_image(file_storage):
    """Validate an uploaded image. Returns (data, ext, error)."""
    if file_storage is None or not file_storage.filename:
        return None, None, "Please choose a product image."
    data = file_storage.read()
    if not data:
        return None, None, "The selected image file is empty."
    if len(data) > MAX_IMAGE_BYTES:
        return None, None, "The image is too large. Maximum size is 2 MB."
    ext = detect_image_ext(data)
    if not ext:
        return None, None, "The image must be a real JPG, PNG, GIF or WEBP file."
    return data, ext, None


def write_image(data, ext):
    name = secrets.token_hex(16) + ext  # random name: no clashes, no path tricks
    with open(os.path.join(UPLOAD_DIR, name), "wb") as f:
        f.write(data)
    return name


def delete_image(name):
    if name:
        try:
            os.remove(os.path.join(UPLOAD_DIR, os.path.basename(name)))
        except OSError:
            pass


# ---------- product form validation ----------
def parse_product_form(form):
    raw = {"name": form.get("name", "").strip(),
           "description": form.get("description", "").strip(),
           "price": form.get("price", "").strip(),
           "stock": form.get("stock", "").strip()}
    errors, price, stock = [], None, None
    if not 2 <= len(raw["name"]) <= 120:
        errors.append("Product name must be between 2 and 120 characters.")
    if not 1 <= len(raw["description"]) <= 1000:
        errors.append("Description is required (maximum 1000 characters).")
    try:
        d = Decimal(raw["price"].replace(",", ""))
        if not d.is_finite() or d <= 0:
            raise InvalidOperation
        if d.as_tuple().exponent < -2:
            errors.append("Price can have at most 2 decimal places.")
        elif d > Decimal("100000000"):
            errors.append("Price is too large.")
        else:
            price = float(d)
    except InvalidOperation:
        errors.append("Price must be a positive number.")
    if re.fullmatch(r"\d{1,7}", raw["stock"]) and int(raw["stock"]) <= 1_000_000:
        stock = int(raw["stock"])
    else:
        errors.append("Stock quantity must be a whole number (0 or more).")
    return raw, price, stock, errors


def manage_home():
    return url_for("admin_products") if session["role"] == "admin" else url_for("seller_dashboard")


def product_or_redirect(pid):
    """Sellers may only touch their own products; admins may touch all."""
    p = get_db().execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if not p:
        abort(404)
    if session["role"] != "admin" and p["seller_id"] != session["user_id"]:
        return None, redirect(manage_home())
    return p, None


# ---------- Seller / Admin: product management ----------
def manage_page(rows, title, show_seller):
    stats = {"count": len(rows), "units": sum(r["stock"] for r in rows),
             "out": sum(1 for r in rows if r["stock"] == 0)}
    return render_template("manage_products.html", products=rows, title=title,
                           show_seller=show_seller, stats=stats)


@app.route("/seller/dashboard")
@role_required("seller")
def seller_dashboard():
    rows = get_db().execute("SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC",
                            (session["user_id"],)).fetchall()
    return manage_page(rows, "Seller Dashboard - My Products", False)


@app.route("/admin/products")
@role_required("admin")
def admin_products():
    rows = get_db().execute(
        "SELECT p.*, u.full_name AS seller_name FROM products p JOIN users u ON u.id = p.seller_id "
        "ORDER BY p.id DESC").fetchall()
    return manage_page(rows, "All Products", True)


@app.route("/products/new", methods=["GET", "POST"])
@role_required("seller", "admin")
def product_new():
    values = {"name": "", "description": "", "price": "", "stock": ""}
    if request.method == "POST":
        values, price, stock, errors = parse_product_form(request.form)
        data, ext, img_err = read_image(request.files.get("image"))  # image is required
        if img_err:
            errors.append(img_err)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            filename = write_image(data, ext)
            db = get_db()
            db.execute("INSERT INTO products (seller_id, name, description, price, stock, image_filename, created_at) "
                       "VALUES (?,?,?,?,?,?,?)",
                       (session["user_id"], values["name"], values["description"], price, stock,
                        filename, now().isoformat()))
            db.commit()
            flash(f"Product '{values['name']}' registered.", "success")
            return redirect(manage_home())
    return render_template("product_form.html", product=None, values=values)


@app.route("/products/<int:pid>/edit", methods=["GET", "POST"])
@role_required("seller", "admin")
def product_edit(pid):
    product, deny = product_or_redirect(pid)
    if deny:
        flash("You can only manage your own products.", "error")
        return deny
    values = {"name": product["name"], "description": product["description"],
              "price": f"{product['price']:g}", "stock": str(product["stock"])}
    if request.method == "POST":
        values, price, stock, errors = parse_product_form(request.form)
        data = ext = None
        new_file = request.files.get("image")
        if new_file and new_file.filename:  # image is optional when editing
            data, ext, img_err = read_image(new_file)
            if img_err:
                errors.append(img_err)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            filename = product["image_filename"]
            if data:
                filename = write_image(data, ext)
            db = get_db()
            db.execute("UPDATE products SET name=?, description=?, price=?, stock=?, image_filename=? WHERE id=?",
                       (values["name"], values["description"], price, stock, filename, pid))
            db.commit()
            if data:
                delete_image(product["image_filename"])
            flash("Product updated.", "success")
            return redirect(manage_home())
    return render_template("product_form.html", product=product, values=values)


@app.route("/products/<int:pid>/delete", methods=["POST"])
@role_required("seller", "admin")
def product_delete(pid):
    product, deny = product_or_redirect(pid)
    if deny:
        flash("You can only manage your own products.", "error")
        return deny
    db = get_db()
    db.execute("DELETE FROM products WHERE id = ?", (pid,))  # cart rows cascade; order history keeps the name
    db.commit()
    delete_image(product["image_filename"])
    flash(f"Product '{product['name']}' deleted.", "success")
    return redirect(manage_home())


# ---------- Buyer: catalog ----------
@app.route("/buyer/dashboard")
@role_required("buyer")
def buyer_dashboard():
    q = request.args.get("q", "").strip()
    if q:
        rows = get_db().execute("SELECT * FROM products WHERE name LIKE ? ORDER BY id DESC",
                                (f"%{q}%",)).fetchall()
    else:
        rows = get_db().execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("buyer_dashboard.html", products=rows, q=q)


@app.route("/product/<int:pid>")
def product_detail(pid):
    p = get_db().execute("SELECT p.*, u.full_name AS seller_name FROM products p "
                         "JOIN users u ON u.id = p.seller_id WHERE p.id = ?", (pid,)).fetchone()
    if not p:
        abort(404)
    return render_template("product_detail.html", p=p)


# ---------- Buyer: shopping cart (stored in the database -> survives refresh/logout) ----------
def cart_items(db, uid):
    return db.execute(
        "SELECT c.product_id, c.quantity, p.name, p.price, p.stock, p.image_filename, p.seller_id "
        "FROM cart_items c JOIN products p ON p.id = c.product_id "
        "WHERE c.user_id = ? ORDER BY c.rowid", (uid,)).fetchall()


def cart_totals(db, uid):
    row = db.execute(
        "SELECT COALESCE(SUM(c.quantity),0) AS n, COALESCE(SUM(c.quantity * p.price),0) AS total "
        "FROM cart_items c JOIN products p ON p.id = c.product_id WHERE c.user_id = ?", (uid,)).fetchone()
    return row["n"], round(row["total"], 2)


def cart_reply(db, ok, message, pid=None, removed=False):
    """JSON for the live (AJAX) cart; flash + redirect for plain form posts."""
    uid = session["user_id"]
    count, total = cart_totals(db, uid)
    if request.headers.get("X-Requested-With") == "fetch":
        data = {"ok": ok, "message": message, "count": count, "total": total,
                "total_fmt": fmt_money(total), "removed": removed}
        if pid is not None and not removed:
            row = db.execute("SELECT c.quantity, p.price, p.stock FROM cart_items c "
                             "JOIN products p ON p.id = c.product_id WHERE c.user_id = ? AND c.product_id = ?",
                             (uid, pid)).fetchone()
            if row:
                data.update(quantity=row["quantity"], stock=row["stock"],
                            subtotal_fmt=fmt_money(row["quantity"] * row["price"]))
        return jsonify(data)
    flash(message, "success" if ok else "error")
    return redirect(request.referrer or url_for("cart_view"))


@app.route("/cart")
@role_required("buyer")
def cart_view():
    db = get_db()
    items = cart_items(db, session["user_id"])
    count, total = cart_totals(db, session["user_id"])
    return render_template("cart.html", items=items, count=count, total=total)


@app.route("/cart/add", methods=["POST"])
@role_required("buyer")
def cart_add():
    db, uid = get_db(), session["user_id"]
    pid = request.form.get("product_id", type=int)
    p = db.execute("SELECT id, name, stock FROM products WHERE id = ?", (pid,)).fetchone()
    if not p:
        return cart_reply(db, False, "That product no longer exists.")
    if p["stock"] <= 0:
        return cart_reply(db, False, f"Sorry, {p['name']} is out of stock.")
    row = db.execute("SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?", (uid, pid)).fetchone()
    have = row["quantity"] if row else 0
    if have + 1 > p["stock"]:
        return cart_reply(db, False, f"Only {p['stock']} unit(s) of {p['name']} available - "
                                     f"you already have {have} in your cart.", pid)
    if row:
        db.execute("UPDATE cart_items SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?", (uid, pid))
    else:
        db.execute("INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?,?,1)", (uid, pid))
    db.commit()
    return cart_reply(db, True, f"{p['name']} added to your cart.", pid)


@app.route("/cart/update", methods=["POST"])
@role_required("buyer")
def cart_update():
    db, uid = get_db(), session["user_id"]
    pid = request.form.get("product_id", type=int)
    qty = request.form.get("quantity", type=int)
    row = db.execute("SELECT c.quantity, p.name, p.stock FROM cart_items c JOIN products p ON p.id = c.product_id "
                     "WHERE c.user_id = ? AND c.product_id = ?", (uid, pid)).fetchone()
    if not row:
        return cart_reply(db, False, "That item is not in your cart.")
    if qty is None or qty < 1:
        return cart_reply(db, False, "Quantity must be at least 1. Use the trash icon to remove an item.", pid)
    if qty > row["stock"]:
        return cart_reply(db, False, f"Only {row['stock']} unit(s) of {row['name']} in stock.", pid)
    db.execute("UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?", (qty, uid, pid))
    db.commit()
    return cart_reply(db, True, "Cart updated.", pid)


@app.route("/cart/remove", methods=["POST"])
@role_required("buyer")
def cart_remove():
    db, uid = get_db(), session["user_id"]
    pid = request.form.get("product_id", type=int)
    db.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (uid, pid))
    db.commit()
    return cart_reply(db, True, "Item removed from your cart.", pid, removed=True)


# ---------- Checkout ----------
VAT_RATE = 0.18  # Rwanda VAT - product prices already include it
SHIPPING_FEE = float(os.environ.get("SHIPPING_FEE", "2000"))
PAYMENT_LABELS = {
    "card": "Card (Visa / Mastercard)",
    "momo": "MTN MoMo",
    "cod": "Cash on Delivery (COD)",
}
PAYMENT_STATUS = {"card": "Paid (simulated)", "momo": "Paid via MTN MoMo (simulated)", "cod": "Pay on delivery"}
DISTRICTS = [
    "Gasabo", "Kicukiro", "Nyarugenge",                                                       # Kigali
    "Burera", "Gakenke", "Gicumbi", "Musanze", "Rulindo",                                     # North
    "Gisagara", "Huye", "Kamonyi", "Muhanga", "Nyamagabe", "Nyanza", "Nyaruguru", "Ruhango",  # South
    "Bugesera", "Gatsibo", "Kayonza", "Kirehe", "Ngoma", "Nyagatare", "Rwamagana",            # East
    "Karongi", "Ngororero", "Nyabihu", "Nyamasheke", "Rubavu", "Rusizi", "Rutsiro",           # West
]
PHONE_RE = re.compile(r"^(?:\+?250|0)7[2389]\d{7}$")   # MTN / Airtel Rwanda
MOMO_RE = re.compile(r"^(?:\+?250|0)7[89]\d{7}$")      # MTN Rwanda
app.jinja_env.filters["payment_label"] = lambda k: PAYMENT_LABELS.get(k, k or "-")


def normalize_phone(raw, rx):
    cleaned = re.sub(r"[\s\-()]", "", raw or "")
    return "+250" + cleaned[-9:] if rx.match(cleaned) else None


def order_totals(subtotal):
    total = round(subtotal + SHIPPING_FEE, 2)
    tax = round(total * VAT_RATE / (1 + VAT_RATE), 2)  # tax already included in the price
    return {"subtotal": round(subtotal, 2), "shipping": SHIPPING_FEE, "total": total, "tax": tax}


def place_order(db, uid, d):
    """Atomically take the stock (Stock Out), save the order and empty the cart.
    Returns (order_id, error_message)."""
    try:
        db.execute("BEGIN IMMEDIATE")  # lock so two buyers cannot take the last unit together
        rows = cart_items(db, uid)
        if not rows:
            db.rollback()
            return None, "Your cart is empty."
        short = []
        for r in rows:
            cur = db.execute("UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?",
                             (r["quantity"], r["product_id"], r["quantity"]))
            if cur.rowcount == 0:
                short.append(r["name"])
        if short:
            db.rollback()
            return None, "Not enough stock for: " + ", ".join(short) + ". Please adjust your quantities."
        t = order_totals(sum(r["quantity"] * r["price"] for r in rows))
        oid = db.execute(
            "INSERT INTO orders (user_id, total, created_at, subtotal, shipping, tax, contact_email, contact_phone, "
            "ship_name, ship_address, ship_district, ship_city, payment_method, payment_status, momo_number) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, t["total"], now().isoformat(), t["subtotal"], t["shipping"], t["tax"], d["email"], d["phone"],
             d["ship_name"], d["address"], d["district"], d["city"], d["payment"],
             PAYMENT_STATUS[d["payment"]], d.get("momo"))).lastrowid
        db.executemany("INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, "
                       "seller_id, status) VALUES (?,?,?,?,?,?,'Placed')",
                       [(oid, r["product_id"], r["name"], r["price"], r["quantity"], r["seller_id"]) for r in rows])
        db.execute("DELETE FROM cart_items WHERE user_id = ?", (uid,))
        db.commit()
        return oid, None
    except Exception:
        db.rollback()
        app.logger.exception("Checkout failed")
        return None, "Checkout failed. Please try again."


@app.route("/checkout", methods=["GET", "POST"])
@role_required("buyer")
def checkout():
    db, uid = get_db(), session["user_id"]
    items = cart_items(db, uid)
    if not items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart_view"))
    bad = [i["name"] for i in items if i["quantity"] > i["stock"]]
    if bad:
        flash("Please adjust your cart first - not enough stock for: " + ", ".join(bad) + ".", "error")
        return redirect(url_for("cart_view"))
    totals = order_totals(sum(i["quantity"] * i["price"] for i in items))

    user = db.execute("SELECT full_name, email FROM users WHERE id = ?", (uid,)).fetchone()
    parts = user["full_name"].split(None, 1)
    values = {"email": user["email"], "phone": "", "first_name": parts[0] if parts else "",
              "last_name": parts[1] if len(parts) > 1 else "", "address": "", "district": "",
              "city": "", "payment": "card", "momo": ""}
    if request.method == "POST":
        for k in values:
            values[k] = request.form.get(k, "").strip()
        values["email"] = user["email"]  # always the verified account email, never a typed-in address
        errors = []
        if not EMAIL_RE.match(values["email"].lower()):
            errors.append("Enter a valid email address.")
        phone = normalize_phone(values["phone"], PHONE_RE)
        if not phone:
            errors.append("Enter a valid Rwandan phone number, for example 0788 123 456.")
        if len(values["first_name"]) < 2 or len(values["last_name"]) < 2:
            errors.append("Enter your first name and last name.")
        if len(values["address"]) < 5:
            errors.append("Enter your delivery address (street, house number or landmark).")
        if values["district"] not in DISTRICTS:
            errors.append("Choose your district.")
        if len(values["city"]) < 2:
            errors.append("Enter your city or sector.")
        if values["payment"] not in PAYMENT_LABELS:
            errors.append("Choose a payment method.")
        momo = None
        if values["payment"] == "momo":
            momo = normalize_phone(values["momo"], MOMO_RE)
            if not momo:
                errors.append("Enter a valid MTN MoMo number (starting 078 or 079).")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            details = {"email": values["email"].lower(), "phone": phone, "address": values["address"],
                       "ship_name": f"{values['first_name']} {values['last_name']}", "district": values["district"],
                       "city": values["city"], "payment": values["payment"], "momo": momo}
            oid, err = place_order(db, uid, details)
            if err:
                flash(err, "error")
                return redirect(url_for("cart_view"))
            lines = "\n".join(f"- {i['name']} x {i['quantity']}: {fmt_money(i['quantity'] * i['price'])}"
                              for i in items)
            send_email(details["email"], f"Your ShopHub order #{oid}",
                       f"Hello {values['first_name']},\n\nThank you for your order #{oid}.\n\n{lines}\n\n"
                       f"Delivery: {fmt_money(totals['shipping'])}\nTotal: {fmt_money(totals['total'])} "
                       f"(including {fmt_money(totals['tax'])} in taxes)\nPayment: {PAYMENT_LABELS[details['payment']]}"
                       f" - {PAYMENT_STATUS[details['payment']]}\n\nWe will deliver to: {details['address']}, "
                       f"{details['city']}, {details['district']}.\n\nThis is a demo store: no real payment was taken.",
                       "<p>Thank you for your order <strong>#%d</strong>.</p><p>Total: <strong>%s</strong></p>"
                       "<p>You can see the full details under <em>My Orders</em> on ShopHub.</p>"
                       "<p><small>This is a demo store: no real payment was taken.</small></p>"
                       % (oid, fmt_money(totals["total"])))
            flash(f"Thank you! Your order #{oid} has been placed.", "success")
            return redirect(url_for("order_detail", oid=oid))
    return render_template("checkout.html", items=items, totals=totals, values=values,
                           districts=DISTRICTS, payment_labels=PAYMENT_LABELS)


@app.route("/orders")
@role_required("buyer")
def orders():
    db = get_db()
    result = []
    for o in db.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (session["user_id"],)):
        items = db.execute("SELECT * FROM order_items WHERE order_id = ?", (o["id"],)).fetchall()
        result.append({"order": o, "items": items,
                       "status": derive_status(o["status"], [i["status"] for i in items])})
    return render_template("orders.html", orders=result)


@app.route("/orders/<int:oid>")
@role_required("buyer")
def order_detail(oid):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (oid, session["user_id"])).fetchone()
    if not o:
        abort(404)
    items = db.execute("SELECT * FROM order_items WHERE order_id = ?", (oid,)).fetchall()
    return render_template("order_detail.html", o=o, items=items,
                           status=derive_status(o["status"], [i["status"] for i in items]))


ORDER_STEPS = {"Shipped": "Placed", "Delivered": "Shipped"}   # new item status -> status it must have now


def derive_status(order_status, item_statuses):
    """One status for the whole order, worked out from its lines."""
    if (order_status or "Placed") == "Cancelled":
        return "Cancelled"
    st = [x or "Placed" for x in item_statuses]
    if not st:
        return "Placed"
    if all(x == "Delivered" for x in st):
        return "Delivered"
    if all(x in ("Shipped", "Delivered") for x in st):
        return "Shipped"
    if any(x in ("Shipped", "Delivered") for x in st):
        return "Partially shipped"
    return "Placed"


def cancel_order(db, oid, user_id=None):
    """Cancel an order that nobody has shipped yet: stock goes back, payment is marked refunded.
    Returns (result, order) where result is ok / notfound / already / shipped / error."""
    sql, args = "SELECT * FROM orders WHERE id = ?", [oid]
    if user_id is not None:
        sql += " AND user_id = ?"
        args.append(user_id)
    o = db.execute(sql, args).fetchone()
    if not o:
        return "notfound", None
    if (o["status"] or "Placed") == "Cancelled":
        return "already", o
    try:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT COUNT(*) FROM order_items WHERE order_id = ? AND COALESCE(status,'Placed') != 'Placed'",
                      (oid,)).fetchone()[0]:
            db.rollback()
            return "shipped", o
        cur = db.execute("UPDATE orders SET status = 'Cancelled', cancelled_at = ?, payment_status = ? "
                         "WHERE id = ? AND COALESCE(status, 'Placed') = 'Placed'",
                         (now().isoformat(),
                          "Cancelled - nothing to pay" if o["payment_method"] == "cod" else "Refunded (simulated)",
                          oid))
        if cur.rowcount == 0:  # cancelled a moment ago elsewhere: never restore stock twice
            db.rollback()
            return "already", o
        for it in db.execute("SELECT product_id, quantity FROM order_items WHERE order_id = ?", (oid,)).fetchall():
            if it["product_id"] is not None:  # product may have been deleted by its seller since
                db.execute("UPDATE products SET stock = stock + ? WHERE id = ?", (it["quantity"], it["product_id"]))
        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Cancel failed")
        return "error", o
    if o["contact_email"]:
        send_email(o["contact_email"], f"Your ShopHub order #{oid} was cancelled",
                   f"Your order #{oid} has been cancelled and the items were returned to stock.\n"
                   + ("No payment is due." if o["payment_method"] == "cod" else
                      "Your payment will be refunded (demo store: no real money was taken)."),
                   f"<p>Your order <strong>#{oid}</strong> has been cancelled.</p>")
    return "ok", o


CANCEL_MESSAGES = {
    "already": "This order has already been cancelled.",
    "shipped": "This order has already been shipped, so it can no longer be cancelled. "
               "Please see our Return Policy.",
    "error": "Could not cancel the order. Please try again.",
}


@app.route("/orders/<int:oid>/cancel", methods=["POST"])
@role_required("buyer")
def order_cancel(oid):
    result, _o = cancel_order(get_db(), oid, session["user_id"])
    if result == "notfound":
        abort(404)
    if result == "ok":
        flash(f"Order #{oid} has been cancelled.", "success")
    else:
        flash(CANCEL_MESSAGES[result], "error")
    return redirect(url_for("order_detail", oid=oid))


@app.route("/orders/<int:oid>/delete", methods=["POST"])
@role_required("buyer")
def order_delete(oid):
    """Remove a CANCELLED order from the buyer's history (active orders must be cancelled first)."""
    db = get_db()
    o = db.execute("SELECT status FROM orders WHERE id = ? AND user_id = ?", (oid, session["user_id"])).fetchone()
    if not o:
        abort(404)
    if (o["status"] or "Placed") != "Cancelled":
        flash("Only cancelled orders can be deleted. Cancel the order first.", "error")
        return redirect(url_for("order_detail", oid=oid))
    db.execute("DELETE FROM orders WHERE id = ?", (oid,))  # its items are removed too (ON DELETE CASCADE)
    db.commit()
    flash(f"Order #{oid} was deleted from your history.", "success")
    return redirect(url_for("orders"))


# ---------- Seller / Admin: orders and fulfilment ----------
def orders_home():
    return url_for("admin_orders") if session["role"] == "admin" else url_for("seller_orders")


@app.route("/seller/orders")
@role_required("seller")
def seller_orders():
    """Orders that contain this seller's products (only this seller's lines are shown)."""
    db, uid = get_db(), session["user_id"]
    groups = []
    for o in db.execute("SELECT DISTINCT o.*, u.full_name AS buyer_name FROM orders o "
                        "JOIN order_items i ON i.order_id = o.id JOIN users u ON u.id = o.user_id "
                        "WHERE i.seller_id = ? ORDER BY o.id DESC", (uid,)).fetchall():
        items = db.execute("SELECT * FROM order_items WHERE order_id = ? AND seller_id = ?", (o["id"], uid)).fetchall()
        groups.append({"order": o, "items": items,
                       "status": derive_status(o["status"], [i["status"] for i in items]),
                       "mine_total": sum(i["unit_price"] * i["quantity"] for i in items)})
    return render_template("seller_orders.html", groups=groups)


@app.route("/admin/orders")
@role_required("admin")
def admin_orders():
    db = get_db()
    wanted = request.args.get("status", "")
    groups = []
    for o in db.execute("SELECT o.*, u.full_name AS buyer_name, u.email AS buyer_email FROM orders o "
                        "JOIN users u ON u.id = o.user_id ORDER BY o.id DESC LIMIT 300").fetchall():
        items = db.execute("SELECT i.*, u.full_name AS seller_name FROM order_items i "
                           "LEFT JOIN users u ON u.id = i.seller_id WHERE i.order_id = ?", (o["id"],)).fetchall()
        status = derive_status(o["status"], [i["status"] for i in items])
        if wanted and status != wanted:
            continue
        groups.append({"order": o, "items": items, "status": status})
    return render_template("admin_orders.html", groups=groups, wanted=wanted,
                           statuses=["Placed", "Partially shipped", "Shipped", "Delivered", "Cancelled"])


@app.route("/orders/<int:oid>/fulfil", methods=["POST"])
@role_required("seller", "admin")
def order_fulfil(oid):
    """Mark lines as Shipped or Delivered. Sellers move only their own lines; admins move all lines."""
    new = request.form.get("status", "")
    if new not in ORDER_STEPS:
        abort(400)
    db, uid, role = get_db(), session["user_id"], session["role"]
    try:
        db.execute("BEGIN IMMEDIATE")  # same lock as cancelling, so a cancelled order is never shipped
        o = db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
        if not o:
            db.rollback()
            abort(404)
        if (o["status"] or "Placed") == "Cancelled":
            db.rollback()
            flash("This order was cancelled and cannot be updated.", "error")
            return redirect(orders_home())
        sql, args = "SELECT * FROM order_items WHERE order_id = ?", [oid]
        if role == "seller":
            sql += " AND seller_id = ?"
            args.append(uid)
        items = db.execute(sql, args).fetchall()
        if not items:
            db.rollback()
            flash("That order has none of your products.", "error")
            return redirect(orders_home())
        movable = [i["id"] for i in items if (i["status"] or "Placed") == ORDER_STEPS[new]]
        if not movable:
            db.rollback()
            flash("Nothing to update: items must be marked Shipped before Delivered, and each step happens once.", "error")
            return redirect(orders_home())
        db.executemany("UPDATE order_items SET status = ? WHERE id = ?", [(new, i) for i in movable])
        all_status = [r[0] for r in db.execute("SELECT status FROM order_items WHERE order_id = ?", (oid,))]
        if new == "Delivered" and derive_status(None, all_status) == "Delivered" and o["payment_method"] == "cod":
            db.execute("UPDATE orders SET payment_status = 'Paid (cash on delivery)' WHERE id = ?", (oid,))
        db.commit()
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        app.logger.exception("Order update failed")
        flash("Could not update the order. Please try again.", "error")
        return redirect(orders_home())
    if o["contact_email"]:
        word = "shipped" if new == "Shipped" else "delivered"
        send_email(o["contact_email"], f"Your ShopHub order #{oid} was {word}",
                   f"Good news: your order #{oid} has been {word}.\nYou can follow it under My Orders.",
                   f"<p>Your order <strong>#{oid}</strong> has been {word}.</p>")
    flash(f"Order #{oid} marked as {new.lower()}.", "success")
    return redirect(orders_home())


@app.route("/admin/orders/<int:oid>/cancel", methods=["POST"])
@role_required("admin")
def admin_order_cancel(oid):
    result, _o = cancel_order(get_db(), oid)
    if result == "notfound":
        abort(404)
    if result == "ok":
        flash(f"Order #{oid} has been cancelled and its stock restored.", "success")
    else:
        flash(CANCEL_MESSAGES[result], "error")
    return redirect(url_for("admin_orders"))


# ================= Site-wide info (footer) and public pages =================
def _site():
    phone = os.environ.get("CONTACT_PHONE", "").strip()
    digits = re.sub(r"\D", "", phone)
    email = os.environ.get("CONTACT_EMAIL") or os.environ.get("MAIL_USERNAME", "")
    social = {k: os.environ.get(f"SOCIAL_{k.upper()}") or "#" for k in ("instagram", "tiktok")}
    whatsapp = f"https://wa.me/{digits}" if digits else "#"
    chat = whatsapp if digits else (f"mailto:{email}" if email else "#")
    return {"name": "ShopHub", "phone": phone, "email": email, "social": social,
            "whatsapp": whatsapp, "chat": chat, "year": now().year}


@app.context_processor
def inject_site():
    return {"site": _site(), "social_enabled": ENABLED_PROVIDERS}


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/returns")
def returns():
    return render_template("returns.html")


CONTACT_LOG = []


def contact_allowed():
    cutoff = time.time() - 3600
    CONTACT_LOG[:] = [t for t in CONTACT_LOG if t > cutoff]
    if len(CONTACT_LOG) >= 20:
        return False
    CONTACT_LOG.append(time.time())
    return True


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = {"name": session.get("name", ""), "email": "", "message": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("name", "email", "message")}
        errors = []
        if len(form["name"]) < 2:
            errors.append("Please enter your name.")
        if not EMAIL_RE.match(form["email"]):
            errors.append("Enter a valid email address.")
        if not 10 <= len(form["message"]) <= 2000:
            errors.append("Your message must be between 10 and 2000 characters.")
        if not _site()["email"]:
            errors.append("The contact form is not configured yet. Please try again later.")
        if not errors and time.time() - session.get("contact_ts", 0) < 60:
            errors.append("Please wait a minute before sending another message.")
        if not errors and not contact_allowed():  # overall cap so the form cannot be used to spam anyone
            errors.append("We are receiving many messages right now. Please try again later.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            session["contact_ts"] = time.time()
            esc = lambda v: v.replace("&", "&amp;").replace("<", "&lt;")
            # 1) to the shop: pressing Reply in Gmail answers the visitor directly
            send_email(_site()["email"], f"ShopHub contact form: {form['name']}",
                       f"From: {form['name']} <{form['email']}>\n\n{form['message']}",
                       "<p><strong>From:</strong> %s &lt;%s&gt;</p><p>%s</p>" % (
                           esc(form["name"]), esc(form["email"]), esc(form["message"]).replace("\n", "<br>")),
                       reply_to=form["email"])
            # 2) to the visitor: confirmation from the ShopHub account
            send_email(form["email"], "We received your message - ShopHub",
                       f"Hello {form['name']},\n\nThank you for contacting ShopHub. We received your message and "
                       f"will reply by email as soon as we can.\n\nYour message:\n{form['message']}\n\n"
                       "If you did not write to us, you can ignore this email.",
                       "<p>Hello %s,</p><p>Thank you for contacting <strong>ShopHub</strong>. We received your "
                       "message and will reply by email as soon as we can.</p><blockquote>%s</blockquote>"
                       "<p><small>If you did not write to us, you can ignore this email.</small></p>" % (
                           esc(form["name"]), esc(form["message"]).replace("\n", "<br>")))
            flash(f"Thank you! Your message was received. A confirmation email is on its way to {form['email']} - "
                  "check your inbox (and Spam) in a minute. We will reply by email.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html", form=form)


if __name__ == "__main__":
    init_db()
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = host in ("127.0.0.1", "localhost") and os.environ.get("FLASK_DEBUG", "true").lower() in (
        "1", "true", "yes", "on")
    app.run(host=host, port=port, debug=debug)
