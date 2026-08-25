"""
Vulnerable Web Lab — A realistic training target for SQLi, XSS & File Upload.

Usage:
    python app.py --easy
    python app.py --medium
    python app.py --hard
    python app.py --reset          # wipe and reseed the database
    python app.py --host 0.0.0.0   # bind to all interfaces (lab network only!)
"""

import argparse
import os
import sqlite3
import uuid
import subprocess
import platform
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, flash, abort, make_response,
)

from difficulty import sanitize_sql, filter_xss, check_upload, idor_requires_login, idor_uses_uuid
from seed import seed_database, DB_PATH
from mysql_sim import build_product_select, simulate_mysql_error

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "vulnlab-super-secret-key-change-in-prod-just-kidding"

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- Request Logger: stores incoming requests with source IP ---
REQUEST_LOG = []
MAX_LOG_ENTRIES = 500


@app.before_request
def log_request():
    """Log every incoming request with IP, timestamp, and path."""
    entry = {
        "ip": request.remote_addr,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "method": request.method,
        "path": request.full_path,
        "ua": request.headers.get("User-Agent", "-"),
    }
    REQUEST_LOG.insert(0, entry)
    if len(REQUEST_LOG) > MAX_LOG_ENTRIES:
        REQUEST_LOG.pop()


@app.context_processor
def inject_difficulty():
    """Make difficulty level and helper functions available in all templates."""
    return {
        'difficulty': get_level(),
        'idor_uses_uuid': idor_uses_uuid(get_level()),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_level():
    """Return the current difficulty level from app config."""
    return app.config.get("DIFFICULTY", "easy")


def ensure_db():
    """Create the database if it doesn't exist."""
    if not os.path.exists(DB_PATH):
        seed_database(DB_PATH)


# ---------------------------------------------------------------------------
# Routes — Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("home"))


@app.route("/home.html")
def home():
    db = get_db()
    products = db.execute(
        "SELECT * FROM products ORDER BY RANDOM() LIMIT 6"
    ).fetchall()
    categories = db.execute("SELECT * FROM categories").fetchall()
    db.close()
    return render_template("home.html", products=products, categories=categories)


@app.route("/product.html")
def product():
    product_id = request.args.get("id", "")
    # SQLi: Vulnerable — string concatenation, no parameterized query
    level = get_level()
    filtered_id = sanitize_sql(product_id, level)

    db = get_db()
    error_msg = None

    try:
        # VULNERABLE: raw string concatenation
        # Different product IDs use different column counts to confuse UNION-based SQLi
        query, col_count = build_product_select(filtered_id)
        result = db.execute(query).fetchone()

        if result:
            # Get category name
            cat_row = db.execute(
                f"SELECT name FROM categories WHERE id = '{result['category_id']}'"
            ).fetchone()
            category_name = cat_row["name"] if cat_row else "Unknown"

            # Get comments for this product
            comments = db.execute("""
                SELECT c.content, c.id as comment_id, u.username
                FROM comments c
                JOIN users u ON c.user_id = u.id
                WHERE c.product_id = ?
                ORDER BY c.id DESC
            """, [result["id"]]).fetchall()

            db.close()
            return render_template(
                "product.html",
                product=result,
                category_name=category_name,
                comments=comments,
            )
        else:
            db.close()
            return render_template("product.html", product=None)

    except Exception as e:
        db.close()
        # Try MySQL error simulation first (for SQLi training payloads)
        raw_id = request.args.get("id", "")
        mysql_err = simulate_mysql_error(str(e), raw_id)
        if mysql_err:
            return render_template("product.html", product=None, error=mysql_err)
        # At easy: show full error. At medium+: show generic message.
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while processing your request."
        return render_template("product.html", product=None, error=error_msg)


@app.route("/category.html")
def category():
    cat_id = request.args.get("cat_id", "")
    level = get_level()
    filtered_id = sanitize_sql(cat_id, level)

    db = get_db()
    error_msg = None

    try:
        # VULNERABLE: string concatenation for UNION-based SQLi
        query = f"SELECT * FROM products WHERE category_id = '{filtered_id}'"
        products = db.execute(query).fetchall()

        # Get category info
        cat_query = f"SELECT * FROM categories WHERE id = '{filtered_id}'"
        category = db.execute(cat_query).fetchone()

        db.close()
        return render_template(
            "category.html",
            products=products,
            category=category,
        )

    except Exception as e:
        db.close()
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while processing your request."
        return render_template(
            "category.html", products=[], category=None, error=error_msg
        )




@app.route("/user.html")
def user_view():
    name = request.args.get("name", "")
    level = get_level()
    filtered_name = sanitize_sql(name, level)

    db = get_db()
    error_msg = None

    try:
        # VULNERABLE: string concatenation
        query = f"SELECT * FROM users WHERE username = '{filtered_name}'"
        user = db.execute(query).fetchone()

        db.close()
        return render_template("user.html", user=user)

    except Exception as e:
        db.close()
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while processing your request."
        return render_template("user.html", user=None, error=error_msg)


@app.route("/members")
def members():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY username").fetchall()
    db.close()
    return render_template("members.html", users=users)


# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    level = get_level()

    # Apply SQL filter
    filtered_user = sanitize_sql(username, level)
    filtered_pass = sanitize_sql(password, level)

    db = get_db()
    error_msg = None

    try:
        # VULNERABLE: string concatenation — classic auth bypass target
        query = (
            f"SELECT * FROM users WHERE username = '{filtered_user}' "
            f"AND password = '{filtered_pass}'"
        )
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            session["user_uuid"] = user["uuid"]
            db.close()
            return redirect(url_for("home"))
        else:
            db.close()
            # At easy: show SQL errors. At medium+: generic message.
            if level == "easy":
                # At easy level, show detailed SQL errors to the student
                try:
                    # Re-run to get the specific error for display
                    db2 = get_db()
                    db2.execute(query)
                    db2.close()
                except Exception as inner_e:
                    error_msg = f"Login failed: {str(inner_e)}"
                if not error_msg:
                    error_msg = "Invalid username or password."
            else:
                error_msg = "Invalid username or password."
            return render_template("login.html", error=error_msg)

    except Exception as e:
        db.close()
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred during login."
        return render_template("login.html", error=error_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password2 = request.form.get("password2", "")
    phone = request.form.get("phone", "")

    if password != password2:
        return render_template("register.html", error="Passwords do not match.")

    if len(username) < 3 or len(password) < 4:
        return render_template(
            "register.html",
            error="Username must be 3+ chars, password 4+ chars.",
        )

    # Server-side: phone must be exactly 10 digits
    if not phone.isdigit() or len(phone) != 10:
        resp = make_response(
            render_template("register.html",
                            error=f"Phone number must be exactly 10 digits — got {len(phone)} digits."),
            500,
        )
        return resp

    db = get_db()
    try:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            db.close()
            return render_template(
                "register.html", error="Username already taken."
            )

        new_uuid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (uuid, username, password, phone) VALUES (?, ?, ?, ?)",
            (new_uuid, username, password, phone),
        )
        db.commit()
        db.close()
        return render_template(
            "login.html", success="Account created! You can now log in."
        )
    except sqlite3.IntegrityError as e:
        db.close()
        return render_template(
            "register.html",
            error=f"Registration failed: {str(e)}",
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Routes — Profile & Deface (Stored XSS)
# ---------------------------------------------------------------------------

@app.route("/profile")
def profile():
    user_id = request.args.get("id", "")
    level = get_level()

    # IDOR: access control varies by difficulty tier
    if idor_requires_login(level):
        # Medium/Hard: require a login session, but NO ownership check
        # (any authenticated user can view any profile by changing ?id=)
        if not session.get("user_id"):
            return redirect(url_for("login"))

    # IDOR: at hard tier, IDs are UUIDs instead of sequential integers
    if idor_uses_uuid(level):
        # Look up by UUID column instead of integer id
        filtered_id = sanitize_sql(user_id, level)
        query = f"SELECT * FROM users WHERE uuid = '{filtered_id}'"
    else:
        # Easy/Medium: sequential integer IDs
        filtered_id = sanitize_sql(user_id, level)
        query = f"SELECT * FROM users WHERE id = '{filtered_id}'"

    db = get_db()
    try:
        user = db.execute(query).fetchone()
    except Exception:
        user = None

    is_own = (
        user and session.get("user_id") and user["id"] == session["user_id"]
    )
    db.close()
    return render_template(
        "profile.html", user=user, is_own=is_own, success=None, error=None
    )


@app.route("/profile/update", methods=["POST"])
def profile_update():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    bio_raw = request.form.get("bio", "")
    level = get_level()

    # Apply XSS filter to the bio before storing
    bio_filtered = filter_xss(bio_raw, level)

    db = get_db()
    db.execute(
        "UPDATE users SET bio = ? WHERE id = ?",
        (bio_filtered, session["user_id"]),
    )
    db.commit()

    # Re-fetch user
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    db.close()

    return render_template(
        "profile.html",
        user=user,
        is_own=True,
        success="Profile updated!",
        error=None,
    )


# ---------------------------------------------------------------------------
# Routes — Comments (Stored XSS)
# ---------------------------------------------------------------------------

@app.route("/comment", methods=["POST"])
def add_comment():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    product_id = request.form.get("product_id", "")
    content_raw = request.form.get("content", "")
    level = get_level()

    # Apply XSS filter before storing
    content_filtered = filter_xss(content_raw, level)

    db = get_db()
    db.execute(
        "INSERT INTO comments (user_id, product_id, content) VALUES (?, ?, ?)",
        (session["user_id"], product_id, content_filtered),
    )
    db.commit()
    db.close()

    return redirect(url_for("product", id=product_id))


# ---------------------------------------------------------------------------
# Routes — Admin (SQLi auth-bypass target)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Routes - Leaky API (IDOR hard-tier UUID discovery)
# ---------------------------------------------------------------------------

@app.route('/api/users/search')
def api_users_search():
    """Leaky autocomplete endpoint - returns UUIDs even though the UI never shows them.
    Hard-tier IDOR: students discover valid UUIDs here to use on /profile?id=
    """
    q = request.args.get('q', '')
    level = get_level()

    if not q:
        return {'users': []}

    db = get_db()
    # VULNERABLE: returns uuid field even though it is hidden from the UI
    users = db.execute(
        'SELECT id, uuid, username FROM users WHERE username LIKE ?',
        ('%' + q + '%',)
    ).fetchall()
    db.close()

    return {
        'users': [
            {'id': u['id'], 'uuid': u['uuid'], 'username': u['username']}
            for u in users
        ]
    }


@app.route("/admin")
def admin():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    db = get_db()

    if session.get("is_admin"):
        stats = {
            "users": db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"],
            "products": db.execute("SELECT COUNT(*) as c FROM products").fetchone()["c"],
            "categories": db.execute("SELECT COUNT(*) as c FROM categories").fetchone()["c"],
            "comments": db.execute("SELECT COUNT(*) as c FROM comments").fetchone()["c"],
        }
        users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
        db.close()
        return render_template(
            "admin.html",
            stats=stats,
            users=users,
            difficulty=get_level(),
        )
    else:
        db.close()
        return render_template("admin.html")


# ---------------------------------------------------------------------------
# Routes — File Upload
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if request.method == "GET":
        # Show user's existing uploads
        db = get_db()
        user_id = session["user_id"]
        uploads = db.execute(
            "SELECT filename FROM uploads WHERE user_id = ?", (user_id,)
        ).fetchall()
        db.close()
        return render_template("upload.html", uploads=uploads, error=None, success=None)

    # POST: Handle file upload
    level = get_level()
    file = request.files.get("file")

    if not file or file.filename == "":
        return render_template("upload.html", error="No file selected.", uploads=[], success=None)

    # Check upload eligibility
    allowed, reason = check_upload(file.filename, level)
    if not allowed:
        db = get_db()
        uploads = db.execute(
            "SELECT filename FROM uploads WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
        db.close()
        return render_template(
            "upload.html", error=reason, uploads=uploads, success=None
        )

    # Generate safe-ish filename (but deliberately flawed at hard tier)
    original_filename = file.filename
    ext = original_filename.rsplit(".", 1)[-1] if "." in original_filename else "bin"

    # At hard tier: we use the original filename WITHOUT sanitizing for path traversal
    # At easy/medium: we add a random prefix to avoid collisions (but still no real sanitization)
    if level == "hard":
        # INTENTIONAL FLAW: path traversal in filename not sanitized
        save_name = original_filename
    else:
        save_name = f"{uuid.uuid4().hex[:8]}_{original_filename}"

    save_path = os.path.join(UPLOAD_DIR, save_name)

    # Ensure the uploads directory exists (handle subdirs from traversal)
    save_dir = os.path.dirname(save_path)
    if save_dir and not os.path.exists(save_dir):
        os.makedirs(save_dir, exist_ok=True)

    file.save(save_path)

    # Record in DB
    db = get_db()
    db.execute(
        "INSERT INTO uploads (user_id, filename) VALUES (?, ?)",
        (session["user_id"], save_name),
    )
    db.commit()

    # Re-fetch uploads list
    uploads = db.execute(
        "SELECT filename FROM uploads WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    db.close()

    return render_template(
        "upload.html",
        uploads=uploads,
        success=f"File uploaded: <a href='/uploads/{save_name}'>{save_name}</a>",
        error=None,
    )


@app.route("/uploads/<path:filename>")
def serve_upload(filename):

    return send_from_directory(UPLOAD_DIR, filename)


# ---------------------------------------------------------------------------
# Routes — User Gallery (SQLi + XSS combo)
# ---------------------------------------------------------------------------

@app.route("/user-galary-2026-event-photo.html")
def user_galary_event_photo():
    """Gallery page — classic-era SQLi on GET param AND request headers.

    Vector 1 (GET param): ?photo='  → LIKE query concatenation.
        ' ORDER BY 3-- -   ok      |  ' ORDER BY 4-- -   error
        ' UNION SELECT 1,(SELECT group_concat(username||':'||password) FROM users),3-- -
        Results render inside the photo cards.

    Vector 2 (request header): Referer → partner-campaign lookup SELECT.
        Referer: x' ORDER BY 4-- -     ok
        Referer: x' UNION SELECT 1,2,(SELECT group_concat(username||':'||password) FROM users),4-- -
        Result renders inside the partner banner.

    Vector 3 (request headers): User-Agent / X-Forwarded-For → raw INSERT
        into gallery_visits; broken syntax surfaces a loud classic SQLite
        error at easy tier. Recent visits render below (stored XSS too).
    """
    level = get_level()

    # ---- inputs ----
    photo = request.args.get("photo", "")
    referer = request.headers.get("Referer", "")
    user_agent = request.headers.get("User-Agent", "unknown")
    xff = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    db = get_db()
    error_msg = None
    photos = []
    campaign = None
    ref_error = None
    log_error = None

    # ---- lazy tables (seed.py untouched) ----
    db.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            tagline TEXT DEFAULT ''
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS gallery_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            referer TEXT DEFAULT '',
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    if db.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO campaigns (source, name, tagline) VALUES (?,?,?)",
            ("google", "Google Ads Partner", "Found us through search? Enjoy 5% off with code FOUND5."),
        )
        db.execute(
            "INSERT INTO campaigns (source, name, tagline) VALUES (?,?,?)",
            ("instagram", "Instagram Crew", "Tag us in your setup photos for a shoutout!"),
        )
        db.execute(
            "INSERT INTO campaigns (source, name, tagline) VALUES (?,?,?)",
            ("newsletter", "Newsletter Subscribers", "Early access drops every Friday."),
        )
    db.commit()

    # ---- VECTOR 1: GET param → LIKE query (3 columns: id, content, user_id) ----
    filtered_photo = sanitize_sql(photo, level)
    try:
        query = (
            f"SELECT id, content, user_id FROM comments "
            f"WHERE content LIKE '%{filtered_photo}%' ORDER BY id"
        )
        photos = db.execute(query).fetchall()
    except Exception as e:
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while loading photos."

    # ---- VECTOR 2: Referer header → campaign SELECT (4 columns) ----
    filtered_ref = sanitize_sql(referer, level)
    if filtered_ref:
        try:
            q = (
                f"SELECT id, source, name, tagline FROM campaigns "
                f"WHERE source = '{filtered_ref}'"
            )
            campaign = db.execute(q).fetchone()
        except Exception as e:
            if level == "easy":
                ref_error = f"Database error: {str(e)}"
            else:
                ref_error = "An error occurred while loading the promotion."

    # ---- VECTOR 3: UA / XFF headers → raw INSERT into visit log ----
    filtered_ua = sanitize_sql(user_agent, level)
    filtered_xff = sanitize_sql(xff, level)
    try:
        db.execute(
            f"INSERT INTO gallery_visits (ip, user_agent, referer) "
            f"VALUES ('{filtered_xff}', '{filtered_ua}', '{filtered_ref}')"
        )
        db.commit()
    except Exception as e:
        db.rollback()
        if level == "easy":
            log_error = f"Database error: {str(e)}"

    # ---- recent visits rendered back out (stored XSS surface) ----
    recent_visits = []
    try:
        recent_visits = db.execute(
            "SELECT id, ip, user_agent, referer, visited_at "
            "FROM gallery_visits ORDER BY id DESC LIMIT 6"
        ).fetchall()
    except Exception:
        pass

    db.close()

    return render_template(
        "user_galary_event_photo.html",
        photos=photos,
        photo=photo,
        error=error_msg,
        campaign=campaign,
        ref_error=ref_error,
        log_error=log_error,
        recent_visits=recent_visits,
    )


# ---------------------------------------------------------------------------
# Routes — OS Command Injection (search)
# ---------------------------------------------------------------------------

@app.route("/search.html")
def search():
    query_str = request.args.get("q", "")
    level = get_level()
    filtered_query = sanitize_sql(query_str, level)

    db = get_db()
    error_msg = None
    ping_output = None

    try:
        # VULNERABLE: string concatenation — SQLi
        sql = f"SELECT * FROM products WHERE name LIKE '%{filtered_query}%' OR description LIKE '%{filtered_query}%'"
        products = db.execute(sql).fetchall()
        db.close()
    except Exception as e:
        db.close()
        products = []
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while searching."

    # OS Command Injection: ping the search term (vulnerable!)
    if query_str:
        try:
            if platform.system() == "Windows":
                cmd = f"ping -n 1 {query_str}"
            else:
                cmd = f"ping -c 1 {query_str}"
            # VULNERABLE: user input passed directly to shell
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=5
            )
            ping_output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            ping_output = "Request timed out."
        except Exception as e:
            ping_output = f"Error: {str(e)}"

    # query_str is rendered with | safe → Reflected XSS
    return render_template(
        "search.html",
        products=products,
        query=query_str,
        ping_output=ping_output,
    )


# ---------------------------------------------------------------------------
# Routes — Session Dashboard (cookie & header attack surface, no GET params)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    """Session dashboard — NO id parameter and NO search box.

    All attack surface comes from cookies and HTTP headers:
      SQLi: 'promo_code' cookie concatenated into a SELECT,
            User-Agent / X-Forwarded-For concatenated into an INSERT.
      XSS:  'theme' cookie, Referer, X-Client-Tag reflected with | safe;
            visitor log rows rendered with | safe (stored via headers).
    """
    level = get_level()

    # --- Attack surface 1: cookies ---
    promo_code = request.cookies.get("promo_code", "")
    theme = request.cookies.get("theme", "light")

    # --- Attack surface 2: headers ---
    user_agent = request.headers.get("User-Agent", "unknown")
    referer = request.headers.get("Referer", "")
    xff = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    client_tag = request.headers.get("X-Client-Tag", "")

    db = get_db()

    # Lazily create lab tables (keeps seed.py untouched)
    db.execute("""
        CREATE TABLE IF NOT EXISTS promos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS visitor_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            client_tag TEXT DEFAULT '',
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur = db.execute("SELECT COUNT(*) FROM promos")
    if cur.fetchone()[0] == 0:
        db.execute(
            "INSERT INTO promos (code, title, description) VALUES (?,?,?)",
            ("WELCOME10", "Welcome Offer", "10% off your first order!")
        )
        db.execute(
            "INSERT INTO promos (code, title, description) VALUES (?,?,?)",
            ("SAVE20", "Mega Saver", "20% off orders over $50.")
        )
        db.execute(
            "INSERT INTO promos (code, title, description) VALUES (?,?,?)",
            ("FREESHIP", "Free Shipping", "Free delivery this weekend only.")
        )
    db.commit()

    # --- SQLi via cookie: raw string concatenation in SELECT ---
    promo = None
    sql_error = None
    filtered_promo = sanitize_sql(promo_code, level)
    if filtered_promo:
        try:
            query = (
                f"SELECT id, code, title, description FROM promos "
                f"WHERE code = '{filtered_promo}'"
            )
            promo = db.execute(query).fetchone()
        except Exception as e:
            if level == "easy":
                sql_error = f"Database error: {str(e)}"
            else:
                sql_error = "An error occurred while validating your promo."

    # --- SQLi via headers: raw concatenation in INSERT (UA / XFF / tag) ---
    filtered_ua = sanitize_sql(user_agent, level)
    filtered_xff = sanitize_sql(xff, level)
    filtered_tag = sanitize_sql(client_tag, level)
    try:
        db.execute(
            f"INSERT INTO visitor_log (ip, user_agent, client_tag) "
            f"VALUES ('{filtered_xff}', '{filtered_ua}', '{filtered_tag}')"
        )
        db.commit()
    except Exception:
        db.rollback()  # broken injection still lets the page render

    # --- Stored XSS source: last visitors rendered with | safe ---
    recent_visitors = []
    try:
        recent_visitors = db.execute(
            "SELECT id, ip, user_agent, client_tag, visited_at "
            "FROM visitor_log ORDER BY id DESC LIMIT 8"
        ).fetchall()
    except Exception:
        pass

    db.close()

    return render_template(
        "dashboard.html",
        promo=promo,
        promo_code=promo_code,
        theme=theme,
        user_agent=user_agent,
        referer=referer,
        client_tag=client_tag,
        xff=xff,
        recent_visitors=recent_visitors,
        sql_error=sql_error,
        req_headers=dict(request.headers),
        req_cookies=request.cookies,
    )


@app.route("/gallery-visits/clear")
def gallery_visits_clear():
    """Wipe the gallery visit log."""
    db = get_db()
    try:
        db.execute("DELETE FROM gallery_visits")
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return redirect(url_for("user_galary_event_photo"))


@app.route("/visitor-log/clear")
def visitor_log_clear():
    """Wipe the visitor log (handy when stored payloads pollute the page)."""
    db = get_db()
    try:
        db.execute("DELETE FROM visitor_log")
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return redirect(url_for("dashboard"))


@app.route("/api/promo/check")
def api_promo_check():
    """Raw JSON API — sqlmap / ghauri detect this easily with -r or --url.

    GET /api/promo/check?code=x' UNION SELECT ... -- -

    Returns JSON so no HTML encoding interferes with error pattern matching.
    """
    import json as _json
    level = get_level()
    code = request.args.get("code", "")
    filtered = sanitize_sql(code, level)

    db = get_db()
    try:
        query = f"SELECT id, code, title, description FROM promos WHERE code = '{filtered}'"
        row = db.execute(query).fetchone()
        db.close()
        if row:
            return _json.dumps({"status": "found", "code": row["code"],
                                "title": row["title"], "description": row["description"]})
        return _json.dumps({"status": "not_found", "code": code})
    except Exception as e:
        db.close()
        # Raw error — no HTML encoding — sqlmap matches "unrecognized token" / "SQL syntax"
        return _json.dumps({"status": "error", "error": f"SQLite SQL error: {str(e)}"}), 200


# ---------------------------------------------------------------------------
# Routes — Request Log Viewer
# ---------------------------------------------------------------------------

@app.route("/admin/requests")
def admin_requests():
    """Show all captured requests with source IPs."""
    if not session.get("is_admin"):
        # Allow non-admin viewing for training, but show warning
        pass
    return render_template(
        "admin_requests.html",
        logs=REQUEST_LOG,
    )


# ---------------------------------------------------------------------------
# Routes — Raw JSON APIs (sqlmap / ghauri detect these trivially)
# ---------------------------------------------------------------------------

@app.route("/api/user/lookup")
def api_user_lookup():
    """GET /api/user/lookup?name=' OR 1=1 -- -
    Raw JSON, no HTML encoding, error contains 'SQLite SQL error'."""
    import json as _json
    name = request.args.get("name", "")
    level = get_level()
    filtered = sanitize_sql(name, level)
    db = get_db()
    try:
        query = f"SELECT id, username, email, phone FROM users WHERE username = '{filtered}'"
        row = db.execute(query).fetchone()
        db.close()
        if row:
            return _json.dumps({"status": "found", "id": row["id"],
                                "username": row["username"], "email": row["email"],
                                "phone": row["phone"]})
        return _json.dumps({"status": "not_found", "searched": name})
    except Exception as e:
        db.close()
        return _json.dumps({"status": "error",
                            "error": f"SQLite SQL error: {str(e)}"}), 200


@app.route("/api/product/search")
def api_product_search():
    """GET /api/product/search?q=' UNION SELECT 1,2,3,4,5,6,7 -- -
    Raw JSON, no HTML encoding, error contains 'SQLite SQL error'."""
    import json as _json
    q = request.args.get("q", "")
    level = get_level()
    filtered = sanitize_sql(q, level)
    db = get_db()
    try:
        query = (f"SELECT id, name, description, price, category_id "
                 f"FROM products WHERE name LIKE '%{filtered}%' "
                 f"OR description LIKE '%{filtered}%'")
        rows = db.execute(query).fetchall()
        db.close()
        results = [{"id": r["id"], "name": r["name"],
                     "price": r["price"]} for r in rows]
        return _json.dumps({"status": "ok", "count": len(results),
                            "results": results})
    except Exception as e:
        db.close()
        return _json.dumps({"status": "error",
                            "error": f"SQLite SQL error: {str(e)}"}), 200


@app.route("/api/category/items")
def api_category_items():
    """GET /api/category/items?id=' UNION SELECT 1,2,3,4 -- -
    Raw JSON, no HTML encoding, error contains 'SQLite SQL error'."""
    import json as _json
    cat_id = request.args.get("id", "")
    level = get_level()
    filtered = sanitize_sql(cat_id, level)
    db = get_db()
    try:
        query = f"SELECT id, name, price FROM products WHERE category_id = '{filtered}'"
        rows = db.execute(query).fetchall()
        db.close()
        results = [{"id": r["id"], "name": r["name"],
                     "price": r["price"]} for r in rows]
        return _json.dumps({"status": "ok", "count": len(results),
                            "results": results})
    except Exception as e:
        db.close()
        return _json.dumps({"status": "error",
                            "error": f"SQLite SQL error: {str(e)}"}), 200


@app.route("/api/comment/search")
def api_comment_search():
    """GET /api/comment/search?q=' UNION SELECT 1,2,3,4 -- -
    Raw JSON, no HTML encoding, error contains 'SQLite SQL error'."""
    import json as _json
    q = request.args.get("q", "")
    level = get_level()
    filtered = sanitize_sql(q, level)
    db = get_db()
    try:
        query = (f"SELECT c.id, c.content, u.username "
                 f"FROM comments c JOIN users u ON c.user_id = u.id "
                 f"WHERE c.content LIKE '%{filtered}%'")
        rows = db.execute(query).fetchall()
        db.close()
        results = [{"id": r["id"], "content": r["content"],
                     "author": r["username"]} for r in rows]
        return _json.dumps({"status": "ok", "count": len(results),
                            "results": results})
    except Exception as e:
        db.close()
        return _json.dumps({"status": "error",
                            "error": f"SQLite SQL error: {str(e)}"}), 200


# ---------------------------------------------------------------------------
# Routes — OTP Bypass (Response Manipulation + Length Validation Bug)
# ---------------------------------------------------------------------------

CORRECT_OTP = "1234567890"

@app.route("/secure-login.html", methods=["GET", "POST"])
def secure_login():
    """Two-factor login flow: email step, then OTP verification step.

    Vuln 1 — Response manipulation: server returns HTTP 500 on wrong OTP
    or wrong length. Intercept in Burp, change status 500 → 200, forward
    — browser renders whatever body you pair with it.

    Vuln 2 — Response replay: send correct OTP once, capture the 200
    success page, then replay it over any failed attempt.

    Vuln 3 — Length bypass: server validates exactly 10 digits AND the
    value, but the browser trusts the final response — so a 42-digit or
    100-digit number works fine once the response says success.
    """
    if request.method == "GET":
        return render_template(
            "secure_login.html", step="email", result=None,
            error=None, email=None,
        )

    step = request.form.get("step", "")

    # ---- Step 1: request the OTP ----
    if step == "request":
        email = request.form.get("email", "").strip()
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            return make_response(
                render_template(
                    "secure_login.html", step="email", result=None,
                    error="Please enter a valid email address.", email=email,
                ),
                200,
            )
        # Pretend to email the code, move to verification screen
        return render_template(
            "secure_login.html", step="verify", result=None,
            error=None, email=email,
        )

    # ---- Step 2: verify the OTP ----
    otp = request.form.get("otp", "")

    # Server-side: length must be exactly 10 digits
    if not otp.isdigit() or len(otp) != 10:
        resp = make_response(
            render_template(
                "secure_login.html", step="verify", result="denied",
                email=request.form.get("email", ""),
                error=f"Invalid OTP format — must be exactly 10 digits, got {len(otp)}.",
            ),
            500,
        )
        return resp

    # Server-side: value must match
    if otp == CORRECT_OTP:
        return render_template(
            "secure_login.html", step="done", result="granted",
            error=None, email=request.form.get("email", ""),
        )
    else:
        resp = make_response(
            render_template(
                "secure_login.html", step="verify", result="denied",
                email=request.form.get("email", ""),
                error="OTP verification failed — server error (HTTP 500).",
            ),
            500,
        )
        return resp


# ---------------------------------------------------------------------------
# Routes — Simplified XSS Playground (all basic payloads work)
# ---------------------------------------------------------------------------

@app.route("/xss-playground.html", methods=["GET", "POST"])
def xss_playground():
    """XSS feedback page — every basic payload works at easy mode.

    GET  /xss-playground.html?q=<script>alert(1)</script>        → reflected
    GET  /xss-playground.html?q=<img src=x onerror=alert(1)>     → reflected
    GET  /xss-playground.html?q=<svg onload=alert(1)>            → reflected
    POST with form field 'q' → same result.

    At easy mode filter_xss returns value unchanged so ALL HTML passes.
    At medium mode only <script> tags are stripped (img/svg still work).
    At hard mode <script> + lowercase event handlers are stripped (mixed case bypasses).
    """
    level = get_level()
    q = ""
    if request.method == "POST":
        q = request.form.get("q", "")
    else:
        q = request.args.get("q", "")

    filtered = filter_xss(q, level)

    return render_template(
        "xss_playground.html",
        q=q,
        filtered=filtered,
        method=request.method,
    )


# ---------------------------------------------------------------------------
# Routes — XSS Balancing Challenge (break out of HTML contexts)
# ---------------------------------------------------------------------------

@app.route("/xss-challenge.html", methods=["GET", "POST"])
def xss_challenge():
    """XSS challenge with 4 levels — user input is placed inside different
    HTML contexts.  The attacker must 'balance' (close) the surrounding
    context before injecting a script tag.

    Level 1: Inside double-quoted attribute  →  break with  "><script>...
    Level 2: Inside single-quoted attribute  →  break with  '><script>...
    Level 3: Inside HTML comment             →  break with  --><script>...
    Level 4: Inside <script> string literal  →  break with  ";alert(1)//
    """
    level = int(request.args.get("lvl", "1"))
    user_input = ""

    if request.method == "POST":
        user_input = request.form.get("input", "")
        level = int(request.form.get("lvl", "1"))

    level = max(1, min(4, level))

    # Build the vulnerable HTML context for each level
    if level == 1:
        context_desc = 'Inside a double-quoted attribute: value="___"'
        context_html = f'<input type="text" value="{user_input}" class="form-control">'
        source_code = f'&lt;input type="text" value="<span style="color:red">{user_input}</span>"&gt;'
    elif level == 2:
        context_desc = "Inside a single-quoted attribute: class='___'"
        context_html = f"<div class='{user_input}'>Hello user</div>"
        source_code = f'&lt;div class="<span style="color:red">{user_input}</span>"&gt;...&lt;/div&gt;'
    elif level == 3:
        context_desc = "Inside an HTML comment: &lt;!-- ___ --&gt;"
        context_html = f"<!-- {user_input} -->"
        source_code = f'&lt;!-- <span style="color:red">{user_input}</span> --&gt;'
    else:
        context_desc = 'Inside a JavaScript string: var x = "___"'
        context_html = f'<script>var greeting = "{user_input}";</script>'
        source_code = f'&lt;script&gt;var greeting = "<span style="color:red">{user_input}</span>";&lt;/script&gt;'

    return render_template(
        "xss_challenge.html",
        level=level,
        user_input=user_input,
        context_desc=context_desc,
        context_html=context_html,
        source_code=source_code,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def init_db():
    """Initialize or reset the database."""
    seed_database(DB_PATH)
    # Clear old uploads
    for f in os.listdir(UPLOAD_DIR):
        fpath = os.path.join(UPLOAD_DIR, f)
        if os.path.isfile(fpath):
            os.remove(fpath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vulnerable Web Lab - SQLi, XSS and File Upload training target"
    )
    parser.add_argument(
        "--easy", action="store_true", help="Run with easy difficulty (default)"
    )
    parser.add_argument(
        "--medium", action="store_true", help="Run with medium difficulty"
    )
    parser.add_argument(
        "--hard", action="store_true", help="Run with hard difficulty"
    )
    parser.add_argument(
        "--reset", action="store_true", help="Reset database and uploads before starting"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0 — all interfaces)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to listen on (default: 5000)"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable Flask debug mode"
    )

    args = parser.parse_args()

    # Determine difficulty
    if args.medium:
        level = "medium"
    elif args.hard:
        level = "hard"
    else:
        level = "easy"

    app.config["DIFFICULTY"] = level

    # Init or reset DB
    if args.reset or not os.path.exists(DB_PATH):
        print(f"[+] Initializing database (difficulty: {level})...")
        init_db()
    else:
        print(f"[+] Using existing database (difficulty: {level})")

    # Detect local IP addresses for network access
    import socket
    local_ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    local_ips.append("127.0.0.1")

    sep = "=" * 60
    print()
    print(sep)
    print()
    print(f"  Vulnerable Web Lab - MyHomeLabExample.net")
    print(f"  Difficulty: {level.upper()}")
    print(f"  Listening on: {args.host}:{args.port}")
    print()
    for ip in local_ips:
        print(f"  -> http://{ip}:{args.port}")
    print()
    print(f"  DB: {DB_PATH}")
    print(sep)
    print()
    print("  TIP: Other devices on your network can access")
    print(f"       the lab using your LAN IP address above.")
    print()

    app.run(host=args.host, port=args.port, debug=args.debug)
