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
    session, send_from_directory, flash, abort,
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

    if password != password2:
        return render_template("register.html", error="Passwords do not match.")

    if len(username) < 3 or len(password) < 4:
        return render_template(
            "register.html",
            error="Username must be 3+ chars, password 4+ chars.",
        )

    db = get_db()
    try:
        # Check if username already exists first
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            print(f"[REGISTER] Rejected: '{username}' already exists (id={existing['id']})")
            db.close()
            return render_template(
                "register.html", error="Username already taken."
            )

        new_uuid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (uuid, username, password) VALUES (?, ?, ?)",
            (new_uuid, username, password),
        )
        db.commit()
        db.close()
        print(f"[REGISTER] SUCCESS: '{username}' created (uuid={new_uuid})")
        return render_template(
            "login.html", success="Account created! You can now log in."
        )
    except sqlite3.IntegrityError as e:
        db.close()
        print(f"[REGISTER] ERROR: {e}")
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
    """VULNERABLE: photo parameter is reflected in query AND template.
    SQLi: string concatenation in query.
    XSS: photo param reflected with | safe in template.
    UNION-based + ORDER BY SQLi all work here."""
    photo = request.args.get("photo", "")
    level = get_level()
    filtered_photo = sanitize_sql(photo, level)

    db = get_db()
    error_msg = None
    photos = []

    try:
        # VULNERABLE: raw string concatenation — SQLi target
        query = f"SELECT id, content, user_id FROM comments WHERE content LIKE '%{filtered_photo}%' ORDER BY id"
        photos = db.execute(query).fetchall()
        db.close()
    except Exception as e:
        db.close()
        if level == "easy":
            error_msg = f"Database error: {str(e)}"
        else:
            error_msg = "An error occurred while loading photos."

    # photo is rendered with | safe → Reflected XSS
    return render_template(
        "user_galary_event_photo.html",
        photos=photos,
        photo=photo,
        error=error_msg,
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
