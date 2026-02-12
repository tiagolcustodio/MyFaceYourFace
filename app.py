import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

APP_NAME = "MyFaceYourFace"
DB_PATH = os.environ.get("DB_PATH", "myface.db")

# Demo credentials
DEFAULT_ADMIN_USER = os.environ.get("DEFAULT_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("DEFAULT_ADMIN_PASS", "admin311286?")

DEFAULT_Tiago_USER = os.environ.get("DEFAULT_Tiago_USER", "tiagoluis86")
DEFAULT_Tiago_PASS = os.environ.get("DEFAULT_Tiago_PASS", "Quadrado86?")

UPLOAD_DIR_PROFILES = os.path.join("static", "uploads", "profiles")
UPLOAD_DIR_COMMUNITIES = os.path.join("static", "uploads", "communities")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


# -----------------------------
# Upload helpers
# -----------------------------
def ensure_upload_dirs():
    os.makedirs(UPLOAD_DIR_PROFILES, exist_ok=True)
    os.makedirs(UPLOAD_DIR_COMMUNITIES, exist_ok=True)


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def save_upload(file_storage, folder: str, prefix: str) -> str | None:
    """
    Saves upload into static/uploads/<folder>.
    Returns relative path like: uploads/profiles/xxx.png
    """
    if not file_storage or file_storage.filename == "":
        return None
    if not allowed_file(file_storage.filename):
        return None

    ensure_upload_dirs()

    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    unique = f"{prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.{ext}"

    if folder == "profiles":
        abs_path = os.path.join(UPLOAD_DIR_PROFILES, unique)
        rel_path = os.path.join("uploads", "profiles", unique).replace("\\", "/")
    else:
        abs_path = os.path.join(UPLOAD_DIR_COMMUNITIES, unique)
        rel_path = os.path.join("uploads", "communities", unique).replace("\\", "/")

    file_storage.save(abs_path)
    return rel_path


# -----------------------------
# DB
# -----------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def column_exists(table: str, column: str) -> bool:
    db = get_db()
    cols = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c["name"] == column for c in cols)


def add_column_if_missing(table: str, column: str, ddl: str):
    if not column_exists(table, column):
        db = get_db()
        db.execute(ddl)
        db.commit()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            UNIQUE(user_id, friend_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(friend_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            type TEXT NOT NULL,        -- 'friend_request' | 'message'
            status TEXT NOT NULL,      -- friend_request: pending/accepted/rejected ; message: sent
            created_at TEXT NOT NULL,
            FOREIGN KEY(from_user_id) REFERENCES users(id),
            FOREIGN KEY(to_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS communities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            icon_path TEXT DEFAULT NULL,
            created_by_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by_user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

    # ---- MIGRATIONS ----
    add_column_if_missing("messages", "content", "ALTER TABLE messages ADD COLUMN content TEXT DEFAULT NULL")
    add_column_if_missing("messages", "read_at", "ALTER TABLE messages ADD COLUMN read_at TEXT DEFAULT NULL")

    add_column_if_missing("users", "profile_pic_path", "ALTER TABLE users ADD COLUMN profile_pic_path TEXT DEFAULT NULL")


def seed_default_users():
    db = get_db()

    def ensure_user(username, password, display_name, description=""):
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            return
        db.execute(
            "INSERT INTO users (username, password_hash, display_name, description) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), display_name, description),
        )
        db.commit()

    ensure_user(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, "Admin", "Administrative account.")
    ensure_user(DEFAULT_Tiago_USER, DEFAULT_Tiago_PASS, "Tiago Luis Custódio", "Test account.")


@app.before_request
def setup():
    init_db()
    seed_default_users()


# -----------------------------
# Auth
# -----------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


# -----------------------------
# Helpers
# -----------------------------
def count_pending_friend_requests(user_id: int) -> int:
    db = get_db()
    row = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM messages
        WHERE to_user_id = ? AND type = 'friend_request' AND status = 'pending'
        """,
        (user_id,),
    ).fetchone()
    return int(row["c"])


def count_messages_total(user_id: int) -> int:
    db = get_db()
    row = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM messages
        WHERE to_user_id = ? AND type = 'message'
        """,
        (user_id,),
    ).fetchone()
    return int(row["c"])


def count_messages_unread(user_id: int) -> int:
    db = get_db()
    row = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM messages
        WHERE to_user_id = ? AND type = 'message' AND read_at IS NULL
        """,
        (user_id,),
    ).fetchone()
    return int(row["c"])


def mark_inbox_read(user_id: int):
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute(
        """
        UPDATE messages
        SET read_at = ?
        WHERE to_user_id = ? AND type = 'message' AND read_at IS NULL
        """,
        (now, user_id),
    )
    db.commit()


def list_friends(user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT u.id, u.username, u.display_name, u.profile_pic_path
        FROM friendships f
        JOIN users u ON u.id = f.friend_id
        WHERE f.user_id = ?
        ORDER BY u.display_name ASC
        """,
        (user_id,),
    ).fetchall()


def list_friends_random(user_id: int, limit: int = 12):
    db = get_db()
    return db.execute(
        """
        SELECT u.id, u.username, u.display_name, u.profile_pic_path
        FROM friendships f
        JOIN users u ON u.id = f.friend_id
        WHERE f.user_id = ?
        ORDER BY RANDOM()
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()


def are_friends(a: int, b: int) -> bool:
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?",
        (a, b),
    ).fetchone()
    return row is not None


def has_pending_request(from_id: int, to_id: int) -> bool:
    db = get_db()
    row = db.execute(
        """
        SELECT 1 FROM messages
        WHERE from_user_id = ? AND to_user_id = ?
          AND type = 'friend_request' AND status = 'pending'
        """,
        (from_id, to_id),
    ).fetchone()
    return row is not None


def make_friendship(a: int, b: int):
    db = get_db()
    db.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (a, b))
    db.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (b, a))
    db.commit()


def remove_friendship(a: int, b: int):
    db = get_db()
    db.execute("DELETE FROM friendships WHERE user_id = ? AND friend_id = ?", (a, b))
    db.execute("DELETE FROM friendships WHERE user_id = ? AND friend_id = ?", (b, a))
    db.commit()


def get_user_by_username(username: str):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_wall_messages(profile_user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT m.id, m.content, m.created_at,
               u.display_name AS from_name, u.username AS from_username, u.profile_pic_path AS from_pic
        FROM messages m
        JOIN users u ON u.id = m.from_user_id
        WHERE m.to_user_id = ? AND m.type = 'message'
        ORDER BY m.created_at DESC
        """,
        (profile_user_id,),
    ).fetchall()


def get_inbox_messages(user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT m.id, m.content, m.created_at, m.read_at,
               u.display_name AS from_name, u.username AS from_username, u.profile_pic_path AS from_pic
        FROM messages m
        JOIN users u ON u.id = m.from_user_id
        WHERE m.to_user_id = ? AND m.type = 'message'
        ORDER BY m.created_at DESC
        """,
        (user_id,),
    ).fetchall()


def list_communities_all():
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.description, c.icon_path, c.created_at,
               u.display_name AS created_by_name, u.username AS created_by_username
        FROM communities c
        JOIN users u ON u.id = c.created_by_user_id
        ORDER BY c.created_at DESC
        """
    ).fetchall()


def list_communities_random(limit: int = 12):
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.icon_path
        FROM communities c
        ORDER BY RANDOM()
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def get_community_by_id(cid: int):
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.description, c.icon_path, c.created_at,
               u.display_name AS created_by_name, u.username AS created_by_username
        FROM communities c
        JOIN users u ON u.id = c.created_by_user_id
        WHERE c.id = ?
        """,
        (cid,),
    ).fetchone()


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def index():
    if "user_id" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return render_template("login.html", app_name=APP_NAME)


@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.")
        return redirect(url_for("login"))

    session["user_id"] = user["id"]
    return redirect(url_for("home"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/home")
@login_required
def home():
    user = current_user()
    db = get_db()

    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])
    friends_random = list_friends_random(user["id"], limit=12)
    communities_random = list_communities_random(limit=12)

    all_users = db.execute(
        "SELECT id, username, display_name FROM users ORDER BY display_name ASC"
    ).fetchall()

    cards = []
    for u in all_users:
        if u["id"] == user["id"]:
            continue
        if are_friends(user["id"], u["id"]):
            continue  # hide existing friends

        can_request = True
        label = "Add friend"

        if has_pending_request(user["id"], u["id"]):
            can_request = False
            label = "Request sent"
        elif has_pending_request(u["id"], user["id"]):
            can_request = False
            label = "They requested you"

        cards.append(
            {
                "id": u["id"],
                "display_name": u["display_name"],
                "username": u["username"],
                "can_request": can_request,
                "label": label,
            }
        )

    return render_template(
        "home.html",
        app_name=APP_NAME,
        user=user,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
        friends_random=friends_random,
        communities_random=communities_random,
        user_cards=cards,
    )


@app.post("/friends/request/<int:to_user_id>")
@login_required
def send_friend_request(to_user_id):
    user = current_user()
    if to_user_id == user["id"]:
        return redirect(url_for("home"))

    if are_friends(user["id"], to_user_id) or has_pending_request(user["id"], to_user_id):
        return redirect(url_for("home"))

    db = get_db()
    db.execute(
        """
        INSERT INTO messages (from_user_id, to_user_id, type, status, created_at)
        VALUES (?, ?, 'friend_request', 'pending', ?)
        """,
        (user["id"], to_user_id, datetime.utcnow().isoformat()),
    )
    db.commit()
    flash("Friend request sent!")
    return redirect(url_for("home"))


@app.get("/friend-requests")
@login_required
def friend_requests():
    user = current_user()
    db = get_db()

    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])
    friends_random = list_friends_random(user["id"], limit=12)
    communities_random = list_communities_random(limit=12)

    pending = db.execute(
        """
        SELECT m.id, m.created_at, u.display_name AS from_name, u.username AS from_username
        FROM messages m
        JOIN users u ON u.id = m.from_user_id
        WHERE m.to_user_id = ? AND m.type = 'friend_request' AND m.status = 'pending'
        ORDER BY m.created_at DESC
        """,
        (user["id"],),
    ).fetchall()

    return render_template(
        "friend_requests.html",
        app_name=APP_NAME,
        user=user,
        pending_requests=pending,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
        friends_random=friends_random,
        communities_random=communities_random,
    )


@app.post("/friend-requests/<int:msg_id>/accept")
@login_required
def accept_friend_request(msg_id):
    user = current_user()
    db = get_db()

    msg = db.execute(
        """
        SELECT * FROM messages
        WHERE id = ? AND to_user_id = ? AND type = 'friend_request' AND status = 'pending'
        """,
        (msg_id, user["id"]),
    ).fetchone()

    if not msg:
        return redirect(url_for("friend_requests"))

    make_friendship(msg["from_user_id"], msg["to_user_id"])
    db.execute("UPDATE messages SET status = 'accepted' WHERE id = ?", (msg_id,))
    db.commit()
    flash("Friend request accepted!")
    return redirect(url_for("friend_requests"))


@app.post("/friend-requests/<int:msg_id>/reject")
@login_required
def reject_friend_request(msg_id):
    user = current_user()
    db = get_db()

    db.execute(
        """
        UPDATE messages
        SET status = 'rejected'
        WHERE id = ? AND to_user_id = ? AND type = 'friend_request' AND status = 'pending'
        """,
        (msg_id, user["id"]),
    )
    db.commit()
    flash("Friend request rejected.")
    return redirect(url_for("friend_requests"))


@app.get("/profile")
@login_required
def my_profile_redirect():
    user = current_user()
    mark_inbox_read(user["id"])  # viewing your own profile counts as "read"
    return redirect(url_for("user_profile", username=user["username"]))


@app.get("/u/<username>")
@login_required
def user_profile(username):
    viewer = current_user()
    profile_user = get_user_by_username(username)
    if not profile_user:
        abort(404)

    pending_requests_count = count_pending_friend_requests(viewer["id"])
    messages_total_count = count_messages_total(viewer["id"])
    messages_unread_count = count_messages_unread(viewer["id"])

    friends_random = list_friends_random(profile_user["id"], limit=12)
    communities_random = list_communities_random(limit=12)

    is_owner = (viewer["id"] == profile_user["id"])
    is_friend = are_friends(viewer["id"], profile_user["id"]) if not is_owner else True

    wall_messages = get_wall_messages(profile_user["id"])

    return render_template(
        "profile.html",
        app_name=APP_NAME,
        viewer=viewer,
        profile_user=profile_user,
        is_owner=is_owner,
        is_friend=is_friend,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
        friends_random=friends_random,
        communities_random=communities_random,
        wall_messages=wall_messages,
    )


@app.get("/edit-profile")
@login_required
def edit_profile():
    user = current_user()
    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])
    return render_template(
        "edit_profile.html",
        app_name=APP_NAME,
        user=user,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
    )


@app.post("/edit-profile")
@login_required
def edit_profile_post():
    user = current_user()
    name = (request.form.get("display_name") or "").strip()
    desc = (request.form.get("description") or "").strip()

    if not name:
        flash("Name cannot be empty.")
        return redirect(url_for("edit_profile"))

    pic = request.files.get("profile_pic")
    rel_path = None
    if pic and pic.filename:
        rel_path = save_upload(pic, "profiles", prefix=f"user{user['id']}")
        if rel_path is None:
            flash("Invalid file. Please upload PNG or JPG.")
            return redirect(url_for("edit_profile"))

    db = get_db()
    if rel_path:
        db.execute(
            "UPDATE users SET display_name = ?, description = ?, profile_pic_path = ? WHERE id = ?",
            (name, desc, rel_path, user["id"]),
        )
    else:
        db.execute(
            "UPDATE users SET display_name = ?, description = ? WHERE id = ?",
            (name, desc, user["id"]),
        )
    db.commit()

    flash("Profile updated.")
    return redirect(url_for("my_profile_redirect"))


@app.post("/u/<username>/message")
@login_required
def post_message(username):
    viewer = current_user()
    profile_user = get_user_by_username(username)
    if not profile_user:
        abort(404)

    if viewer["id"] == profile_user["id"]:
        flash("You cannot post a message to yourself (for now).")
        return redirect(url_for("user_profile", username=username))

    if not are_friends(viewer["id"], profile_user["id"]):
        flash("You can only post messages to friends.")
        return redirect(url_for("user_profile", username=username))

    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Message cannot be empty.")
        return redirect(url_for("user_profile", username=username))
    if len(content) > 500:
        flash("Message is too long (max 500 characters).")
        return redirect(url_for("user_profile", username=username))

    db = get_db()
    db.execute(
        """
        INSERT INTO messages (from_user_id, to_user_id, type, status, content, created_at, read_at)
        VALUES (?, ?, 'message', 'sent', ?, ?, NULL)
        """,
        (viewer["id"], profile_user["id"], content, datetime.utcnow().isoformat()),
    )
    db.commit()
    flash("Message posted.")
    return redirect(url_for("user_profile", username=username))


@app.get("/friends")
@login_required
def friends_page():
    user = current_user()
    friends = list_friends(user["id"])
    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])

    return render_template(
        "friends.html",
        app_name=APP_NAME,
        user=user,
        friends=friends,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
    )


@app.post("/friends/unfriend/<username>")
@login_required
def unfriend(username):
    user = current_user()
    target = get_user_by_username(username)
    if not target:
        abort(404)
    if target["id"] == user["id"]:
        return redirect(url_for("friends_page"))

    if are_friends(user["id"], target["id"]):
        remove_friendship(user["id"], target["id"])
        flash("Friend removed.")
    return redirect(url_for("friends_page"))


@app.get("/messages")
@login_required
def messages():
    user = current_user()
    mark_inbox_read(user["id"])

    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])  # should be 0 after mark
    inbox = get_inbox_messages(user["id"])

    communities_random = list_communities_random(limit=12)

    return render_template(
        "messages.html",
        app_name=APP_NAME,
        user=user,
        inbox=inbox,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
        communities_random=communities_random,
    )


@app.get("/communities")
@login_required
def communities_page():
    user = current_user()
    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])

    communities = list_communities_all()

    return render_template(
        "communities.html",
        app_name=APP_NAME,
        user=user,
        communities=communities,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
    )


@app.post("/communities/create")
@login_required
def create_community():
    user = current_user()

    name = (request.form.get("name") or "").strip()
    desc = (request.form.get("description") or "").strip()

    if not name:
        flash("Community name cannot be empty.")
        return redirect(url_for("communities_page"))

    icon = request.files.get("icon")
    icon_path = None
    if icon and icon.filename:
        icon_path = save_upload(icon, "communities", prefix=f"community_user{user['id']}")
        if icon_path is None:
            flash("Invalid icon. Please upload PNG or JPG.")
            return redirect(url_for("communities_page"))

    db = get_db()
    db.execute(
        """
        INSERT INTO communities (name, description, icon_path, created_by_user_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (name, desc, icon_path, user["id"], datetime.utcnow().isoformat()),
    )
    db.commit()

    flash("Community created.")
    return redirect(url_for("communities_page"))


@app.get("/c/<int:cid>")
@login_required
def community_page(cid):
    user = current_user()
    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])

    community = get_community_by_id(cid)
    if not community:
        abort(404)

    return render_template(
        "community.html",
        app_name=APP_NAME,
        user=user,
        community=community,
        pending_requests_count=pending_requests_count,
        messages_total_count=messages_total_count,
        messages_unread_count=messages_unread_count,
    )


@app.get("/settings")
@login_required
def settings_page():
    user = current_user()
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Settings",
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.get("/help")
@login_required
def help_page():
    user = current_user()
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Help",
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


if __name__ == "__main__":
    ensure_upload_dirs()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
