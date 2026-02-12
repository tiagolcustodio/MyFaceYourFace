import os
import sqlite3
from datetime import datetime
from functools import wraps
import math
import secrets
import re

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

APP_NAME = "MyFaceYourFace"
DB_PATH = os.environ.get("DB_PATH", "myface.db")

DEFAULT_ADMIN_USER = os.environ.get("DEFAULT_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("DEFAULT_ADMIN_PASS", "admin311286?")

DEFAULT_Tiago_USER = os.environ.get("DEFAULT_Tiago_USER", "tiagoluis86")
DEFAULT_Tiago_PASS = os.environ.get("DEFAULT_Tiago_PASS", "Quadrado86?")

UPLOAD_DIR_PROFILES = os.path.join("static", "uploads", "profiles")
UPLOAD_DIR_COMMUNITIES = os.path.join("static", "uploads", "communities")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

PAGE_SIZE = 20

SEX_OPTIONS = ["male", "female", "other"]
ORIENTATION_OPTIONS = ["lesbian", "gay", "bisexual", "transgender", "queer", "intersex", "asexual", "other"]
RELATIONSHIP_OPTIONS = ["single", "dating", "open", "married"]
POLITICS_OPTIONS = ["far-left", "left", "center-left", "center", "center-right", "right", "far-right"]

DEFAULT_INVITES = 5
DEFAULT_INVITES_ADMIN = 15

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


# -----------------------------
# Upload helpers
# -----------------------------
def ensure_upload_dirs():
    os.makedirs(UPLOAD_DIR_PROFILES, exist_ok=True)
    os.makedirs(UPLOAD_DIR_COMMUNITIES, exist_ok=True)


def allowed_file(filename: str) -> bool:
    return bool(filename) and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage, folder: str, prefix: str) -> str | None:
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
            type TEXT NOT NULL,
            status TEXT NOT NULL,
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

        CREATE TABLE IF NOT EXISTS community_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            community_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TEXT NOT NULL,
            UNIQUE(community_id, user_id),
            FOREIGN KEY(community_id) REFERENCES communities(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS community_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            community_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(community_id) REFERENCES communities(id),
            FOREIGN KEY(created_by_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS topic_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_id INTEGER NOT NULL,
            from_user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(topic_id) REFERENCES community_topics(id),
            FOREIGN KEY(from_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS invite_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            inviter_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT DEFAULT NULL,
            used_by_user_id INTEGER DEFAULT NULL,
            FOREIGN KEY(inviter_user_id) REFERENCES users(id),
            FOREIGN KEY(used_by_user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

    # migrations for older DBs
    add_column_if_missing("messages", "content", "ALTER TABLE messages ADD COLUMN content TEXT DEFAULT NULL")
    add_column_if_missing("messages", "read_at", "ALTER TABLE messages ADD COLUMN read_at TEXT DEFAULT NULL")
    add_column_if_missing("users", "profile_pic_path", "ALTER TABLE users ADD COLUMN profile_pic_path TEXT DEFAULT NULL")

    # profile fields
    add_column_if_missing("users", "birthdate", "ALTER TABLE users ADD COLUMN birthdate TEXT DEFAULT NULL")
    add_column_if_missing("users", "sex", "ALTER TABLE users ADD COLUMN sex TEXT DEFAULT NULL")
    add_column_if_missing("users", "sexual_orientation", "ALTER TABLE users ADD COLUMN sexual_orientation TEXT DEFAULT NULL")
    add_column_if_missing("users", "relationship_status", "ALTER TABLE users ADD COLUMN relationship_status TEXT DEFAULT NULL")
    add_column_if_missing("users", "political_orientation", "ALTER TABLE users ADD COLUMN political_orientation TEXT DEFAULT NULL")
    add_column_if_missing("users", "favorite_team", "ALTER TABLE users ADD COLUMN favorite_team TEXT DEFAULT NULL")
    add_column_if_missing("users", "main_hobby", "ALTER TABLE users ADD COLUMN main_hobby TEXT DEFAULT NULL")

    # ✅ invites
    add_column_if_missing("users", "invites_remaining", "ALTER TABLE users ADD COLUMN invites_remaining INTEGER DEFAULT 5")


def seed_default_users():
    db = get_db()

    def ensure_user(username, password, display_name, description="", invites=DEFAULT_INVITES):
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            # ensure invites set if null/0 for existing records
            db.execute(
                """
                UPDATE users
                SET invites_remaining = COALESCE(invites_remaining, ?)
                WHERE username = ?
                """,
                (invites, username),
            )
            db.commit()
            return

        db.execute(
            """
            INSERT INTO users (username, password_hash, display_name, description, invites_remaining)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), display_name, description, invites),
        )
        db.commit()

    ensure_user(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, "Admin", "Administrative account.", invites=DEFAULT_INVITES_ADMIN)
    ensure_user(DEFAULT_Tiago_USER, DEFAULT_Tiago_PASS, "Tiago Luis Custódio", "Test account.", invites=DEFAULT_INVITES)


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
# Pagination helper
# -----------------------------
def get_page_param() -> int:
    try:
        p = int(request.args.get("page", "1"))
        return max(1, p)
    except ValueError:
        return 1


def pagination_meta(total: int, page: int, page_size: int = PAGE_SIZE):
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    page = max(1, min(page, total_pages))
    show = total > page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "show": show,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
    }


# -----------------------------
# Helpers (counts)
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


# -----------------------------
# Helpers (friends)
# -----------------------------
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
    row = db.execute("SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?", (a, b)).fetchone()
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


# -----------------------------
# Helpers (users + profile messages)
# -----------------------------
def get_user_by_username(username: str):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_wall_messages(profile_user_id: int, page: int):
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) AS c FROM messages WHERE to_user_id = ? AND type = 'message'",
        (profile_user_id,),
    ).fetchone()["c"]
    meta = pagination_meta(total, page, PAGE_SIZE)
    offset = (meta["page"] - 1) * meta["page_size"]

    rows = db.execute(
        """
        SELECT m.id, m.content, m.created_at, m.from_user_id, m.to_user_id,
               u.display_name AS from_name, u.username AS from_username, u.profile_pic_path AS from_pic
        FROM messages m
        JOIN users u ON u.id = m.from_user_id
        WHERE m.to_user_id = ? AND m.type = 'message'
        ORDER BY m.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (profile_user_id, meta["page_size"], offset),
    ).fetchall()
    return rows, meta


def get_inbox_messages(user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT m.id, m.content, m.created_at, m.read_at, m.from_user_id, m.to_user_id,
               u.display_name AS from_name, u.username AS from_username, u.profile_pic_path AS from_pic
        FROM messages m
        JOIN users u ON u.id = m.from_user_id
        WHERE m.to_user_id = ? AND m.type = 'message'
        ORDER BY m.created_at DESC
        """,
        (user_id,),
    ).fetchall()


# -----------------------------
# Helpers (communities)
# -----------------------------
def list_communities_all():
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.description, c.icon_path, c.created_at,
               u.display_name AS created_by_name, u.username AS created_by_username,
               c.created_by_user_id
        FROM communities c
        JOIN users u ON u.id = c.created_by_user_id
        ORDER BY c.created_at DESC
        """
    ).fetchall()


def get_community_by_id(cid: int):
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.description, c.icon_path, c.created_at,
               u.display_name AS created_by_name, u.username AS created_by_username,
               c.created_by_user_id
        FROM communities c
        JOIN users u ON u.id = c.created_by_user_id
        WHERE c.id = ?
        """,
        (cid,),
    ).fetchone()


def is_member(user_id: int, community_id: int) -> bool:
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM community_members WHERE community_id = ? AND user_id = ?",
        (community_id, user_id),
    ).fetchone()
    return row is not None


def add_member(user_id: int, community_id: int):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO community_members (community_id, user_id, joined_at) VALUES (?, ?, ?)",
        (community_id, user_id, datetime.utcnow().isoformat()),
    )
    db.commit()


def remove_member(user_id: int, community_id: int):
    db = get_db()
    db.execute(
        "DELETE FROM community_members WHERE community_id = ? AND user_id = ?",
        (community_id, user_id),
    )
    db.commit()


def list_members_random(community_id: int, limit: int = 12):
    db = get_db()
    return db.execute(
        """
        SELECT u.id, u.username, u.display_name, u.profile_pic_path
        FROM community_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.community_id = ?
        ORDER BY RANDOM()
        LIMIT ?
        """,
        (community_id, limit),
    ).fetchall()


def list_members_all(community_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT u.id, u.username, u.display_name, u.profile_pic_path, cm.joined_at
        FROM community_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.community_id = ?
        ORDER BY u.display_name ASC
        """,
        (community_id,),
    ).fetchall()


def list_user_communities_all(user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.description, c.icon_path, c.created_at
        FROM community_members cm
        JOIN communities c ON c.id = cm.community_id
        WHERE cm.user_id = ?
        ORDER BY c.created_at DESC
        """,
        (user_id,),
    ).fetchall()


def list_user_communities_random(user_id: int, limit: int = 12):
    db = get_db()
    return db.execute(
        """
        SELECT c.id, c.name, c.icon_path
        FROM community_members cm
        JOIN communities c ON c.id = cm.community_id
        WHERE cm.user_id = ?
        ORDER BY RANDOM()
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()


# -----------------------------
# Helpers (topics)
# -----------------------------
def list_topics_paginated(community_id: int, page: int):
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) AS c FROM community_topics WHERE community_id = ?",
        (community_id,),
    ).fetchone()["c"]
    meta = pagination_meta(total, page, PAGE_SIZE)
    offset = (meta["page"] - 1) * meta["page_size"]

    rows = db.execute(
        """
        SELECT t.id, t.title, t.created_at, t.updated_at, t.created_by_user_id,
               u.display_name AS created_by_name, u.username AS created_by_username
        FROM community_topics t
        JOIN users u ON u.id = t.created_by_user_id
        WHERE t.community_id = ?
        ORDER BY t.updated_at DESC
        LIMIT ? OFFSET ?
        """,
        (community_id, meta["page_size"], offset),
    ).fetchall()
    return rows, meta


def get_topic(topic_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT t.id, t.community_id, t.title, t.created_at, t.updated_at,
               u.display_name AS created_by_name, u.username AS created_by_username,
               t.created_by_user_id
        FROM community_topics t
        JOIN users u ON u.id = t.created_by_user_id
        WHERE t.id = ?
        """,
        (topic_id,),
    ).fetchone()


def list_topic_messages_paginated(topic_id: int, page: int):
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) AS c FROM topic_messages WHERE topic_id = ?",
        (topic_id,),
    ).fetchone()["c"]
    meta = pagination_meta(total, page, PAGE_SIZE)
    offset = (meta["page"] - 1) * meta["page_size"]

    rows = db.execute(
        """
        SELECT tm.id, tm.content, tm.created_at, tm.from_user_id,
               u.display_name AS from_name, u.username AS from_username, u.profile_pic_path AS from_pic
        FROM topic_messages tm
        JOIN users u ON u.id = tm.from_user_id
        WHERE tm.topic_id = ?
        ORDER BY tm.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (topic_id, meta["page_size"], offset),
    ).fetchall()
    return rows, meta


def create_topic(community_id: int, title: str, created_by_user_id: int):
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute(
        """
        INSERT INTO community_topics (community_id, title, created_by_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (community_id, title, created_by_user_id, now, now),
    )
    db.commit()


def add_topic_message(topic_id: int, from_user_id: int, content: str):
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute(
        """
        INSERT INTO topic_messages (topic_id, from_user_id, content, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (topic_id, from_user_id, content, now),
    )
    db.execute("UPDATE community_topics SET updated_at = ? WHERE id = ?", (now, topic_id))
    db.commit()


# -----------------------------
# Helpers (invites)
# -----------------------------
def get_invites_remaining(user_id: int) -> int:
    db = get_db()
    row = db.execute("SELECT invites_remaining FROM users WHERE id = ?", (user_id,)).fetchone()
    return int(row["invites_remaining"] or 0)


def create_invite_token(inviter_user_id: int) -> str:
    token = secrets.token_urlsafe(24)
    db = get_db()
    db.execute(
        "INSERT INTO invite_tokens (token, inviter_user_id, created_at) VALUES (?, ?, ?)",
        (token, inviter_user_id, datetime.utcnow().isoformat()),
    )
    db.commit()
    return token


def get_invite(token: str):
    db = get_db()
    return db.execute(
        """
        SELECT it.*, u.display_name AS inviter_name, u.username AS inviter_username, u.invites_remaining AS inviter_invites
        FROM invite_tokens it
        JOIN users u ON u.id = it.inviter_user_id
        WHERE it.token = ?
        """,
        (token,),
    ).fetchone()


def mark_invite_used(token: str, used_by_user_id: int):
    db = get_db()
    db.execute(
        "UPDATE invite_tokens SET used_at = ?, used_by_user_id = ? WHERE token = ?",
        (datetime.utcnow().isoformat(), used_by_user_id, token),
    )
    db.commit()


def decrement_invites(inviter_user_id: int):
    db = get_db()
    db.execute(
        """
        UPDATE users
        SET invites_remaining = CASE WHEN invites_remaining > 0 THEN invites_remaining - 1 ELSE 0 END
        WHERE id = ?
        """,
        (inviter_user_id,),
    )
    db.commit()


def validate_username(username: str) -> str | None:
    if not username:
        return "Username is required."
    if len(username) < 3 or len(username) > 20:
        return "Username must be 3 to 20 characters."
    if not re.fullmatch(r"[a-zA-Z0-9_]+", username):
        return "Username can only contain letters, numbers and underscore."
    return None


def validate_password(pw: str) -> str | None:
    # at least 8, one lower, one upper, one symbol
    if not pw or len(pw) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[a-z]", pw):
        return "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", pw):
        return "Password must contain an uppercase letter."
    if not re.search(r"[^a-zA-Z0-9]", pw):
        return "Password must contain a symbol."
    return None


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


def _recent_activities_for_home(viewer_id: int):
    """
    - friend message received: "{Friend} has received a message from {Sender} (timestamp)"
      (only for viewer's friends)
    - community activity: "{Community} had activity (timestamp)"
      (only for communities where viewer is a member)
    max 5 combined, sorted desc
    """
    db = get_db()

    friend_ids = [r["id"] for r in list_friends(viewer_id)]
    activities = []

    if friend_ids:
        q_marks = ",".join(["?"] * len(friend_ids))
        rows = db.execute(
            f"""
            SELECT m.created_at, fu.display_name AS to_name, su.display_name AS from_name
            FROM messages m
            JOIN users fu ON fu.id = m.to_user_id
            JOIN users su ON su.id = m.from_user_id
            WHERE m.type = 'message' AND m.to_user_id IN ({q_marks})
            ORDER BY m.created_at DESC
            LIMIT 10
            """,
            tuple(friend_ids),
        ).fetchall()

        for r in rows:
            activities.append(
                {
                    "ts": r["created_at"],
                    "text": f"{r['to_name']} has received a message from {r['from_name']} ({r['created_at']})",
                }
            )

    comm_rows = db.execute(
        """
        SELECT c.id AS community_id, c.name AS community_name, MAX(tm.created_at) AS last_ts
        FROM community_members cm
        JOIN communities c ON c.id = cm.community_id
        JOIN community_topics t ON t.community_id = c.id
        JOIN topic_messages tm ON tm.topic_id = t.id
        WHERE cm.user_id = ?
        GROUP BY c.id, c.name
        ORDER BY last_ts DESC
        LIMIT 10
        """,
        (viewer_id,),
    ).fetchall()

    for r in comm_rows:
        activities.append(
            {
                "ts": r["last_ts"],
                "text": f"{r['community_name']} had activity ({r['last_ts']})",
            }
        )

    # sort by ts desc and pick top 5
    activities.sort(key=lambda x: x["ts"] or "", reverse=True)
    return activities[:5]


@app.get("/home")
@login_required
def home():
    user = current_user()
    db = get_db()

    pending_requests_count = count_pending_friend_requests(user["id"])
    messages_total_count = count_messages_total(user["id"])
    messages_unread_count = count_messages_unread(user["id"])

    friends_random = list_friends_random(user["id"], limit=12)
    communities_random = list_user_communities_random(user["id"], limit=12)

    all_users = db.execute("SELECT id, username, display_name FROM users ORDER BY display_name ASC").fetchall()

    cards = []
    for u in all_users:
        if u["id"] == user["id"]:
            continue
        if are_friends(user["id"], u["id"]):
            continue

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

    recent_activities = _recent_activities_for_home(user["id"])

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
        recent_activities=recent_activities,
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
    communities_random = list_user_communities_random(user["id"], limit=12)

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
    mark_inbox_read(user["id"])
    return redirect(url_for("user_profile", username=user["username"]))


@app.get("/u/<username>")
@login_required
def user_profile(username):
    viewer = current_user()
    profile_user = get_user_by_username(username)
    if not profile_user:
        abort(404)

    mark_inbox_read(viewer["id"])

    pending_requests_count = count_pending_friend_requests(viewer["id"])
    messages_total_count = count_messages_total(viewer["id"])
    messages_unread_count = count_messages_unread(viewer["id"])

    friends_random = list_friends_random(profile_user["id"], limit=12)
    communities_random = list_user_communities_random(profile_user["id"], limit=12)
    communities_all_for_profile = list_user_communities_all(profile_user["id"])

    is_owner = (viewer["id"] == profile_user["id"])
    is_friend = are_friends(viewer["id"], profile_user["id"]) if not is_owner else True

    page = get_page_param()
    wall_messages, wall_pagination = get_wall_messages(profile_user["id"], page)

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
        communities_all_for_profile=communities_all_for_profile,
        wall_messages=wall_messages,
        wall_pagination=wall_pagination,
    )


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


@app.post("/messages/<int:message_id>/delete")
@login_required
def delete_profile_message(message_id):
    viewer = current_user()
    db = get_db()

    msg = db.execute(
        """
        SELECT id, from_user_id, to_user_id, type
        FROM messages
        WHERE id = ? AND type = 'message'
        """,
        (message_id,),
    ).fetchone()
    if not msg:
        abort(404)

    if viewer["id"] not in (msg["to_user_id"], msg["from_user_id"]):
        abort(403)

    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()

    ref = request.form.get("redirect_to")
    if ref:
        return redirect(ref)

    return redirect(url_for("messages"))


@app.get("/edit-profile")
@login_required
def edit_profile():
    user = current_user()
    return render_template(
        "edit_profile.html",
        app_name=APP_NAME,
        user=user,
        sex_options=SEX_OPTIONS,
        orientation_options=ORIENTATION_OPTIONS,
        relationship_options=RELATIONSHIP_OPTIONS,
        politics_options=POLITICS_OPTIONS,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/edit-profile")
@login_required
def edit_profile_post():
    user = current_user()

    name = (request.form.get("display_name") or "").strip()
    desc = (request.form.get("description") or "").strip()

    birthdate = (request.form.get("birthdate") or "").strip() or None
    sex = (request.form.get("sex") or "").strip() or None
    orientation = (request.form.get("sexual_orientation") or "").strip() or None
    relationship = (request.form.get("relationship_status") or "").strip() or None
    politics = (request.form.get("political_orientation") or "").strip() or None
    favorite_team = (request.form.get("favorite_team") or "").strip() or None
    main_hobby = (request.form.get("main_hobby") or "").strip() or None

    if not name:
        flash("Name cannot be empty.")
        return redirect(url_for("edit_profile"))

    if sex and sex not in SEX_OPTIONS:
        flash("Invalid sex option.")
        return redirect(url_for("edit_profile"))
    if orientation and orientation not in ORIENTATION_OPTIONS:
        flash("Invalid orientation option.")
        return redirect(url_for("edit_profile"))
    if relationship and relationship not in RELATIONSHIP_OPTIONS:
        flash("Invalid relationship option.")
        return redirect(url_for("edit_profile"))
    if politics and politics not in POLITICS_OPTIONS:
        flash("Invalid political option.")
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
            """
            UPDATE users
            SET display_name = ?, description = ?, profile_pic_path = ?,
                birthdate = ?, sex = ?, sexual_orientation = ?, relationship_status = ?,
                political_orientation = ?, favorite_team = ?, main_hobby = ?
            WHERE id = ?
            """,
            (
                name, desc, rel_path,
                birthdate, sex, orientation, relationship,
                politics, favorite_team, main_hobby,
                user["id"],
            ),
        )
    else:
        db.execute(
            """
            UPDATE users
            SET display_name = ?, description = ?,
                birthdate = ?, sex = ?, sexual_orientation = ?, relationship_status = ?,
                political_orientation = ?, favorite_team = ?, main_hobby = ?
            WHERE id = ?
            """,
            (
                name, desc,
                birthdate, sex, orientation, relationship,
                politics, favorite_team, main_hobby,
                user["id"],
            ),
        )
    db.commit()

    flash("Profile updated.")
    return redirect(url_for("my_profile_redirect"))


@app.get("/friends")
@login_required
def friends_page():
    user = current_user()
    friends = list_friends(user["id"])
    invites_remaining = get_invites_remaining(user["id"])

    invite_link = session.pop("last_invite_link", None)

    return render_template(
        "friends.html",
        app_name=APP_NAME,
        user=user,
        friends=friends,
        invites_remaining=invites_remaining,
        invite_link=invite_link,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/invites/create")
@login_required
def invites_create():
    user = current_user()
    remaining = get_invites_remaining(user["id"])
    if remaining <= 0:
        flash("You have no invites remaining.")
        return redirect(url_for("friends_page"))

    token = create_invite_token(user["id"])
    link = url_for("create_profile_from_invite", token=token, _external=True)

    session["last_invite_link"] = link
    flash("Invite link generated.")
    return redirect(url_for("friends_page"))


@app.get("/invite/<token>")
def create_profile_from_invite(token):
    inv = get_invite(token)
    if not inv:
        return render_template("create_profile.html", app_name=APP_NAME, invalid=True)

    if inv["used_at"] is not None:
        return render_template("create_profile.html", app_name=APP_NAME, already_used=True)

    if int(inv["inviter_invites"] or 0) <= 0:
        return render_template("create_profile.html", app_name=APP_NAME, no_invites=True)

    return render_template(
        "create_profile.html",
        app_name=APP_NAME,
        token=token,
        inviter_name=inv["inviter_name"],
        inviter_username=inv["inviter_username"],
        sex_options=SEX_OPTIONS,
        orientation_options=ORIENTATION_OPTIONS,
        relationship_options=RELATIONSHIP_OPTIONS,
        politics_options=POLITICS_OPTIONS,
    )


@app.post("/invite/<token>")
def create_profile_from_invite_post(token):
    inv = get_invite(token)
    if not inv:
        flash("Invalid invite link.")
        return redirect(url_for("login"))

    if inv["used_at"] is not None:
        flash("This invite link has already been used.")
        return redirect(url_for("login"))

    inviter_id = int(inv["inviter_user_id"])
    inviter_remaining = int(inv["inviter_invites"] or 0)
    if inviter_remaining <= 0:
        flash("This inviter has no invites remaining.")
        return redirect(url_for("login"))

    username = (request.form.get("username") or "").strip()
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password2") or ""

    display_name = (request.form.get("display_name") or "").strip()
    desc = (request.form.get("description") or "").strip()

    birthdate = (request.form.get("birthdate") or "").strip() or None
    sex = (request.form.get("sex") or "").strip() or None
    orientation = (request.form.get("sexual_orientation") or "").strip() or None
    relationship = (request.form.get("relationship_status") or "").strip() or None
    politics = (request.form.get("political_orientation") or "").strip() or None
    favorite_team = (request.form.get("favorite_team") or "").strip() or None
    main_hobby = (request.form.get("main_hobby") or "").strip() or None

    err = validate_username(username)
    if err:
        flash(err)
        return redirect(url_for("create_profile_from_invite", token=token))

    perr = validate_password(pw1)
    if perr:
        flash(perr)
        return redirect(url_for("create_profile_from_invite", token=token))

    if pw1 != pw2:
        flash("Passwords do not match.")
        return redirect(url_for("create_profile_from_invite", token=token))

    if not display_name:
        flash("Name is required.")
        return redirect(url_for("create_profile_from_invite", token=token))

    if sex and sex not in SEX_OPTIONS:
        flash("Invalid sex option.")
        return redirect(url_for("create_profile_from_invite", token=token))
    if orientation and orientation not in ORIENTATION_OPTIONS:
        flash("Invalid orientation option.")
        return redirect(url_for("create_profile_from_invite", token=token))
    if relationship and relationship not in RELATIONSHIP_OPTIONS:
        flash("Invalid relationship option.")
        return redirect(url_for("create_profile_from_invite", token=token))
    if politics and politics not in POLITICS_OPTIONS:
        flash("Invalid political option.")
        return redirect(url_for("create_profile_from_invite", token=token))

    pic = request.files.get("profile_pic")
    rel_path = None
    if pic and pic.filename:
        rel_path = save_upload(pic, "profiles", prefix=f"invited_user")
        if rel_path is None:
            flash("Invalid file. Please upload PNG or JPG.")
            return redirect(url_for("create_profile_from_invite", token=token))

    db = get_db()
    existing = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        flash("Username already taken.")
        return redirect(url_for("create_profile_from_invite", token=token))

    # Create new user
    pw_hash = generate_password_hash(pw1)
    db.execute(
        """
        INSERT INTO users (
          username, password_hash, display_name, description,
          profile_pic_path,
          birthdate, sex, sexual_orientation, relationship_status,
          political_orientation, favorite_team, main_hobby,
          invites_remaining
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username, pw_hash, display_name, desc,
            rel_path,
            birthdate, sex, orientation, relationship,
            politics, favorite_team, main_hobby,
            DEFAULT_INVITES,  # invited users start with 5 (same rule)
        ),
    )
    db.commit()

    new_user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]

    # Mark invite used + decrement inviter invites
    mark_invite_used(token, new_user_id)
    decrement_invites(inviter_id)

    # Auto-friend with inviter
    make_friendship(inviter_id, new_user_id)

    flash("Profile created! You can login now.")
    return redirect(url_for("login"))


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

    inbox = get_inbox_messages(user["id"])
    return render_template(
        "messages.html",
        app_name=APP_NAME,
        user=user,
        inbox=inbox,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


# -----------------------------
# Communities (unchanged routes below here except already in your version)
# -----------------------------
@app.get("/communities")
@login_required
def communities_page():
    user = current_user()
    communities = list_communities_all()
    return render_template(
        "communities.html",
        app_name=APP_NAME,
        user=user,
        communities=communities,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/communities/create")
@login_required
def create_community_route():
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
    now = datetime.utcnow().isoformat()
    db.execute(
        """
        INSERT INTO communities (name, description, icon_path, created_by_user_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (name, desc, icon_path, user["id"], now),
    )
    db.commit()

    community_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    add_member(user["id"], community_id)

    flash("Community created.")
    return redirect(url_for("communities_page"))


@app.get("/c/<int:cid>")
@login_required
def community_page(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    member = is_member(user["id"], cid)
    creator = (community["created_by_user_id"] == user["id"])

    members_random = list_members_random(cid, limit=12)

    page = get_page_param()
    topics, topics_pagination = list_topics_paginated(cid, page)

    return render_template(
        "community.html",
        app_name=APP_NAME,
        user=user,
        community=community,
        is_member=member,
        is_creator=creator,
        members_random=members_random,
        topics=topics,
        topics_pagination=topics_pagination,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/c/<int:cid>/join")
@login_required
def community_join(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    add_member(user["id"], cid)
    flash("You joined the community.")
    return redirect(url_for("community_page", cid=cid))


@app.post("/c/<int:cid>/leave")
@login_required
def community_leave(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    if community["created_by_user_id"] == user["id"]:
        flash("The creator cannot leave the community.")
        return redirect(url_for("community_page", cid=cid))

    remove_member(user["id"], cid)
    flash("You left the community.")
    return redirect(url_for("community_page", cid=cid))


@app.get("/c/<int:cid>/members")
@login_required
def community_members(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    members = list_members_all(cid)
    member = is_member(user["id"], cid)
    creator = (community["created_by_user_id"] == user["id"])

    return render_template(
        "community_members.html",
        app_name=APP_NAME,
        user=user,
        community=community,
        members=members,
        is_member=member,
        is_creator=creator,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.get("/c/<int:cid>/edit")
@login_required
def edit_community(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    if community["created_by_user_id"] != user["id"]:
        abort(403)

    return render_template(
        "edit_community.html",
        app_name=APP_NAME,
        user=user,
        community=community,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/c/<int:cid>/edit")
@login_required
def edit_community_post(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    if community["created_by_user_id"] != user["id"]:
        abort(403)

    name = (request.form.get("name") or "").strip()
    desc = (request.form.get("description") or "").strip()

    if not name:
        flash("Community name cannot be empty.")
        return redirect(url_for("edit_community", cid=cid))

    icon = request.files.get("icon")
    icon_path = None
    if icon and icon.filename:
        icon_path = save_upload(icon, "communities", prefix=f"community_{cid}")
        if icon_path is None:
            flash("Invalid icon. Please upload PNG or JPG.")
            return redirect(url_for("edit_community", cid=cid))

    db = get_db()
    if icon_path:
        db.execute(
            "UPDATE communities SET name = ?, description = ?, icon_path = ? WHERE id = ?",
            (name, desc, icon_path, cid),
        )
    else:
        db.execute("UPDATE communities SET name = ?, description = ? WHERE id = ?", (name, desc, cid))
    db.commit()

    flash("Community updated.")
    return redirect(url_for("community_page", cid=cid))


@app.post("/c/<int:cid>/delete")
@login_required
def delete_community(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    if community["created_by_user_id"] != user["id"]:
        abort(403)

    db = get_db()

    topic_ids = db.execute("SELECT id FROM community_topics WHERE community_id = ?", (cid,)).fetchall()
    for t in topic_ids:
        db.execute("DELETE FROM topic_messages WHERE topic_id = ?", (t["id"],))
    db.execute("DELETE FROM community_topics WHERE community_id = ?", (cid,))

    db.execute("DELETE FROM community_members WHERE community_id = ?", (cid,))
    db.execute("DELETE FROM communities WHERE id = ?", (cid,))
    db.commit()

    flash("Community deleted.")
    return redirect(url_for("communities_page"))


@app.post("/c/<int:cid>/topics/create")
@login_required
def create_topic_route(cid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    if not is_member(user["id"], cid):
        flash("Only members can create topics.")
        return redirect(url_for("community_page", cid=cid))

    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Topic title cannot be empty.")
        return redirect(url_for("community_page", cid=cid))
    if len(title) > 80:
        flash("Topic title is too long (max 80 characters).")
        return redirect(url_for("community_page", cid=cid))

    create_topic(cid, title, user["id"])
    flash("Topic created.")
    return redirect(url_for("community_page", cid=cid))


@app.post("/c/<int:cid>/topics/<int:tid>/delete")
@login_required
def delete_topic(cid, tid):
    user = current_user()
    topic = get_topic(tid)
    if not topic or topic["community_id"] != cid:
        abort(404)

    if topic["created_by_user_id"] != user["id"]:
        abort(403)

    db = get_db()
    db.execute("DELETE FROM topic_messages WHERE topic_id = ?", (tid,))
    db.execute("DELETE FROM community_topics WHERE id = ?", (tid,))
    db.commit()

    flash("Topic deleted.")
    return redirect(url_for("community_page", cid=cid))


@app.get("/c/<int:cid>/t/<int:tid>")
@login_required
def topic_page(cid, tid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    topic = get_topic(tid)
    if not topic or topic["community_id"] != cid:
        abort(404)

    member = is_member(user["id"], cid)
    creator = (community["created_by_user_id"] == user["id"])

    members_random = list_members_random(cid, limit=12)

    page = get_page_param()
    msgs, msgs_pagination = list_topic_messages_paginated(tid, page)

    return render_template(
        "topic.html",
        app_name=APP_NAME,
        user=user,
        community=community,
        topic=topic,
        is_member=member,
        is_creator=creator,
        members_random=members_random,
        messages=msgs,
        messages_pagination=msgs_pagination,
        pending_requests_count=count_pending_friend_requests(user["id"]),
        messages_total_count=count_messages_total(user["id"]),
        messages_unread_count=count_messages_unread(user["id"]),
    )


@app.post("/c/<int:cid>/t/<int:tid>/message")
@login_required
def post_topic_message(cid, tid):
    user = current_user()
    community = get_community_by_id(cid)
    if not community:
        abort(404)

    topic = get_topic(tid)
    if not topic or topic["community_id"] != cid:
        abort(404)

    if not is_member(user["id"], cid):
        flash("Only members can post messages.")
        return redirect(url_for("topic_page", cid=cid, tid=tid))

    content = (request.form.get("content") or "").strip()
    if not content:
        flash("Message cannot be empty.")
        return redirect(url_for("topic_page", cid=cid, tid=tid))
    if len(content) > 500:
        flash("Message is too long (max 500 characters).")
        return redirect(url_for("topic_page", cid=cid, tid=tid))

    add_topic_message(tid, user["id"], content)
    return redirect(url_for("topic_page", cid=cid, tid=tid))


@app.post("/c/<int:cid>/t/<int:tid>/messages/<int:mid>/delete")
@login_required
def delete_topic_message(cid, tid, mid):
    user = current_user()
    topic = get_topic(tid)
    if not topic or topic["community_id"] != cid:
        abort(404)

    db = get_db()
    msg = db.execute(
        """
        SELECT id, topic_id, from_user_id
        FROM topic_messages
        WHERE id = ? AND topic_id = ?
        """,
        (mid, tid),
    ).fetchone()
    if not msg:
        abort(404)

    if user["id"] not in (msg["from_user_id"], topic["created_by_user_id"]):
        abort(403)

    db.execute("DELETE FROM topic_messages WHERE id = ?", (mid,))
    db.commit()

    ref = request.form.get("redirect_to")
    if ref:
        return redirect(ref)
    return redirect(url_for("topic_page", cid=cid, tid=tid))


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
