import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = "MyFaceYourFace"
DB_PATH = os.environ.get("DB_PATH", "myface.db")

# ⚠️ Para demo local: você pediu essas credenciais.
# Depois, mova para env vars e mude as senhas.
DEFAULT_ADMIN_USER = os.environ.get("DEFAULT_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("DEFAULT_ADMIN_PASS", "admin311286?")

DEFAULT_Tiago_USER = os.environ.get("DEFAULT_Tiago_USER", "tiagoluis86")
DEFAULT_Tiago_PASS = os.environ.get("DEFAULT_Tiago_PASS", "Quadrado86?")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


# -----------------------------
# DB helpers
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

        -- amizade bidirecional (uma linha por direção)
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            UNIQUE(user_id, friend_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(friend_id) REFERENCES users(id)
        );

        -- por enquanto usamos messages só para friend_request
        -- depois pode ampliar para mensagens normais
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            type TEXT NOT NULL,   -- 'friend_request' | 'message'
            status TEXT NOT NULL, -- friend_request: 'pending' | 'accepted' | 'rejected'
            content TEXT DEFAULT NULL, -- para messages normais futuramente
            created_at TEXT NOT NULL,
            FOREIGN KEY(from_user_id) REFERENCES users(id),
            FOREIGN KEY(to_user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()


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

    ensure_user(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, "Admin", "Conta administrativa.")
    ensure_user(DEFAULT_Tiago_USER, DEFAULT_Tiago_PASS, "Tiago Luis Custódio", "Conta de teste.")


@app.before_request
def setup():
    init_db()
    seed_default_users()


# -----------------------------
# Auth helpers
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
# Counts & lists
# -----------------------------
def count_pending_requests(user_id: int) -> int:
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


def count_messages(user_id: int) -> int:
    # Por enquanto não temos mensagens normais implementadas (type='message').
    # Mantém 0 para o UI.
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


def list_friends(user_id: int):
    db = get_db()
    return db.execute(
        """
        SELECT u.id, u.username, u.display_name
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
        SELECT u.id, u.username, u.display_name
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
        flash("Usuário ou senha inválidos.")
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

    all_users = db.execute(
        "SELECT id, username, display_name FROM users ORDER BY display_name ASC"
    ).fetchall()

    friends_random = list_friends_random(user["id"], limit=12)
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])

    # cards "Você talvez conheça:"
    cards = []
    for u in all_users:
        if u["id"] == user["id"]:
            continue

        can_request = True
        label = "Solicitar amizade"

        if are_friends(user["id"], u["id"]):
            can_request = False
            label = "Já são amigos"
        elif has_pending_request(user["id"], u["id"]):
            can_request = False
            label = "Solicitação enviada"
        elif has_pending_request(u["id"], user["id"]):
            can_request = False
            label = "Ele(a) já solicitou"

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
        messages_count=messages_count,
        friends_random=friends_random,
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
    flash("Solicitação de amizade enviada!")
    return redirect(url_for("home"))


@app.get("/profile")
@login_required
def profile():
    user = current_user()
    friends_random = list_friends_random(user["id"], limit=12)
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])

    return render_template(
        "profile.html",
        app_name=APP_NAME,
        user=user,
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
        friends_random=friends_random,
    )


@app.get("/friends")
@login_required
def friends_page():
    user = current_user()
    friends = list_friends(user["id"])
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])

    return render_template(
        "friends.html",
        app_name=APP_NAME,
        user=user,
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
        friends=friends,
    )


# Solicitações de amizade SEPARADAS de messages
@app.get("/requests")
@login_required
def requests_page():
    user = current_user()
    db = get_db()

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

    friends_random = list_friends_random(user["id"], limit=12)
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])

    return render_template(
        "requests.html",
        app_name=APP_NAME,
        user=user,
        pending_requests=pending,
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
        friends_random=friends_random,
    )


@app.post("/requests/<int:msg_id>/accept")
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
        return redirect(url_for("requests_page"))

    make_friendship(msg["from_user_id"], msg["to_user_id"])
    db.execute("UPDATE messages SET status = 'accepted' WHERE id = ?", (msg_id,))
    db.commit()
    flash("Amizade aceita!")
    return redirect(url_for("requests_page"))


@app.post("/requests/<int:msg_id>/reject")
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
    flash("Solicitação rejeitada.")
    return redirect(url_for("requests_page"))


# Messages (placeholder por enquanto)
@app.get("/messages")
@login_required
def messages():
    user = current_user()
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Messages",
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
    )


@app.get("/communities")
@login_required
def communities_page():
    user = current_user()
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Communities",
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
    )


@app.get("/settings")
@login_required
def settings_page():
    user = current_user()
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Settings",
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
    )


@app.get("/help")
@login_required
def help_page():
    user = current_user()
    pending_requests_count = count_pending_requests(user["id"])
    messages_count = count_messages(user["id"])
    return render_template(
        "simple.html",
        app_name=APP_NAME,
        title="Help",
        pending_requests_count=pending_requests_count,
        messages_count=messages_count,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
