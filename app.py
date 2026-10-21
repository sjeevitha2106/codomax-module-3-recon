
import os
import hmac
import secrets
import sqlite3
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Please set the SECRET_KEY environment variable.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

DB_PATH = Path(__file__).resolve().parent / "students.db"


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def csrf_protection():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")

        if not supplied or not expected:
            app.logger.warning("CSRF token missing")
            abort(400)

        if not hmac.compare_digest(supplied, expected):
            app.logger.warning("CSRF token mismatch")
            abort(400)


def create_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    create_csrf_token()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) > 80 or len(password) > 200:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        with get_db() as db:
            user = db.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            create_csrf_token()
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
        return redirect(url_for("login"))

    return render_template(
        "login.html",
        csrf_token=session["csrf_token"],
    )


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        student = db.execute(
            "SELECT full_name, course, marks FROM students WHERE user_id = ?",
            (session["user_id"],),
        ).fetchone()

    if student is None:
        abort(404)

    return render_template(
        "dashboard.html",
        student=student,
        csrf_token=create_csrf_token(),
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(error):
    return render_template(
        "error.html", code=400, message="Invalid request."
    ), 400


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html", code=404, message="Page not found."
    ), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
