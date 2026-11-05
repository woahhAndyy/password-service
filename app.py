"""A classroom microservice: its own UI, JSON API, and PostgreSQL data.

Set DATABASE_URL, then run python app.py. Open http://localhost:8000.
Use demonstration passwords.
"""

import hashlib
import os
import re
import secrets

import psycopg
from flask import Flask, jsonify, render_template, request
from psycopg.rows import dict_row
from waitress import serve
from werkzeug.exceptions import BadRequest, HTTPException, Unauthorized
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(database_url=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["DATABASE_URL"] = database_url or os.getenv("DATABASE_URL")
    if not app.config["DATABASE_URL"]:
        raise RuntimeError("Set DATABASE_URL to your PostgreSQL connection string. See README.md.")

    def database():
        """Each operation commits on success, rolls back on error, then closes."""
        return psycopg.connect(
            app.config["DATABASE_URL"], row_factory=dict_row, connect_timeout=10,
            prepare_threshold=None,  # Also works with hosted transaction poolers.
        )

    # The database already exists; startup creates this service's table.
    with database() as db:
        # Serialize table creation when several replicas start together.
        # This transaction-scoped lock is released automatically at commit.
        db.execute("SELECT pg_advisory_xact_lock(73006, 1)")
        db.execute("""CREATE TABLE IF NOT EXISTS passwords (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            recovery_hash TEXT NOT NULL
        )""")

    def body(*fields):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise BadRequest("Send a JSON object.")
        for name in fields:
            value = data.get(name)
            if not isinstance(value, str) or not 1 <= len(value) <= 128:
                raise BadRequest(f"{name} must be text between 1 and 128 characters.")
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise BadRequest("Use valid Unicode text.") from None
        if "username" in fields and not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", data["username"]):
            raise BadRequest("Username: use 1–40 letters, numbers, dots, underscores or hyphens.")
        return data

    def new_password(value):
        if not 8 <= len(value) <= 128:
            raise BadRequest("Use a password between 8 and 128 characters.")
        return generate_password_hash(value)

    def recovery_digest(code):
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def find(db, username):
        return db.execute("SELECT * FROM passwords WHERE username = %s", (username,)).fetchone()

    def require_password(row, password):
        if row is None or not check_password_hash(row["password_hash"], password):
            raise Unauthorized("Username or password is incorrect.")

    @app.errorhandler(HTTPException)
    def request_error(error):
        return jsonify(error=error.description), error.code

    @app.errorhandler(psycopg.Error)
    def database_error(error):
        return jsonify(error="Database unavailable. Please try again."), 503

    @app.after_request
    def no_cache(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.get("/health")
    def health():
        with database() as db:
            db.execute("SELECT 1 FROM passwords LIMIT 1")
        return jsonify(status="ok")

    @app.post("/api/passwords")
    def create_password():
        data = body("username", "password")
        password_hash = new_password(data["password"])
        code = secrets.token_urlsafe(24)
        try:
            with database() as db:
                db.execute("INSERT INTO passwords (username, password_hash, recovery_hash) VALUES (%s, %s, %s)",
                           (data["username"], password_hash, recovery_digest(code)))
        except psycopg.errors.UniqueViolation:
            return jsonify(error="That username already has a password."), 409
        return jsonify(message="Password created. Save your recovery code.",
                       username=data["username"], recovery_code=code), 201

    @app.post("/api/passwords/check")
    def check_password():
        data = body("username", "password")
        with database() as db:
            row = find(db, data["username"])
        valid = bool(row and check_password_hash(row["password_hash"], data["password"]))
        return jsonify(valid=valid, message="Password matches." if valid else "Username or password is incorrect.")

    @app.post("/api/passwords/change")
    def change_password():
        data = body("username", "current_password", "new_password")
        with database() as db:
            row = find(db, data["username"])
            require_password(row, data["current_password"])
            # Match the old hash too: a simultaneous change must not be overwritten.
            changed = db.execute(
                "UPDATE passwords SET password_hash = %s WHERE username = %s AND password_hash = %s",
                (new_password(data["new_password"]), data["username"], row["password_hash"])
            ).rowcount
            if not changed:
                return jsonify(error="Password changed in another request. Try again."), 409
        return jsonify(message="Password changed.")

    @app.post("/api/passwords/reset")
    def reset_password():
        data = body("username", "recovery_code", "new_password")
        code = secrets.token_urlsafe(24)
        with database() as db:
            row = find(db, data["username"])
            if row is None or not secrets.compare_digest(
                row["recovery_hash"], recovery_digest(data["recovery_code"])
            ):
                raise Unauthorized("Username or recovery code is incorrect.")
            changed = db.execute(
                """UPDATE passwords SET password_hash = %s, recovery_hash = %s
                   WHERE username = %s AND password_hash = %s AND recovery_hash = %s""",
                (new_password(data["new_password"]), recovery_digest(code),
                 data["username"], row["password_hash"], row["recovery_hash"])
            ).rowcount
            if not changed:
                return jsonify(error="Credential changed in another request. Try again."), 409
        return jsonify(message="Password reset. Save your new recovery code.", recovery_code=code)

    @app.delete("/api/passwords")
    def delete_password():
        data = body("username", "password")
        with database() as db:
            row = find(db, data["username"])
            require_password(row, data["password"])
            deleted = db.execute(
                "DELETE FROM passwords WHERE username = %s AND password_hash = %s",
                (data["username"], row["password_hash"])
            ).rowcount
            if not deleted:
                return jsonify(error="Password changed in another request. Try again."), 409
        return jsonify(message="Password record deleted.")

    @app.post("/api/passwords/validate")
    def validate_password():
        data = body("password")
        valid = 8 <= len(data["password"]) <= 128
        return jsonify(valid=valid, message="Password length accepted." if valid
                       else "Use a password between 8 and 128 characters.")

    return app


if __name__ == "__main__":
    try:
        app = create_app()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except psycopg.Error:
        raise SystemExit(
            "Cannot connect to PostgreSQL or create its table. Check DATABASE_URL, "
            "network access, and database permissions. See README.md."
        ) from None
    port = int(os.getenv("PORT", "8000"))
    print(f"Password service: open http://localhost:{port}", flush=True)
    serve(app, host="0.0.0.0", port=port, threads=4)
