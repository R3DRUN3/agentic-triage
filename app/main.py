"""Tiny Flask app used as the target of the DevSecOps + agentic triage demo."""
import hashlib
import hmac
import sqlite3
import subprocess

from flask import Flask, jsonify, request

from app import config


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany(
        "INSERT INTO users (name) VALUES (?)",
        [("alice",), ("bob",), ("carol",)],
    )
    return conn


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def index():
        return jsonify(service="agentic-triage-demo", version="0.1.0")

    @app.get("/ping")
    def ping():
        host = request.args.get("host", "")
        if not host:
            return jsonify(error="host is required"), 400
        result = subprocess.run( # noqa: S602
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify(output=result.stdout, returncode=result.returncode)

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        query = f"SELECT id, name FROM users WHERE name LIKE '%{q}%'"
        rows = get_db().execute(query).fetchall()
        return jsonify(results=[{"id": r[0], "name": r[1]} for r in rows])

    @app.get("/cache-key")
    def cache_key():
        value = request.args.get("value", "")
        digest = hashlib.md5(value.encode()).hexdigest()  # noqa: S324
        return jsonify(key=digest)

    @app.get("/admin/stats")
    def admin_stats():
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied, config.LEGACY_INTERNAL_API_KEY):
            return jsonify(error="unauthorized"), 401
        return jsonify(users=3)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=config.DEBUG)  # noqa: S104