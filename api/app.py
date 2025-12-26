from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import logging
from pathlib import Path

app = Flask(__name__)

# ✅ Secret moved to environment variable
API_KEY = os.environ.get("API_KEY", "not-set")

# ✅ Secure logging level
logging.basicConfig(level=logging.INFO)

DATABASE = "users.db"
SAFE_DIR = Path("/app/files")  # directory autorisé pour lecture de fichiers


# ---------- AUTH (SQL Injection FIX) ----------
@app.route("/auth", methods=["POST"])
def auth():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return {"status": "invalid input"}, 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ✅ Parametrized query
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        return {"status": "authenticated"}
    return {"status": "denied"}, 401


# ---------- COMMAND EXECUTION (Command Injection FIX) ----------
@app.route("/exec", methods=["POST"])
def exec_cmd():
    data = request.json or {}
    host = data.get("host", "8.8.8.8")

    # ✅ No shell=True
    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        stderr=subprocess.STDOUT,
        timeout=5
    )

    return {"output": output.decode()}


# ---------- DESERIALIZATION (Pickle REMOVED) ----------
@app.route("/deserialize", methods=["POST"])
def deserialize():
    # ✅ Use safe formats (JSON)
    data = request.json
    return {"object": data}


# ---------- HASHING (MD5 FIX) ----------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "")
    hashed = hashlib.sha256(text.encode()).hexdigest()
    return {"hash": hashed}


# ---------- FILE ACCESS (Path Traversal FIX) ----------
@app.route("/file", methods=["POST"])
def read_file():
    filename = request.json.get("filename", "")
    file_path = (SAFE_DIR / filename).resolve()

    # ✅ Restrict to SAFE_DIR
    if not file_path.is_file() or not str(file_path).startswith(str(SAFE_DIR)):
        return {"error": "Access denied"}, 403

    with open(file_path, "r") as f:
        return {"content": f.read()}


# ---------- DEBUG INFO (Information Disclosure FIX) ----------
@app.route("/debug", methods=["GET"])
def debug():
    return {"status": "debug disabled"}, 403


# ---------- LOGGING (Log Injection FIX) ----------
@app.route("/log", methods=["POST"])
def log_data():
    data = request.json
    logging.info("User input received")
    return {"status": "logged"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
