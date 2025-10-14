# app.py
import os
import json
import sqlite3
import uuid
import datetime
from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from scanner import scan_config
import csv
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "data.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app)

# --- Simple SQLite helpers ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        token TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        created_at TEXT,
        result_json TEXT
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Simple auth ---
def require_token(fn):
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Auth-Token") or (request.headers.get("Authorization") or "").replace("Bearer ", "")
        if not token:
            return jsonify({"error":"token required in X-Auth-Token or Authorization header"}), 401
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
        conn.close()
        if not user:
            return jsonify({"error":"invalid token"}), 401
        request.user = user
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

# --- Auth endpoints ---
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    pw_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (username, pw_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error":"username exists"}), 400
    conn.close()
    return jsonify({"message":"user created"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error":"invalid credentials"}), 401
    # create token
    token = str(uuid.uuid4())
    conn = get_db()
    conn.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))
    conn.commit()
    conn.close()
    return jsonify({"token": token}), 200

# --- Upload + Scan endpoint ---
@app.route("/scan", methods=["POST"])
@require_token
def scan_upload():
    # Accept either file upload or raw JSON in body
    if "file" in request.files:
        f = request.files["file"]
        fname = secure_filename(f.filename)
        save_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{fname}")
        f.save(save_path)
        with open(save_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    else:
        # accept JSON body
        cfg = request.get_json()
        if cfg is None:
            return jsonify({"error":"send JSON body or file"}), 400
        # persist JSON to file for traceability
        fname = f"uploaded_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        save_path = os.path.join(UPLOAD_DIR, fname)
        with open(save_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)

    # run scanner
    result = scan_config(cfg)

    # save in DB
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (user_id, filename, created_at, result_json) VALUES (?,?,?,?)",
                (request.user["id"], save_path, datetime.datetime.utcnow().isoformat(), json.dumps(result)))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()

    return jsonify({"scan_id": scan_id, "summary": result["summary"]}), 201

@app.route("/scans", methods=["GET"])
@require_token
def list_scans():
    conn = get_db()
    rows = conn.execute("SELECT id, filename, created_at FROM scans WHERE user_id = ? ORDER BY id DESC", (request.user["id"],)).fetchall()
    conn.close()
    out = [{"id": r["id"], "filename": r["filename"], "created_at": r["created_at"]} for r in rows]
    return jsonify(out)

@app.route("/scan/<int:scan_id>", methods=["GET"])
@require_token
def get_scan(scan_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, request.user["id"])).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"scan not found"}), 404
    return jsonify(json.loads(row["result_json"]))

@app.route("/report/<int:scan_id>/csv", methods=["GET"])
@require_token
def download_csv(scan_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, request.user["id"])).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"scan not found"}), 404

    result = json.loads(row["result_json"])
    issues = result.get("issues", [])

    # write to temp CSV
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    try:
        with open(tf.name, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["check_id","title","severity","message","resource"])
            for it in issues:
                writer.writerow([it.get("check_id"), it.get("title"), it.get("severity"), it.get("message"), it.get("resource")])
        return send_file(tf.name, as_attachment=True, download_name=f"scan_{scan_id}_report.csv")
    finally:
        pass  # temp file will be left for download; OS will clean later

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
