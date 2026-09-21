"""
app.py -- Flask backend + REST API for the VAPT scanner.

Wires the Python scanning engine (Sarvesh) to the web platform (Ronit):
serves the frontend pages, exposes a JSON API the frontend calls with fetch(),
and persists every scan to SQLite for the history view.

Routes
------
Pages
  GET  /                 landing + scan form
  GET  /history          scan history list

API (JSON)
  GET  /api/checks       metadata about the checks we run
  POST /api/scan         run a scan for {"url": "..."}; save + return report
  GET  /api/history      list recent scans
  GET  /api/scan/<id>    reopen one saved scan (full results)
  DELETE /api/scan/<id>  delete one saved scan
  DELETE /api/history    clear all history

Owned by: Ronit (Full-Stack Developer)
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

import database
from scanner import run_all_checks, CHECK_REGISTRY

app = Flask(__name__)
CORS(app)  # allow the fetch() frontend to call the API during local dev

# Make sure the scans table exists before we serve any request.
database.init_db()


# --------------------------------------------------------------------------- #
# Page routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html", checks=CHECK_REGISTRY)


@app.route("/history")
def history_page():
    return render_template("history.html")


# --------------------------------------------------------------------------- #
# API routes
# --------------------------------------------------------------------------- #
@app.route("/api/checks", methods=["GET"])
def api_checks():
    """Describe the checks the engine runs (used by the landing page)."""
    return jsonify({"checks": CHECK_REGISTRY})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run a full scan for the submitted URL, save it, and return the report."""
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()

    if not url:
        return jsonify({"ok": False, "error": "Please enter a URL to scan."}), 400

    report = run_all_checks(url)

    if not report["ok"]:
        # Invalid URL etc. -- return the message but don't save a broken scan.
        return jsonify(report), 400

    # Persist and hand the new id back so the frontend can deep-link the report.
    scan_id = database.save_scan(report)
    report["id"] = scan_id
    return jsonify(report), 200


@app.route("/api/history", methods=["GET"])
def api_history():
    """Recent scans, newest first (history auto-prunes to MAX_HISTORY)."""
    scans = database.list_scans(limit=100)
    return jsonify({"scans": scans, "max_history": database.MAX_HISTORY})


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    """Reopen a saved scan with its full per-check results."""
    scan = database.get_scan(scan_id)
    if scan is None:
        return jsonify({"ok": False, "error": "Scan not found."}), 404
    return jsonify(scan)


@app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    """Delete a single scan from history."""
    ok = database.delete_scan(scan_id)
    if not ok:
        return jsonify({"ok": False, "error": "Scan not found."}), 404
    return jsonify({"ok": True})


@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    """Wipe all scan history."""
    removed = database.clear_history()
    return jsonify({"ok": True, "removed": removed})


if __name__ == "__main__":
    # debug=True gives auto-reload while developing. Host stays on localhost.
    app.run(host="127.0.0.1", port=5000, debug=True)
