#!/usr/bin/env python3
"""
FolderSharer Server with background Flask, interactive REPL, and GUI log viewer.
"""
import os, sys, json, secrets, shutil, pathlib, threading, subprocess, time, argparse
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_file, abort
import logging
import socket
from typing import Optional
import queue

# ---------------------
# Config & Globals
# ---------------------
BASE_DIR = pathlib.Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
UPDATES_DIR = DATA_DIR / "updates"
KEY_FILE = DATA_DIR / "server_key.txt"
CONF_FILE = DATA_DIR / "server_conf.json"
LOG_FILE = DATA_DIR / "server.log"

DATA_DIR.mkdir(exist_ok=True)
UPDATES_DIR.mkdir(exist_ok=True)

BACKUP_LIMIT_DEFAULT = 6
LOG_BUFFER_MAX_LINES = 5000
GUI_POLL_SECONDS = 1.5

_log_lock = threading.Lock()
_log_lines = []

_clients_lock = threading.Lock()
CLIENTS = {}

_console_events = queue.Queue()
_console_printer_started = False
_console_printer_lock = threading.Lock()

# ---------------------
# Logging
# ---------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"

def _append_log_line(line: str):
    with _log_lock:
        ts_line = f"[{now_iso()}] {line}"
        _log_lines.append(ts_line)
        if len(_log_lines) > LOG_BUFFER_MAX_LINES:
            _log_lines[:] = _log_lines[-LOG_BUFFER_MAX_LINES:]
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(ts_line + "\n")
        except Exception:
            pass

def log(msg: str):
    print(f"[{now_iso()}] {msg}")
    _append_log_line(msg)

def log_flask(msg: str):
    _append_log_line(msg)


def _update_client(client_id: str, name: str, ip: str, applied_version: Optional[str] = None):
    if not client_id:
        return
    with _clients_lock:
        c = CLIENTS.get(client_id) or {}
        c["id"] = client_id
        if name:
            c["name"] = name
        if ip:
            c["ip"] = ip
        if applied_version is not None:
            c["applied_version"] = applied_version
        c["last_seen"] = time.time()
        CLIENTS[client_id] = c


def _start_console_printer_if_needed():
    global _console_printer_started
    with _console_printer_lock:
        if _console_printer_started:
            return
        _console_printer_started = True

    def worker():
        while True:
            msg = _console_events.get()
            try:
                # Print on its own line and re-render prompt.
                sys.stdout.write("\n" + str(msg) + "\n> ")
                sys.stdout.flush()
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


def console_event(msg: str):
    _start_console_printer_if_needed()
    try:
        _console_events.put(msg)
    except Exception:
        pass


def is_blocked(client_id: Optional[str], remote_ip: Optional[str]) -> bool:
    blocked = set(CONF.get("blocked", []) or [])
    allowed = set(CONF.get("allowed", []) or [])
    blockall = bool(CONF.get("blockall", False))

    if client_id and client_id in blocked:
        return True
    if remote_ip and remote_ip in blocked:
        return True
    if blockall:
        # allowlist overrides blockall; blocklist is still enforced above
        if client_id and client_id in allowed:
            return False
        if remote_ip and remote_ip in allowed:
            return False
        return True
    return False


def get_request_key() -> Optional[str]:
    try:
        k = request.headers.get("X-Server-Key")
        if k:
            return k
    except Exception:
        pass
    try:
        k = request.args.get("key")
        if k:
            return k
    except Exception:
        pass
    try:
        k = request.form.get("key")
        if k:
            return k
    except Exception:
        pass
    try:
        j = request.json or {}
        k = j.get("key")
        if k:
            return k
    except Exception:
        pass
    return None


def require_server_key_or_403():
    if get_request_key() != SERVER_KEY:
        return jsonify({"error": "bad_key"}), 403
    return None

# ---------------------
# Config & Key Management
# ---------------------
if not KEY_FILE.exists():
    KEY_FILE.write_text(secrets.token_hex(16), encoding="utf-8")
SERVER_KEY = KEY_FILE.read_text(encoding="utf-8").strip()

if not CONF_FILE.exists():
    CONF_FILE.write_text(json.dumps({
        "current": None,
        "backuplimit": BACKUP_LIMIT_DEFAULT,
        "blocked": [],
        "allowed": [],
        "blockall": False,
        "server_name": "FolderSharerServer",
    }, indent=2), encoding="utf-8")
CONF = json.loads(CONF_FILE.read_text(encoding="utf-8"))

def save_conf():
    CONF_FILE.write_text(json.dumps(CONF, indent=2), encoding="utf-8")

# ---------------------
# Backup & Metadata Helpers
# ---------------------
def list_metas():
    metas = []
    for mf in sorted(UPDATES_DIR.glob("meta-*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            metas.append(json.loads(mf.read_text(encoding="utf-8")))
        except Exception:
            continue
    return metas

def prune_backups():
    limit = int(CONF.get("backuplimit", BACKUP_LIMIT_DEFAULT))
    metas = list_metas()
    if len(metas) <= limit:
        return
    for m in metas[limit:]:
        uid = m.get("update_id")
        zf = UPDATES_DIR / f"{uid}.zip"
        mf = UPDATES_DIR / f"meta-{uid}.json"
        try:
            if zf.exists(): zf.unlink()
            if mf.exists(): mf.unlink()
            log_flask(f"Pruned backup {uid}")
        except Exception as e:
            log_flask(f"Prune error {uid}: {e}")

# ---------------------
# Admin Command Handler
# ---------------------
def admin_command_handler(cmdline: str):
    cmdline = (cmdline or "").strip()
    if not cmdline:
        return {"ok": False, "output": "empty"}
    parts = cmdline.split()
    cmd = parts[0].lower()
    args = parts[1:]
    try:
        if cmd == "help":
            out = (
                "Commands:\n"
                " help\n"
                " viewpc\n"
                " block <id|ip>\n"
                " unblock <id|ip>\n"
                " blockall <true|false>\n"
                " backuplimit <num>\n"
                " changename <name>\n"
                " displaybackups\n"
                " displayblock\n"
                " restorebackup <slot>\n"
                " regenkey\n"
                " flask\n"
                " exit\n"
            )
            return {"ok": True, "output": out}

        if cmd == "viewpc":
            curr = CONF.get("current")
            now = time.time()
            with _clients_lock:
                clients = list(CLIENTS.values())
            clients.sort(key=lambda c: (c.get("name") or "", c.get("id") or ""))

            out = [f"current: {curr}", "Clients (name:ip:id sync last_seen_s):"]
            for c in clients:
                applied = c.get("applied_version")
                sync = "YES" if (curr and applied == curr) else "NO"
                last_seen = c.get("last_seen") or 0
                age = int(max(0, now - last_seen))
                out.append(f" {c.get('name')}:{c.get('ip')}:{c.get('id')} sync={sync} seen={age}s")

            if len(out) == 2:
                out.append(" (none)")
            return {"ok": True, "output": "\n".join(out)}

        if cmd == "block":
            v = args[0] if args else None
            if not v:
                return {"ok": False, "output": "missing id/ip"}
            with _clients_lock:
                known = (v in CLIENTS) or any((c.get("ip") == v) for c in CLIENTS.values())
            if (v in (CONF.get("allowed", []) or [])) or (v in (CONF.get("blocked", []) or [])):
                known = True
            if not known:
                return {"ok": False, "output": f"unknown target (not connected): {v}"}
            if v not in CONF.get("blocked", []):
                CONF.setdefault("blocked", []).append(v)
            # if they're blocked explicitly, also remove from allowlist
            if v in CONF.get("allowed", []):
                try: CONF["allowed"].remove(v)
                except Exception: pass
            save_conf()
            print(f"ADMIN: blocked {v}")
            return {"ok": True, "output": f"blocked {v}"}

        if cmd == "unblock":
            v = args[0] if args else None
            if not v:
                return {"ok": False, "output": "missing id/ip"}
            blockall_active = bool(CONF.get("blockall", False))
            if not blockall_active:
                with _clients_lock:
                    known = (v in CLIENTS) or any((c.get("ip") == v) for c in CLIENTS.values())
                if (v in (CONF.get("allowed", []) or [])) or (v in (CONF.get("blocked", []) or [])):
                    known = True
                if not known:
                    return {"ok": False, "output": f"unknown target (not connected): {v}"}
            if v in CONF.get("blocked", []):
                try: CONF["blocked"].remove(v)
                except Exception: pass
            # if blockall is active, unblocking means add to allowlist
            if blockall_active and v not in CONF.get("allowed", []):
                CONF.setdefault("allowed", []).append(v)
            save_conf()
            print(f"ADMIN: unblocked {v}")
            return {"ok": True, "output": f"unblocked {v}"}

        if cmd == "blockall":
            if not args:
                return {"ok": True, "output": f"blockall={bool(CONF.get('blockall', False))}"}
            v = str(args[0]).strip().lower()
            if v in ("1", "true", "yes", "on"):
                CONF["blockall"] = True
            elif v in ("0", "false", "no", "off"):
                CONF["blockall"] = False
            else:
                return {"ok": False, "output": "usage: blockall <true|false>"}
            save_conf()
            print(f"ADMIN: blockall -> {CONF['blockall']}")
            return {"ok": True, "output": f"blockall set to {CONF['blockall']}"}

        if cmd == "backuplimit":
            n = int(args[0]) if args else BACKUP_LIMIT_DEFAULT
            CONF["backuplimit"] = n; save_conf(); prune_backups(); print(f"ADMIN: backuplimit {n}")
            return {"ok": True, "output": f"backuplimit set to {n}"}

        if cmd == "changename":
            nm = " ".join(args)
            CONF["server_name"] = nm; save_conf(); print(f"ADMIN: server_name -> {nm}")
            return {"ok": True, "output": f"server_name set to {nm}"}

        if cmd == "displaybackups":
            metas = list_metas()
            out = [f"{i+1}. {m.get('update_id')} by {m.get('uploader_name')} @ {m.get('timestamp_iso')}" for i,m in enumerate(metas)]
            return {"ok": True, "output": "\n".join(out)}

        if cmd == "displayblock":
            return {"ok": True, "output": "\n".join(CONF.get("blocked", []))}

        if cmd in ("restorebackup", "restore"):
            slot = int(args[0])
            metas = list_metas()
            if not (1 <= slot <= len(metas)):
                return {"ok": False, "output": "bad slot"}
            chosen = metas[slot-1]
            srczip = UPDATES_DIR / f"{chosen['update_id']}.zip"
            if not srczip.exists():
                return {"ok": False, "output": "missing source zip"}
            new_uid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
            dstzip = UPDATES_DIR / f"{new_uid}.zip"
            dstmeta = UPDATES_DIR / f"meta-{new_uid}.json"
            shutil.copy2(srczip, dstzip)
            meta = {**chosen, "update_id": new_uid, "timestamp": int(datetime.now(timezone.utc).timestamp()), 
                    "timestamp_iso": now_iso(), "uploader_id": "admin", "uploader_name": "restore_admin"}
            dstmeta.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            CONF["current"] = new_uid; save_conf(); prune_backups()
            print(f"ADMIN: restore pushed {new_uid} from slot {slot}")
            return {"ok": True, "output": f"restore pushed {new_uid}"}

        if cmd in ("flask", "flaskterminalview"):
            try:
                args = [sys.executable, str(__file__), "--gui", "--key", SERVER_KEY, "--host", "127.0.0.1", "--port", "9000"]
                subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("ADMIN: launched GUI viewer")
                return {"ok": True, "output": "Launched GUI viewer"}
            except Exception as e:
                return {"ok": False, "output": f"Failed to launch GUI: {e}"}

        if cmd in ("regenkey", "regeneratekey"):
            print("This will generate a new server key and require all clients to be updated.")
            ans = input("Proceed? (y/n): ").strip().lower()
            if ans not in ("y", "yes"):
                return {"ok": True, "output": "Cancelled."}
            try:
                new_key = secrets.token_hex(16)
                KEY_FILE.write_text(new_key, encoding="utf-8")
                print(f"NEW KEY: {new_key}")
                print("Server will now exit. Restart the server process to use the new key.")
                time.sleep(0.2)
            except Exception as e:
                return {"ok": False, "output": f"Failed to write new key: {e}"}
            os._exit(0)

        if cmd == "exit":
            return {"ok": True, "output": "exit"}

        return {"ok": False, "output": f"unknown command: {cmd}"}

    except Exception as e:
        log(f"ADMIN_CMD_ERROR: {e}")
        return {"ok": False, "output": str(e)}
# Flask App
# ---------------------
app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)


@app.before_request
def _console_connection_log():
    return

@app.route("/", methods=["GET"])
def index():
    return jsonify({"ok": True})

@app.route("/status", methods=["GET"])
def status():
    r = require_server_key_or_403()
    if r is not None:
        return r
    current = CONF.get("current")
    metas = list_metas()
    last_msg = f"Uploaded {metas[0].get('update_id')} by {metas[0].get('uploader_name')}" if metas else None
    last_time = metas[0].get("timestamp_iso") if metas else None
    current_meta = {}
    if current and (mf := UPDATES_DIR / f"meta-{current}.json").exists():
        try: current_meta = json.loads(mf.read_text(encoding="utf-8"))
        except Exception: current_meta = {}
    # include connected clients for UI
    clients_view = {}
    now = time.time()
    with _clients_lock:
        for cid, c in CLIENTS.items():
            last_seen = c.get("last_seen")
            age = int(max(0, now - last_seen)) if isinstance(last_seen, (int, float)) else None
            clients_view[cid] = {
                "name": c.get("name"),
                "ip": c.get("ip"),
                "applied_version": c.get("applied_version"),
                "sync_enabled": bool(c.get("sync_enabled", False)),
                "last_seen": age,
            }

    return jsonify({
        "server_name": CONF.get("server_name"),
        "current": current,
        "backups": [{"slot": i+1, "update_id": b["update_id"], "timestamp": b.get("timestamp_iso")} for i,b in enumerate(metas[:CONF.get("backuplimit", BACKUP_LIMIT_DEFAULT)])],
        "clients": clients_view,
        "last_update_message": last_msg,
        "last_update_time": last_time,
        "current_meta": current_meta
    })

@app.route("/admin/terminal/logs", methods=["GET"])
def admin_terminal_logs():
    if request.args.get("key") != SERVER_KEY:
        return jsonify({"error":"unauthorized"}), 403
    with _log_lock:
        return jsonify({"lines": list(_log_lines)})

@app.route("/upload", methods=["POST"])
def upload():
    client_key = request.form.get("key")
    client_id = request.form.get("id")
    uploader_name = request.form.get("name")
    base_update_id = request.form.get("base_update_id")

    if client_key != SERVER_KEY:
        return jsonify({"error":"bad_key"}), 403
    if is_blocked(client_id, request.remote_addr):
        log_flask(f"BLOCKED upload {client_id} ({request.remote_addr})")
        return jsonify({"error":"blocked"}), 403
    
    current = CONF.get("current")
    if base_update_id and current and base_update_id != current:
        log_flask(f"UPLOAD_REJECT base mismatch: client {client_id} base {base_update_id} != server {current}")
        return jsonify({"error":"base_mismatch", "current": current}), 409

    if 'update' not in request.files:
        return jsonify({"error":"no_file"}), 400
    
    f = request.files['update']
    uid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    zpath = UPDATES_DIR / f"{uid}.zip"
    metaf = UPDATES_DIR / f"meta-{uid}.json"
    try:
        f.save(str(zpath))
        manifest = {}
        try:
            import zipfile
            with zipfile.ZipFile(zpath, "r") as z:
                if "manifest.json" in z.namelist():
                    manifest = json.loads(z.read("manifest.json").decode("utf-8"))
        except Exception:
            manifest = {}
        
        meta = {
            "update_id": uid,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "timestamp_iso": now_iso(),
            "uploader_id": client_id,
            "uploader_name": uploader_name,
            "manifest": manifest
        }
        metaf.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        CONF["current"] = uid; save_conf(); prune_backups()
        log_flask(f"UPLOAD saved: {uid} from {client_id}/{uploader_name}")
        return jsonify({"update_id": uid}), 200
    except Exception as e:
        log_flask(f"UPLOAD error: {e}")
        if zpath.exists(): zpath.unlink(missing_ok=True)
        if metaf.exists(): metaf.unlink(missing_ok=True)
        return jsonify({"error":"save_failed", "msg": str(e)}), 500

@app.route("/download/<update_id>", methods=["GET"])
def download(update_id):
    r = require_server_key_or_403()
    if r is not None:
        return r
    zf = UPDATES_DIR / f"{update_id}.zip"
    if not zf.exists():
        return abort(404)
    return send_file(str(zf), as_attachment=True, download_name=f"{update_id}.zip")

@app.route("/ack", methods=["POST"])
def ack():
    data = request.json or {}
    if (data.get("key") or "") != SERVER_KEY:
        return jsonify({"error":"bad_key"}), 403
    if is_blocked(str(data.get("id") or ""), request.remote_addr):
        return jsonify({"error":"blocked"}), 403
    try:
        _update_client(
            client_id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            ip=str(request.remote_addr or ""),
            applied_version=str(data.get("update_id") or ""),
        )
    except Exception:
        pass
    log_flask(f"ACK: client {data.get('id')} applied {data.get('update_id')}")
    return jsonify({"ok": True})

@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    if data.get("key") != SERVER_KEY: return jsonify({"error":"bad_key"}), 403
    cid = str(data.get("id") or "")
    nm = str(data.get("name") or "")
    ip = str(request.remote_addr or "")
    if is_blocked(cid, ip):
        log_flask(f"BLOCKED register {cid} ({ip})")
        return jsonify({"error":"blocked"}), 403
    # Console connection display: always print on register (reconnects too)
    try:
        if cid:
            console_event(f"{nm} - {ip} - {cid}")
    except Exception:
        pass
    try:
        _update_client(
            client_id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            ip=str(request.remote_addr or ""),
            applied_version=str(data.get("applied_version") or ""),
        )
    except Exception:
        pass
    log_flask(f"REGISTER: {data.get('name')} ({request.remote_addr}) [{data.get('id')}] applied={data.get('applied_version')}")
    return jsonify({"ok": True})


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.json or {}
    if (data.get("key") or "") != SERVER_KEY:
        return jsonify({"error":"bad_key"}), 403
    cid = str(data.get("id") or "")
    nm = str(data.get("name") or "")
    ip = str(request.remote_addr or "")
    if is_blocked(cid, ip):
        return jsonify({"error":"blocked"}), 403
    sync_enabled = bool(data.get("sync_enabled", False))
    try:
        prev = None
        with _clients_lock:
            prev = (CLIENTS.get(cid) or {}).get("sync_enabled")
        _update_client(client_id=cid, name=nm, ip=ip, applied_version=None)
        with _clients_lock:
            if cid in CLIENTS:
                CLIENTS[cid]["sync_enabled"] = sync_enabled
        if prev is None or bool(prev) != sync_enabled:
            console_event(f"{nm} - {ip} - {cid} sync_enabled={sync_enabled}")
            log_flask(f"SYNC_TOGGLE: {cid} {nm} {ip} -> {sync_enabled}")
    except Exception:
        pass
    return jsonify({"ok": True})

@app.route("/updates", methods=["GET"])
def updates():
    return status()

@app.route("/request_restore", methods=["POST"])
def request_restore():
    data = request.json or {}
    if (data.get("key") or "") != SERVER_KEY:
        return jsonify({"error":"bad_key"}), 403
    cid = data.get("id"); slot = int(data.get("slot", 0))
    metas = list_metas()
    if not (1 <= slot <= len(metas)): return jsonify({"error":"bad_slot"}), 400
    chosen = metas[slot-1]; srczip = UPDATES_DIR / f"{chosen['update_id']}.zip"
    if not srczip.exists(): return jsonify({"error":"missing"}), 500
    new_uid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    dstzip = UPDATES_DIR / f"{new_uid}.zip"; dstmeta = UPDATES_DIR / f"meta-{new_uid}.json"
    shutil.copy2(srczip, dstzip)
    meta = {**chosen, "update_id": new_uid, "timestamp": int(datetime.now(timezone.utc).timestamp()), 
            "timestamp_iso": now_iso(), "uploader_id": cid, "uploader_name": f"restore_by_{cid}"}
    dstmeta.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    CONF["current"] = new_uid; save_conf(); prune_backups()
    log_flask(f"RESTORE pushed: {new_uid} from slot {slot} by {cid}")
    return jsonify({"ok": True, "restore_update_id": new_uid}), 200


def run_flask_background():
    from werkzeug.serving import make_server
    try:
        log_flask("Flask server thread starting")
        log_flask("Listening on http://0.0.0.0:9000")
    except Exception:
        pass
    srv = make_server("0.0.0.0", 9000, app)
    srv.serve_forever()


def admin_repl_loop():
    lan_ip = get_lan_ip()
    print("===== FolderSharer Admin Terminal =====")
    print(f"Server (LAN): http://{lan_ip}:9000")
    print("Server (bind): http://0.0.0.0:9000")
    print(f"Key: {SERVER_KEY}")
    print(f"Data dir: {str(DATA_DIR)}")
    print("Type 'help' for commands.")
    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print("Admin console exiting by interrupt")
            break
        if not cmd:
            continue
        res = admin_command_handler(cmd)
        if res.get("output"):
            print(res["output"])
        if cmd.strip().lower() == "exit":
            print("Admin requested exit")
            break
    print("Server shutting down.")
    os._exit(0)


def run_gui_mode(host, port, key, poll=GUI_POLL_SECONDS):
    import tkinter as tk
    import tkinter.scrolledtext as st
    import requests

    base = f"http://{host}:{port}"

    root = tk.Tk()
    root.title("FolderSharer - Server Terminal")
    root.geometry("900x600")

    txt = st.ScrolledText(root, state="disabled", wrap="none", font=("Consolas", 10))
    txt.pack(fill="both", expand=True, padx=6, pady=6)

    status_var = tk.StringVar(value=f"Polling {base}/admin/terminal/logs")
    status = tk.Label(root, textvariable=status_var, anchor="w")
    status.pack(fill="x", padx=6, pady=(0, 6))

    stop_flag = {"stop": False}

    def set_text(lines):
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        for line in lines:
            txt.insert("end", line + "\n")
        txt.see("end")
        txt.configure(state="disabled")

    def poll_loop():
        while not stop_flag["stop"]:
            try:
                r = requests.get(f"{base}/admin/terminal/logs", params={"key": key}, timeout=4)
                if r.status_code == 200:
                    lines = (r.json() or {}).get("lines", [])
                    root.after(0, set_text, lines)
                    root.after(0, status_var.set, f"Connected to {base}")
                else:
                    root.after(0, status_var.set, f"HTTP {r.status_code}: {r.text[:120]}")
            except Exception as e:
                root.after(0, status_var.set, f"Poll error: {e}")
            time.sleep(poll)

    threading.Thread(target=poll_loop, daemon=True).start()

    def on_close():
        stop_flag["stop"] = True
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--gui", action="store_true")
    p.add_argument("--key")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default="9000")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.gui:
        if not args.key:
            print("GUI mode requires --key")
            sys.exit(2)
        run_gui_mode(args.host, args.port, args.key)
        sys.exit(0)

    t = threading.Thread(target=run_flask_background, daemon=True)
    t.start()

    try:
        log_flask("Server process started")
        log_flask(f"Data dir: {str(DATA_DIR)}")
    except Exception:
        pass

    admin_repl_loop()
