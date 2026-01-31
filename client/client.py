#!/usr/bin/env python3
"""
FolderSharer client — full fix for deletion/manifest/conflict handling.

Requirements:
  pip install requests pystray Pillow watchdog

Usage:
  python client.py
"""
import os
import sys
import json
import uuid
import pathlib
import threading
import time
import requests
import zipfile
import hashlib
import tempfile
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pystray
from PIL import Image, ImageDraw
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timezone, timedelta
import traceback
from typing import Optional

try:
    import ctypes
except Exception:
    ctypes = None

APP_DIR = pathlib.Path.home() / ".foldersharer"
CONF_FILE = APP_DIR / "config.json"
ID_FILE = APP_DIR / "id.json"
APPLIED_FILE = APP_DIR / "applied_version.txt"

ICON_PATH = pathlib.Path(__file__).with_name("ltt.ico")

DEFAULT_POLL_INTERVAL = 8
CHANGE_DEBOUNCE = 1.5
UPLOAD_RETRY = 1

POLL_TIMEOUT_SECONDS = 15
HEARTBEAT_TIMEOUT_SECONDS = 8

STARTUP_CMD_NAME = "FolderSharerClient.cmd"

def ensure_dirs():
    APP_DIR.mkdir(exist_ok=True)

def normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "http://" + u
    return u.rstrip("/")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def _set_windows_app_user_model_id(app_id: str):
    if os.name != "nt" or not ctypes:
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        pass

def _apply_window_icon(win):
    if os.name != "nt":
        return
    if not ICON_PATH.exists():
        return
    try:
        win.iconbitmap(str(ICON_PATH))
    except Exception:
        pass

def _load_tray_image():
    if ICON_PATH.exists():
        try:
            return Image.open(str(ICON_PATH))
        except Exception:
            return None
    return None

def _get_windows_startup_dir() -> Optional[pathlib.Path]:
    if os.name != "nt":
        return None
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    return pathlib.Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"

def _get_pythonw_executable() -> str:
    exe = sys.executable
    if os.name != "nt":
        return exe
    try:
        p = pathlib.Path(exe)
        if p.name.lower() == "python.exe":
            pw = p.with_name("pythonw.exe")
            if pw.exists():
                return str(pw)
    except Exception:
        pass
    return exe

def set_start_on_startup_enabled(enabled: bool) -> bool:
    """Best-effort Windows startup integration using the user's Startup folder."""
    startup_dir = _get_windows_startup_dir()
    if not startup_dir:
        return False
    try:
        startup_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return False

    target = startup_dir / STARTUP_CMD_NAME
    if not enabled:
        try:
            if target.exists():
                target.unlink()
            return True
        except Exception:
            return False

    try:
        pyw = _get_pythonw_executable()
        script = str(pathlib.Path(__file__).resolve())
        workdir = str(pathlib.Path(__file__).resolve().parent)
        content = (
            "@echo off\r\n"
            f"cd /d \"{workdir}\"\r\n"
            f"\"{pyw}\" \"{script}\"\r\n"
        )
        target.write_text(content, encoding="utf-8")
        return True
    except Exception:
        return False

def load_config():
    if not CONF_FILE.exists():
        cfg = {
            "servers": [],
            "current_server_index": 0,
            "display_name": f"user-{uuid.uuid4().hex[:6]}",
            "start_on_startup": False,
            "start_with_program": False,
            "start_program_path": "",
            "close_when_program_closes": False,
            "only_sync_when_program_closes": False,
            "enable_sync_startup": True,
            "tray_on_startup": False,
            "auto_upload": True,
            "sync_folder": "",
            "last_uploaded_hash": "",
            "applied_version": ""
        }
        save_config(cfg)
        return cfg
    return json.loads(CONF_FILE.read_text(encoding="utf-8"))

def save_config(cfg):
    CONF_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def load_id():
    if not ID_FILE.exists():
        try:
            hw = str(uuid.getnode())
            stable = hashlib.sha256(hw.encode("utf-8")).hexdigest()
            idd = {"id": stable, "hw": hw}
        except Exception:
            idd = {"id": uuid.uuid4().hex, "hw": None}
        ID_FILE.write_text(json.dumps(idd), encoding="utf-8")
        return idd
    return json.loads(ID_FILE.read_text(encoding="utf-8"))

def compute_file_hash(path: pathlib.Path):
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
    except Exception:
        h.update(b"__UNREADABLE__")
    return h.hexdigest()

def compute_folder_signature(folder: str):
    """Deterministic signature of folder contents (paths + file hashes)."""
    folder = pathlib.Path(folder)
    if not folder.exists():
        return ""
    items = []
    for root, dirs, files in os.walk(folder):
        for fn in files:
            p = pathlib.Path(root) / fn
            try:
                rel = str(p.relative_to(folder)).replace("\\", "/")
            except Exception:
                rel = str(p)
            items.append(rel)
    items.sort()
    overall = hashlib.sha256()
    for rel in items:
        p = folder / rel
        fh = compute_file_hash(p)
        overall.update(rel.encode("utf-8"))
        overall.update(b"\0")
        overall.update(fh.encode("utf-8"))
        overall.update(b"\n")
    return overall.hexdigest()

def zip_folder_with_manifest(folder: str, out_path: pathlib.Path):
    """
    Create a zip of folder and include manifest.json file listing all file paths, hashes and mtimes.
    The manifest also contains a `created` timestamp (UTC ISO).
    """
    folder = pathlib.Path(folder)
    manifest = {"created": now_iso(), "files": []}
    # create in temp dir to avoid reading partial writes
    tmp_zip = out_path.with_suffix(out_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(folder):
            for f in files:
                p = pathlib.Path(root) / f
                arcname = str(p.relative_to(folder)).replace("\\", "/")
                try:
                    file_bytes = p.read_bytes()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
                    manifest["files"].append({"path": arcname, "hash": file_hash, "mtime": mtime})
                    z.writestr(arcname, file_bytes)
                except Exception:
                    # skip unreadable files (but still include an entry with empty hash)
                    manifest["files"].append({"path": arcname, "hash": "", "mtime": None})
        # finally add manifest.json
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    tmp_zip.replace(out_path)
    return manifest

def ping_server(url, timeout=5):
    try:
        url = normalize_url(url)
        r = requests.get(url + "/", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False

def local_latest_mtime(folder: str):
    folder = pathlib.Path(folder)
    if not folder.exists():
        return None
    latest = None
    for root, dirs, files in os.walk(folder):
        for f in files:
            p = pathlib.Path(root) / f
            try:
                m = p.stat().st_mtime
            except Exception:
                continue
            if latest is None or m > latest:
                latest = m
    if latest is None:
        return None
    return datetime.fromtimestamp(latest, tz=timezone.utc)

def iso_to_dt(iso_str):
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def short_time_from_iso(iso_str):
    dt = iso_to_dt(iso_str)
    if not dt:
        return ""
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")

class DebounceHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self._timer = None
        self._lock = threading.Lock()
    def _start_timer(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(CHANGE_DEBOUNCE, self._fire)
            self._timer.daemon = True
            self._timer.start()
    def _fire(self):
        try:
            self.callback()
        except Exception as e:
            print("watcher callback error:", e)
    def on_any_event(self, event):
        # any file system event (created/modified/deleted/moved) triggers debounce
        self._start_timer()

# Minimal interactive server info window used previously (keeps behavior)
class ServerInfoWindow(tk.Toplevel):
    def __init__(self, master, client_app):
        super().__init__(master)
        self.client_app = client_app
        _apply_window_icon(self)
        self.title("Server info")
        self.geometry("520x420")
        topf = tk.Frame(self); topf.pack(fill="x", padx=8, pady=8)
        tk.Label(topf, text="Server:").pack(side="left")
        self.server_label = tk.Label(topf, text="(not connected)")
        self.server_label.pack(side="left", padx=6)
        tk.Button(topf, text="Refresh", command=self.manual_refresh).pack(side="right")
        cols = ("nickname", "ip", "id", "applied", "sync", "last_seen")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=110 if c != "id" else 180, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=6)
        botf = tk.Frame(self); botf.pack(fill="x", padx=8, pady=8)
        tk.Label(botf, text="Restore backup:").pack(side="left")
        self.backup_var = tk.StringVar(value="(none)")
        self.backup_dropdown = ttk.Combobox(botf, textvariable=self.backup_var, state="disabled", width=40)
        self.backup_dropdown.pack(side="left", padx=6)
        self.restore_btn = tk.Button(botf, text="Restore (request)", command=self.request_restore, state="disabled")
        self.restore_btn.pack(side="left", padx=6)
        self.last_update_label = tk.Label(self, text="Last update: (none)")
        self.last_update_label.pack(anchor="w", padx=8)
        self._stop = False
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<Destroy>", lambda _e: setattr(self, "_stop", True))
        self._updater = threading.Thread(target=self._update_loop, daemon=True)
        self._updater.start()
    def on_close(self):
        self._stop = True
        self.destroy()
    def _update_loop(self):
        while not self._stop:
            self.manual_refresh()
            time.sleep(3)
    def manual_refresh(self):
        def fetch_and_apply():
            s = self.client_app.get_active_server()
            if s is None:
                data = None
                s_url = None
            else:
                s_url = s["url"]
                try:
                    r = requests.get(s_url.rstrip("/") + "/status", params={"key": s.get("key", "")}, timeout=4)
                    data = r.json() if r.status_code == 200 else {"error": r.text}
                except Exception as e:
                    data = {"error": str(e)}
            if self._stop:
                return
            try:
                if not self.winfo_exists():
                    return
            except Exception:
                return
            def apply():
                if self._stop:
                    return
                try:
                    if not self.winfo_exists():
                        return
                except Exception:
                    return
                try:
                    self._apply_status(data, s_url)
                except tk.TclError:
                    pass
            try:
                self.after(0, apply)
            except tk.TclError:
                pass
        threading.Thread(target=fetch_and_apply, daemon=True).start()
    def _apply_status(self, data, s_url):
        if self._stop:
            return
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        if data is None:
            self.server_label.config(text="(no server configured)")
            self.tree.delete(*self.tree.get_children())
            self.backup_dropdown["state"] = "disabled"
            self.restore_btn["state"] = "disabled"
            self.last_update_label.config(text="Last update: (none)")
            return
        if data.get("error"):
            text = f"{s_url} (unreachable)" if s_url else "(unreachable)"
            self.server_label.config(text=text)
            self.last_update_label.config(text="Last update: No connection")
            return
        self.server_label.config(text=f"{s_url} ({data.get('server_name')})")
        self.tree.delete(*self.tree.get_children())
        for cid, info in data.get("clients", {}).items():
            self.tree.insert("", "end", values=(
                info.get("name"),
                info.get("ip"),
                cid,
                info.get("applied_version"),
                str(info.get("sync_enabled")),
                info.get("last_seen")
            ))
        backups = data.get("backups", []) or []
        if backups:
            items = [f"slot {b['slot']}: {b['update_id']} @ {short_time_from_iso(b['timestamp'])}" if isinstance(b.get("timestamp"), str) else f"slot {b['slot']}: {b['update_id']} @ {b.get('timestamp')}" for b in backups]
            self.backup_dropdown["values"] = items
            if items:
                self.backup_dropdown.current(0)
                self.backup_dropdown["state"] = "readonly"
                self.restore_btn["state"] = "normal"
        else:
            self.backup_dropdown["values"] = []
            self.backup_dropdown.set("(none)")
            self.backup_dropdown["state"] = "disabled"
            self.restore_btn["state"] = "disabled"
        last_msg = data.get("last_update_message")
        last_time = data.get("last_update_time")
        st = "Last update: (none)"
        if last_msg:
            short_t = short_time_from_iso(last_time)
            st = f"Last update: {last_msg} @ {short_t}" if short_t else f"Last update: {last_msg}"
        self.last_update_label.config(text=st)
    def request_restore(self):
        s = self.client_app.get_active_server()
        if s is None:
            messagebox.showerror("No server", "Not connected to server")
            return
        choice = self.backup_var.get()
        if not choice or choice.startswith("(none)"):
            messagebox.showerror("No backup", "Select a backup slot")
            return
        try:
            slot_part = choice.split(":")[0].strip()
            slot_num = int(slot_part.split()[1])
        except Exception:
            messagebox.showerror("Bad selection", "Can't parse backup slot")
            return
        payload = {"id": self.client_app.idrec["id"], "slot": slot_num, "key": s.get("key", "")}
        try:
            r = requests.post(s["url"].rstrip("/") + "/request_restore", json=payload, timeout=8)
            if r.status_code == 200:
                j = r.json()
                if j.get("ok"):
                    messagebox.showinfo("Restore requested", f"Restore queued as update {j.get('restore_update_id')}")
                else:
                    messagebox.showerror("Restore failed", j.get("error", "unknown"))
            else:
                try:
                    j = r.json()
                    messagebox.showerror("Restore rejected", j.get("error", r.text))
                except Exception:
                    messagebox.showerror("Restore failed", r.text)
        except Exception as e:
            messagebox.showerror("Network error", str(e))

class ClientApp:
    def __init__(self, root):
        ensure_dirs()
        self.cfg = load_config()
        self.idrec = load_id()
        self.applied_version = self.cfg.get("applied_version") or (APPLIED_FILE.read_text().strip() if APPLIED_FILE.exists() else None)
        self.root = root
        self.server = None
        self.sync_enabled = False
        self.stop_poll = threading.Event()
        self.poll_thread = None
        self.observer = None
        self.watcher_handler = None
        self.sync_folder = self.cfg.get("sync_folder") or None
        self._last_seen_signature = None
        self._upload_lock = threading.Lock()
        self.mismatch_state = None
        self.mismatch_modal_shown = False
        self._last_poll_exception_msg = None
        self._last_poll_exception_print_ts = 0.0
        self._autostart_done = False
        self._program_proc = None
        self._launch_program_when_ready = False
        try:
            set_start_on_startup_enabled(bool(self.cfg.get("start_on_startup", False)))
        except Exception:
            pass
        self.init_ui()
    def init_ui(self):
        r = self.root
        r.title("FolderSharer - Client")
        _apply_window_icon(r)
        topf = tk.Frame(r); topf.pack(fill="x", padx=6, pady=6)
        tk.Button(topf, text="+ Add Server", command=self.add_server).pack(side="left")
        tk.Button(topf, text="Settings", command=self.open_settings).pack(side="right")
        tk.Button(topf, text="Server Info", command=self.open_server_info).pack(side="right", padx=6)
        mid = tk.Frame(r); mid.pack(fill="x", padx=6, pady=6)
        tk.Label(mid, text="Folder to sync:").pack(side="left")
        initial_folder = self.cfg.get("sync_folder") or str(APP_DIR)
        self.folder_var = tk.StringVar(value=str(initial_folder))
        tk.Entry(mid, textvariable=self.folder_var, width=50).pack(side="left", padx=6)
        tk.Button(mid, text="...", command=self.browse_folder).pack(side="left")
        tk.Button(mid, text="Apply", command=self.apply_folder).pack(side="left", padx=6)
        self.init_button = tk.Button(r, text="Initialize (Enable Sync)", command=self.toggle_sync)
        self.init_button.pack(padx=6, pady=6)
        actionf = tk.Frame(r); actionf.pack(fill="x", padx=6, pady=6)
        self.status_text = tk.StringVar(value="Not connected")
        tk.Label(actionf, textvariable=self.status_text).pack(side="left", padx=12)
        self.create_tray_icon()
        r.protocol("WM_DELETE_WINDOW", self.on_close)
        if self.sync_folder:
            self.folder_var.set(self.sync_folder)
        if self.cfg.get("tray_on_startup", False):
            self.root.after(100, self.root.withdraw)
        self.root.after(500, lambda: self.try_autostart())

    def _launch_program_and_monitor(self):
        if self._program_proc is not None:
            return
        if not self.cfg.get("start_with_program", False):
            return
        prog = (self.cfg.get("start_program_path") or "").strip()
        if not prog:
            return

        try:
            proc = subprocess.Popen([prog])
            self._program_proc = proc
        except Exception as e:
            self.root.after(0, lambda: self.status_text.set(f"Failed to start program: {e}"))
            return

        def waiter():
            try:
                proc.wait()
            except Exception:
                return

            def after_close():
                if self.cfg.get("only_sync_when_program_closes", False):
                    self.stop_sync()
                if self.cfg.get("close_when_program_closes", False):
                    try:
                        if self.sync_enabled:
                            self.stop_sync()
                    except Exception:
                        pass
                    self.exit_app()

            try:
                self.root.after(0, after_close)
            except Exception:
                pass

        threading.Thread(target=waiter, daemon=True).start()

    def _maybe_launch_program_now(self, server_current: Optional[str]):
        if not self._launch_program_when_ready:
            return
        if self._program_proc is not None:
            return
        # Only launch once we're caught up with the server (or server has no current yet)
        if server_current and self.applied_version != server_current:
            return
        self._launch_program_when_ready = False
        self._launch_program_and_monitor()
    def add_server(self):
        dlg = tk.Toplevel(self.root); dlg.title("Add server")
        _apply_window_icon(dlg)
        tk.Label(dlg, text="Server URL (e.g. 192.168.1.20:9000)").pack(padx=6, pady=6)
        url_var = tk.StringVar(value="")
        tk.Entry(dlg, textvariable=url_var, width=60).pack(padx=6)
        tk.Label(dlg, text="Server key:").pack(padx=6, pady=(8,0))
        key_var = tk.StringVar(); tk.Entry(dlg, textvariable=key_var, width=60).pack(padx=6)
        tk.Label(dlg, text="Display name:").pack(padx=6, pady=(8,0))
        name_var = tk.StringVar(value=self.cfg.get("display_name")); tk.Entry(dlg, textvariable=name_var, width=60).pack(padx=6)
        status_label = tk.Label(dlg, text="", fg="blue"); status_label.pack(pady=(6,0))
        def do_ping():
            addr = normalize_url(url_var.get().strip()); status_label.config(text="Pinging..."); self.root.update_idletasks(); ok = ping_server(addr); status_label.config(text="Reachable" if ok else "Unreachable", fg="green" if ok else "red")
        tk.Button(dlg, text="Ping", command=do_ping).pack(pady=(6,0))
        def do_add():
            url = normalize_url(url_var.get().strip()); key = key_var.get().strip(); name = name_var.get().strip() or self.cfg.get("display_name")
            if not url or not key:
                messagebox.showerror("missing", "Please fill url and key"); return
            if not ping_server(url):
                messagebox.showerror("unreachable", "Server unreachable. Ping first or verify address."); return
            self.cfg.setdefault("servers", []).append({"url": url, "key": key, "name": name})
            save_config(self.cfg); messagebox.showinfo("added", "Server added"); dlg.destroy()
        tk.Button(dlg, text="Add", command=do_add).pack(pady=8)
    def open_settings(self):
        dlg = tk.Toplevel(self.root); dlg.title("Settings")
        _apply_window_icon(dlg)
        tk.Label(dlg, text="Display name:").pack(anchor="w", padx=6, pady=(6,0))
        dn = tk.StringVar(value=self.cfg.get("display_name"))
        tk.Entry(dlg, textvariable=dn, width=60).pack(padx=6)

        start_on_startup = tk.BooleanVar(value=bool(self.cfg.get("start_on_startup", False)))
        tk.Checkbutton(dlg, text="Start on startup", variable=start_on_startup).pack(anchor="w", padx=6, pady=6)

        startprog = tk.BooleanVar(value=self.cfg.get("start_with_program"))
        cb_startprog = tk.Checkbutton(dlg, text="Start with program?", variable=startprog); cb_startprog.pack(anchor="w", padx=6, pady=6)
        progpath = tk.StringVar(value=self.cfg.get("start_program_path",""))
        fframe = tk.Frame(dlg); fframe.pack(fill="x", padx=6)
        prog_entry = tk.Entry(fframe, textvariable=progpath, width=48); prog_entry.pack(side="left")
        def browse_prog():
            p = filedialog.askopenfilename()
            if p: progpath.set(p)
        browse_btn = tk.Button(fframe, text="...", command=browse_prog); browse_btn.pack(side="left")
        close_when = tk.BooleanVar(value=self.cfg.get("close_when_program_closes"))
        cb_close_when = tk.Checkbutton(dlg, text="Close when opened program closes", variable=close_when); cb_close_when.pack(anchor="w", padx=6)
        only_when_prog_closes = tk.BooleanVar(value=self.cfg.get("only_sync_when_program_closes", False))
        cb_only_when = tk.Checkbutton(dlg, text="Only sync after program closes", variable=only_when_prog_closes); cb_only_when.pack(anchor="w", padx=6)
        enable_sync = tk.BooleanVar(value=self.cfg.get("enable_sync_startup"))
        tk.Checkbutton(dlg, text="Enable syncing at startup", variable=enable_sync).pack(anchor="w", padx=6)
        tray_on = tk.BooleanVar(value=self.cfg.get("tray_on_startup"))
        tk.Checkbutton(dlg, text="Go to tray at startup", variable=tray_on).pack(anchor="w", padx=6)
        tk.Label(dlg, text="Edit server:").pack(anchor="w", padx=6, pady=(8,0))
        servers_list = self.cfg.get("servers", [])
        if servers_list:
            selected_idx = tk.IntVar(value=self.cfg.get("current_server_index", 0))
            choices = list(range(len(servers_list)))
            dd = tk.OptionMenu(dlg, selected_idx, *choices)
            dd.pack(anchor="w", padx=6)
        else:
            selected_idx = tk.IntVar(value=0); tk.Label(dlg, text="(no servers configured)").pack(anchor="w", padx=6)
        def edit_selected():
            idx = selected_idx.get()
            if idx >= len(self.cfg.get("servers", [])): messagebox.showerror("no", "Invalid selection"); return
            s = self.cfg["servers"][idx]; self.open_edit_server_dialog(s, idx, dlg)
        tk.Button(dlg, text="Edit selected server", command=edit_selected).pack(padx=6, pady=(6,0))
        def do_unregister():
            ok = messagebox.askyesno("Unregister", "This will unregister this client from the selected server (if online). Continue?")
            if not ok: return
            svr = self.get_active_server()
            if svr:
                try:
                    requests.post(svr["url"].rstrip("/") + "/unregister", json={"id": self.idrec["id"], "key": svr["key"]}, timeout=5)
                except Exception:
                    pass
                self.unregister_local_server(svr["url"])
                messagebox.showinfo("done", "Unregistered locally for that server.")
            else:
                messagebox.showinfo("none", "No active server configured.")
        tk.Button(dlg, text="Unregister (server)", command=do_unregister).pack(pady=8)
        def save_and_close():
            self.cfg["display_name"] = dn.get().strip()
            self.cfg["start_on_startup"] = bool(start_on_startup.get())
            self.cfg["start_with_program"] = bool(startprog.get())
            self.cfg["start_program_path"] = progpath.get().strip()
            self.cfg["close_when_program_closes"] = bool(close_when.get())
            self.cfg["only_sync_when_program_closes"] = bool(only_when_prog_closes.get())
            self.cfg["enable_sync_startup"] = bool(enable_sync.get())
            self.cfg["tray_on_startup"] = bool(tray_on.get())
            save_config(self.cfg)
            try:
                set_start_on_startup_enabled(bool(self.cfg.get("start_on_startup", False)))
            except Exception:
                pass
            dlg.destroy()
        tk.Button(dlg, text="Save", command=save_and_close).pack(pady=6)
        def update_enabled_states(*_):
            enabled = bool(startprog.get())
            state = "normal" if enabled else "disabled"
            prog_entry.config(state=state); browse_btn.config(state=state)
            cb_close_when.config(state=state); cb_only_when.config(state=state)
        update_enabled_states(); startprog.trace_add("write", lambda *a: update_enabled_states())
    def open_edit_server_dialog(self, server_obj, index, parent):
        dlg = tk.Toplevel(parent); dlg.title("Edit server")
        _apply_window_icon(dlg)
        tk.Label(dlg, text="Server URL (ip:port or http://...):").pack(padx=6, pady=6)
        url_var = tk.StringVar(value=server_obj.get("url")); tk.Entry(dlg, textvariable=url_var, width=60).pack(padx=6)
        tk.Label(dlg, text="Server key:").pack(padx=6, pady=(8,0)); key_var = tk.StringVar(value=server_obj.get("key")); tk.Entry(dlg, textvariable=key_var, width=60).pack(padx=6)
        tk.Label(dlg, text="Display name:").pack(padx=6, pady=(8,0)); name_var = tk.StringVar(value=server_obj.get("name")); tk.Entry(dlg, textvariable=name_var, width=60).pack(padx=6)
        status_label = tk.Label(dlg, text="", fg="blue"); status_label.pack(pady=(6,0))
        def do_ping():
            addr = normalize_url(url_var.get().strip()); status_label.config(text="Pinging..."); self.root.update_idletasks(); ok = ping_server(addr); status_label.config(text="Reachable" if ok else "Unreachable", fg="green" if ok else "red")
        tk.Button(dlg, text="Ping", command=do_ping).pack(pady=(6,0))
        def do_save():
            url = normalize_url(url_var.get().strip()); key = key_var.get().strip(); nm = name_var.get().strip() or self.cfg.get("display_name")
            if not url or not key: messagebox.showerror("missing", "Please fill url and key"); return
            if not ping_server(url): messagebox.showerror("unreachable", "Server unreachable."); return
            self.cfg["servers"][index] = {"url": url, "key": key, "name": nm}; save_config(self.cfg); dlg.destroy()
        tk.Button(dlg, text="Save", command=do_save).pack(pady=8)
    def get_active_server(self):
        servers = self.cfg.get("servers", [])
        idx = self.cfg.get("current_server_index", 0)
        if not servers: return None
        if idx >= len(servers): idx = 0
        s = servers[idx].copy(); s["url"] = normalize_url(s.get("url","")); return s
    def open_server_info(self):
        win = ServerInfoWindow(self.root, self)
        win.grab_set()
    def browse_folder(self):
        p = filedialog.askdirectory()
        if p: self.folder_var.set(p)
    def apply_folder(self):
        path = self.folder_var.get().strip()
        if not os.path.isdir(path):
            messagebox.showerror("bad", "Path not a folder"); return
        self.sync_folder = path
        self.cfg["sync_folder"] = path
        save_config(self.cfg)
        self.status_text.set(f"Folder set: {path}")
    def toggle_sync(self):
        if not getattr(self, "sync_folder", None):
            saved = self.cfg.get("sync_folder")
            if saved:
                self.sync_folder = saved
            else:
                messagebox.showerror("No folder", "Select and apply a folder to sync first."); return
        if self.sync_enabled:
            self.stop_sync()
        else:
            self.start_sync()

    # ---------- upload helper with base_update_id and 409 handling ----------
    def upload_helper(self, tmpzip_path, sig):
        url = self.server["url"].rstrip("/") + "/upload"
        files = {"update": open(tmpzip_path, "rb")}
        data = {
            "id": self.idrec["id"],
            "key": self.server["key"],
            "name": self.cfg.get("display_name"),
            "base_update_id": self.applied_version or ""
        }
        try:
            r = requests.post(url, files=files, data=data, timeout=120)
        finally:
            try: files["update"].close()
            except Exception: pass

        if r.status_code == 200:
            try:
                j = r.json(); return True, j.get("update_id")
            except Exception:
                return True, "ok"
        elif r.status_code == 409:
            try:
                j = r.json(); server_cur = j.get("current")
            except Exception:
                server_cur = None
            # prompt user with three options
            dlg = tk.Toplevel(self.root)
            dlg.title("Server changed")
            _apply_window_icon(dlg)
            tk.Label(dlg, text="Server has a newer update than your base. Choose action:").pack(padx=10, pady=10)
            res = {"choice": None}
            def do_download_apply():
                res["choice"] = "download"; dlg.destroy()
            def do_force():
                res["choice"] = "force"; dlg.destroy()
            def do_cancel():
                res["choice"] = "cancel"; dlg.destroy()
            btnf = tk.Frame(dlg); btnf.pack(pady=8)
            tk.Button(btnf, text="Download & apply server update (recommended)", command=do_download_apply).pack(fill="x", padx=8, pady=3)
            tk.Button(btnf, text="Force upload (overwrite server)", command=do_force).pack(fill="x", padx=8, pady=3)
            tk.Button(btnf, text="Cancel", command=do_cancel).pack(fill="x", padx=8, pady=3)
            dlg.transient(self.root); dlg.grab_set(); dlg.lift()
            self.root.wait_window(dlg)
            choice = res["choice"]
            if choice == "download":
                cur = server_cur
                if cur:
                    self.root.after(0, lambda: self.status_text.set("Fetching server update..."))
                    applied = self.download_and_apply(cur)
                    if applied:
                        return False, "rebase_done"
                    else:
                        return False, "download_failed"
                return False, "no_server_current"
            elif choice == "force":
                files2 = {"update": open(tmpzip_path, "rb")}
                data2 = {"id": self.idrec["id"], "key": self.server["key"], "name": self.cfg.get("display_name"), "base_update_id": ""}
                try:
                    r2 = requests.post(url, files=files2, data=data2, timeout=120)
                finally:
                    try: files2["update"].close()
                    except Exception: pass
                if r2.status_code == 200:
                    try:
                        return True, r2.json().get("update_id")
                    except Exception:
                        return True, "ok"
                else:
                    try:
                        return False, r2.json()
                    except Exception:
                        return False, r2.text
            else:
                return False, "cancelled"
        else:
            try:
                return False, r.json()
            except Exception:
                return False, r.text
    def start_sync(self):
        s = self.get_active_server()
        if not s:
            messagebox.showerror("No server", "Add a server first."); return
        self.server = s
        try:
            payload = {"id": self.idrec["id"], "name": self.cfg.get("display_name"), "key": s["key"], "applied_version": self.applied_version}
            r = requests.post(s["url"].rstrip("/") + "/register", json=payload, timeout=5)
            if r.status_code == 403:
                try:
                    err = r.json().get("error", "forbidden")
                except Exception:
                    err = r.text
                self.status_text.set(f"Register blocked: {err}"); return
            if r.status_code != 200:
                messagebox.showerror("reg failed", r.text); return
        except Exception as e:
            messagebox.showerror("reg failed", str(e)); return
        # startup mismatch check (modal once)
        try:
            r2 = requests.get(s["url"].rstrip("/") + "/status", params={"key": s.get("key", "")}, timeout=6)
            server_last_time = None
            current_meta = {}
            if r2.status_code == 200:
                j = r2.json()
                server_last_time = j.get("last_update_time")
                current_meta = j.get("current_meta", {}) or {}
            else:
                server_last_time = None
        except Exception:
            server_last_time = None
            current_meta = {}
        local_dt = None
        if self.sync_folder:
            local_dt = local_latest_mtime(self.sync_folder)
        server_dt = iso_to_dt(server_last_time)
        do_prompt = False
        if local_dt and server_dt:
            if local_dt > server_dt + timedelta(seconds=1):
                do_prompt = True
        elif local_dt and not server_dt:
            do_prompt = True
        if do_prompt and not self.mismatch_modal_shown:
            chosen_action = self.startup_conflict_popup(local_dt, server_dt, s, current_meta)
            self.mismatch_modal_shown = True
            if chosen_action == "upload":
                self._perform_upload_now()
            elif chosen_action == "use_server":
                cur = None
                try:
                    rr = requests.get(s["url"].rstrip("/") + "/updates", params={"key": s.get("key", "")}, timeout=6)
                    if rr.status_code == 200:
                        cur = rr.json().get("current")
                except Exception:
                    cur = None
                if cur:
                    self.download_and_apply(cur)
            else:
                self.mismatch_state = {"type": "startup_unresolved", "local": local_dt.isoformat() if local_dt else None, "server": server_last_time}
                self.status_text.set("Local > server (startup) — resolve in Settings")
        elif do_prompt and self.mismatch_modal_shown:
            # don't re-show; just update status
            self.mismatch_state = {"type": "startup_unresolved", "local": local_dt.isoformat() if local_dt else None, "server": server_last_time}
            self.status_text.set("Local > server — startup mismatch (popup shown earlier)")
        else:
            self.mismatch_state = None
        # enable sync
        self.sync_enabled = True
        self.init_button.config(text="Stop (Disable Sync)")
        self.status_text.set("Sync enabled")
        self.stop_poll.clear()
        self.poll_thread = threading.Thread(target=self.poll_loop, daemon=True)
        self.poll_thread.start()
        self.start_watcher()
        persisted_sig = self.cfg.get("last_uploaded_hash", "")
        if persisted_sig:
            self._last_seen_signature = persisted_sig
        else:
            try:
                self._last_seen_signature = compute_folder_signature(self.sync_folder) or ""
            except Exception:
                self._last_seen_signature = ""
        if self.applied_version:
            self.cfg["applied_version"] = self.applied_version
            save_config(self.cfg)
        self.send_heartbeat(sync_enabled=True)
    def startup_conflict_popup(self, local_dt, server_dt, server_obj, current_meta):
        txt_local = local_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S UTC") if local_dt else "(none)"
        txt_server = server_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S UTC") if server_dt else "(no server backup)"
        info = f"Local latest modification: {txt_local}\nServer latest backup: {txt_server}\n\nChoose how to resolve:"
        win = tk.Toplevel(self.root)
        win.title("Local vs Server mismatch")
        _apply_window_icon(win)
        win.geometry("520x220")
        win.attributes("-topmost", True)
        tk.Label(win, text=info, justify="left", anchor="w").pack(fill="both", padx=12, pady=12)
        res = {"choice": None}
        def do_upload():
            res["choice"] = "upload"; win.grab_release(); win.destroy()
        def do_use_server():
            res["choice"] = "use_server"; win.grab_release(); win.destroy()
        def do_cancel():
            res["choice"] = None; win.grab_release(); win.destroy()
        btnf = tk.Frame(win); btnf.pack(pady=12)
        tk.Button(btnf, text="Upload local (replace server)", command=do_upload).pack(side="left", padx=8)
        tk.Button(btnf, text="Use server backup (download & apply)", command=do_use_server).pack(side="left", padx=8)
        tk.Button(btnf, text="Cancel (do nothing)", command=do_cancel).pack(side="left", padx=8)
        win.transient(self.root); win.grab_set(); win.lift()
        self.root.wait_window(win)
        return res["choice"]
    def _perform_upload_now(self):
        if not self.sync_folder:
            self.root.after(0, lambda: messagebox.showerror("No folder", "No folder selected to upload."))
            return
        tmpzip = None
        try:
            sig = compute_folder_signature(self.sync_folder)
            timestamp = int(time.time())
            tmpzip = APP_DIR / f"upload-{timestamp}.zip"
            manifest = zip_folder_with_manifest(self.sync_folder, tmpzip)
            ok, res = self.upload_helper(tmpzip, sig)
            if ok:
                update_id = res
                self.applied_version = update_id
                self.cfg["applied_version"] = update_id
                self.cfg["last_uploaded_hash"] = sig
                save_config(self.cfg)
                try: APPLIED_FILE.write_text(self.applied_version)
                except Exception: pass
                try:
                    requests.post(self.server["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": update_id, "key": self.server.get("key", ""), "name": self.cfg.get("display_name")}, timeout=6)
                except Exception:
                    pass
                self.root.after(0, lambda: self.status_text.set(f"Upload OK -> {update_id}"))
            else:
                if res == "rebase_done":
                    self.root.after(0, lambda: self.status_text.set("Rebased from server; you may reattempt upload"))
                else:
                    self.root.after(0, lambda: self.status_text.set(f"Upload aborted: {res}"))
        except Exception as e:
            self.root.after(0, lambda: self.status_text.set(f"Startup upload error: {e}"))
            traceback.print_exc()
        finally:
            try:
                if tmpzip:
                    tmpzip.unlink(missing_ok=True)
            except Exception:
                pass
    def download_and_apply(self, update_id):
        """
        Download zip -> validate -> read manifest -> compute conflict list (includes deletion conflicts)
        -> show conflict popup if needed -> apply update (including deletions when applying server version)
        """
        try:
            url = self.server["url"].rstrip("/") + f"/download/{update_id}"
            dl = requests.get(url, params={"key": self.server.get("key", "")}, timeout=90)
            if dl.status_code != 200:
                self.root.after(0, lambda: self.status_text.set(f"Download failed: {dl.status_code}"))
                return False
            tmpzip = APP_DIR / f"{update_id}.zip"
            with open(tmpzip, "wb") as f:
                f.write(dl.content)
            # basic zip validity check
            try:
                with zipfile.ZipFile(tmpzip, "r") as z:
                    bad = z.testzip()
                    if bad is not None:
                        tmpzip.unlink(missing_ok=True)
                        self.root.after(0, lambda: self.status_text.set("Downloaded update corrupted"))
                        return False
            except zipfile.BadZipFile:
                tmpzip.unlink(missing_ok=True)
                self.root.after(0, lambda: self.status_text.set("Downloaded update corrupted"))
                return False
            # parse manifest
            try:
                with zipfile.ZipFile(tmpzip, "r") as z:
                    if "manifest.json" in z.namelist():
                        manifest = json.loads(z.read("manifest.json").decode("utf-8"))
                    else:
                        # backward compatibility: if no manifest then treat zip contents as "all files" without created time
                        manifest = {"created": None, "files": [{"path": n, "hash": None, "mtime": None} for n in z.namelist() if not n.endswith("/")]}
            except Exception:
                tmpzip.unlink(missing_ok=True)
                self.root.after(0, lambda: self.status_text.set("Bad manifest in update"))
                return False
            incoming_files = {f["path"]: f for f in manifest.get("files", [])}
            created_iso = manifest.get("created")
            created_dt = iso_to_dt(created_iso)
            # detect conflicts:
            conflicts = []          # files that exist both places but differ
            deletion_conflicts = [] # local files that are NOT in incoming manifest but are newer than update -> potential data loss
            # check file-level conflicts
            for path, finfo in incoming_files.items():
                localp = pathlib.Path(self.sync_folder) / path
                try:
                    incoming_hash = finfo.get("hash") or ""
                    if localp.exists():
                        local_hash = compute_file_hash(localp)
                        if incoming_hash and local_hash != incoming_hash:
                            conflicts.append(path)
                except Exception:
                    # if unreadable, consider it conflict
                    if localp.exists():
                        conflicts.append(path)
            # check local-only files that would be deleted
            # build set of incoming paths
            inc_paths = set(incoming_files.keys())
            # walk local folder
            for root, dirs, files in os.walk(self.sync_folder):
                for f in files:
                    p = pathlib.Path(root) / f
                    rel = str(p.relative_to(self.sync_folder)).replace("\\", "/")
                    if rel not in inc_paths:
                        # candidate for deletion; if local mtime is newer than incoming created time -> conflict
                        try:
                            local_m = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
                        except Exception:
                            local_m = None
                        is_conflict = False
                        if created_dt is None:
                            # no created time — conservatively treat as conflict to avoid data loss
                            is_conflict = True
                        else:
                            if local_m and local_m > created_dt + timedelta(seconds=1):
                                is_conflict = True
                        if is_conflict:
                            deletion_conflicts.append(rel)
            # aggregate conflict list (include deletion_conflicts as special)
            any_conflict = bool(conflicts or deletion_conflicts)
            if any_conflict:
                # show popup listing both kinds (mark deletion items)
                self.root.after(0, lambda: self.show_conflict_popup_with_deletions(conflicts, deletion_conflicts, tmpzip))
                return False
            # no conflicts: apply update and delete any files not present in manifest (mirror behavior)
            self.apply_update_zip_with_manifest(tmpzip, self.sync_folder, incoming_files, keep_local=False)
            # ack
            try:
                requests.post(self.server["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": update_id, "key": self.server.get("key", ""), "name": self.cfg.get("display_name")}, timeout=6)
            except Exception:
                pass
            self.applied_version = update_id
            self.cfg["applied_version"] = update_id
            save_config(self.cfg)
            try:
                APPLIED_FILE.write_text(update_id)
            except Exception:
                pass
            self.root.after(0, lambda: self.status_text.set(f"Applied update {update_id}"))
            try:
                tmpzip.unlink(missing_ok=True)
            except Exception:
                pass
            return True
        except Exception as e:
            traceback.print_exc()
            self.root.after(0, lambda: self.status_text.set(f"Download/apply error: {e}"))
            return False
    def show_conflict_popup_with_deletions(self, conflicts, deletion_conflicts, tmpzip):
        # build unified UI that shows both change conflicts and deletion candidates
        win = tk.Toplevel(self.root); win.title("Conflicts detected"); win.geometry("520x420")
        _apply_window_icon(win)
        tk.Label(win, text=f"Conflicts detected.", anchor="w").pack(fill="x", padx=8, pady=6)
        fr = tk.Frame(win); fr.pack(fill="both", expand=True, padx=8)
        tk.Label(fr, text="Files that differ (will be overwritten):").pack(anchor="w")
        lb1 = tk.Listbox(fr, height=8)
        lb1.pack(fill="both", expand=False, pady=2)
        for c in conflicts: lb1.insert("end", c)
        tk.Label(fr, text="Local files that would be deleted by server (newer locally):").pack(anchor="w", pady=(6,0))
        lb2 = tk.Listbox(fr, height=8)
        lb2.pack(fill="both", expand=False, pady=2)
        for c in deletion_conflicts: lb2.insert("end", c)
        def apply_server():
            # apply incoming but do NOT keep conflicted local files (overwrite), delete absent files
            self.apply_update_zip_with_manifest(tmpzip, self.sync_folder, None, keep_local=False)
            try:
                requests.post(self.server["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": tmpzip.stem, "key": self.server.get("key", ""), "name": self.cfg.get("display_name")}, timeout=6)
            except Exception:
                pass
            win.destroy()
            self.root.after(0, lambda: self.status_text.set("Applied server update (overwrite/delete)"))
        def keep_local():
            # do nothing: keep local files, but ack (so server thinks applied)
            try:
                requests.post(self.server["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": tmpzip.stem, "key": self.server.get("key", ""), "name": self.cfg.get("display_name")}, timeout=6)
            except Exception:
                pass
            win.destroy()
    def apply_update_zip_with_manifest(self, zip_path, target_folder, incoming_files_map=None, keep_local=False):
        """
        Unpack files from zip into target_folder. If incoming_files_map provided (dict path->meta),
        then after extracting we will delete any local files not in incoming_files_map unless keep_local=True.
        If keep_local is True, local-only files are preserved.
        """
        tmp_extract = tempfile.mkdtemp(prefix="fs_apply_")
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                # extract everything to tmp folder
                z.extractall(tmp_extract)
            # copy files from tmp into target (overwrite or rename as requested)
            for root, dirs, files in os.walk(tmp_extract):
                for f in files:
                    relpath = os.path.relpath(os.path.join(root, f), tmp_extract).replace("\\", "/")
                    src = pathlib.Path(root) / f
                    dst = pathlib.Path(target_folder) / relpath
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if dst.exists() and keep_local:
                        # rename existing local to keep it
                        ts = int(time.time())
                        renamed = dst.with_name(dst.name + f".conflict-{self.idrec['id'][:6]}-{ts}")
                        try:
                            dst.rename(renamed)
                        except Exception:
                            # fallback: try to remove then write
                            pass
                    # write incoming file
                    try:
                        shutil.copy2(src, dst)
                    except Exception:
                        try:
                            # fallback: raw write
                            data = src.read_bytes()
                            with open(dst, "wb") as w: w.write(data)
                        except Exception:
                            pass
            # now delete local files not in incoming_files_map unless keep_local True
            if incoming_files_map is not None and not keep_local:
                incoming_set = set(incoming_files_map.keys())
                for root, dirs, files in os.walk(target_folder):
                    for f in files:
                        p = pathlib.Path(root) / f
                        rel = str(p.relative_to(target_folder)).replace("\\", "/")
                        if rel not in incoming_set:
                            try:
                                p.unlink()
                            except Exception:
                                pass
            # update applied version / saved state handled by caller
        finally:
            try:
                shutil.rmtree(tmp_extract)
            except Exception:
                pass
    def start_watcher(self):
        if not self.sync_folder:
            return
        if self.observer:
            return
        self.watcher_handler = DebounceHandler(self._on_folder_debounced)
        self.observer = Observer()
        self.observer.schedule(self.watcher_handler, path=self.sync_folder, recursive=True)
        self.observer.daemon = True
        self.observer.start()
    def stop_watcher(self):
        if self.observer:
            self.observer.stop(); self.observer.join(timeout=1.0); self.observer = None; self.watcher_handler = None
    def _on_folder_debounced(self):
        # triggered by watcher; schedule upload (debounced)
        if not (self.sync_enabled and self.server and self.sync_folder):
            return
        if not self._upload_lock.acquire(blocking=False):
            return
        def worker():
            tmpzip = None
            try:
                sig = compute_folder_signature(self.sync_folder)
                last = self.cfg.get("last_uploaded_hash", "")
                if sig and sig == last:
                    # no real content-change
                    self.root.after(0, lambda: self.status_text.set("No content change; skipping upload"))
                    return
                timestamp = int(time.time())
                tmpzip = APP_DIR / f"upload-{timestamp}.zip"
                manifest = zip_folder_with_manifest(self.sync_folder, tmpzip)
                ok, res = self.upload_helper(tmpzip, sig)
                if ok:
                    update_id = res
                    self.applied_version = update_id
                    self.cfg["applied_version"] = update_id
                    self.cfg["last_uploaded_hash"] = sig
                    save_config(self.cfg)
                    try: APPLIED_FILE.write_text(self.applied_version)
                    except Exception: pass
                    try:
                        requests.post(self.server["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": update_id, "key": self.server.get("key", ""), "name": self.cfg.get("display_name")}, timeout=6)
                    except Exception:
                        pass
                    self.root.after(0, lambda: self.status_text.set(f"Upload OK -> {update_id}"))
                else:
                    if res == "rebase_done":
                        self.root.after(0, lambda: self.status_text.set("Upload deferred: rebased to server"))
                    else:
                        self.root.after(0, lambda: self.status_text.set(f"Upload aborted: {res}"))
            finally:
                try:
                    if tmpzip: tmpzip.unlink(missing_ok=True)
                except Exception:
                    pass
                self._upload_lock.release()
        threading.Thread(target=worker, daemon=True).start()
    def poll_loop(self):
        # periodic poll: also performs a safety signature scan in case watcher missed changes
        scan_interval = DEFAULT_POLL_INTERVAL
        counter = 0
        while not self.stop_poll.is_set():
            try:
                # every poll compute signature to catch missed events (cheap-ish)
                try:
                    if self.sync_enabled and self.sync_folder:
                        sig = compute_folder_signature(self.sync_folder)
                        last = self.cfg.get("last_uploaded_hash", "")
                        if sig and sig != last:
                            # schedule an upload (non-blocking)
                            self._on_folder_debounced()
                except Exception:
                    pass
                self.poll_once()
            except Exception as e:
                print("poll error", e)
            time.sleep(scan_interval)
    def poll_once(self):
        s = self.server
        if not s:
            return
        try:
            r = requests.get(s["url"].rstrip("/") + "/updates", params={"key": s.get("key", "")}, timeout=POLL_TIMEOUT_SECONDS)
            if r.status_code != 200:
                self.root.after(0, lambda: self.status_text.set("No connection"))
                return
            data = r.json()
            last_msg = data.get("last_update_message")
            last_time = data.get("last_update_time")
            if last_msg:
                short_t = short_time_from_iso(last_time)
                if short_t:
                    self.root.after(0, lambda: self.status_text.set(f"Last update: {last_msg} @ {short_t}"))
                else:
                    self.root.after(0, lambda: self.status_text.set(f"Last update: {last_msg}"))
            else:
                # If we successfully reached the server but there is no last_update_message,
                # make sure we clear any previous "No connection" status.
                self.root.after(0, lambda: self.status_text.set("Connected"))
            cur = data.get("current")
            cur_meta = data.get("current_meta", {}) or {}
            # skip if current update uploaded by this client (server marks uploader)
            if cur and cur_meta.get("uploader_id") == self.idrec["id"]:
                if cur != self.applied_version:
                    self.applied_version = cur
                    self.cfg["applied_version"] = cur
                    save_config(self.cfg)
                    try: APPLIED_FILE.write_text(cur)
                    except Exception: pass
                    try:
                        requests.post(s["url"].rstrip("/") + "/ack", json={"id": self.idrec["id"], "update_id": cur, "key": s.get("key", ""), "name": self.cfg.get("display_name")}, timeout=4)
                    except Exception:
                        pass
                return
            # check for mismatch (local newer than server) — update status only (no modal)
            server_dt = iso_to_dt(last_time)
            local_dt = None
            if self.sync_folder:
                local_dt = local_latest_mtime(self.sync_folder)
            mismatch_detected = False
            if local_dt and server_dt:
                if local_dt > server_dt + timedelta(seconds=1):
                    mismatch_detected = True
            elif local_dt and not server_dt:
                mismatch_detected = True
            if mismatch_detected:
                self.mismatch_state = {"local_latest": local_dt.isoformat() if local_dt else None, "server_latest": last_time}
                short_local = local_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S") if local_dt else "(none)"
                short_server = short_time_from_iso(last_time) if last_time else "(no backup)"
                self.root.after(0, lambda: self.status_text.set(f"Mismatch: local {short_local} > server {short_server} — open UI to resolve"))
                return
            # otherwise, if there is a new current update (not applied), download and apply
            if cur and cur != self.applied_version:
                applied_ok = self.download_and_apply(cur)
                if applied_ok:
                    self._maybe_launch_program_now(cur)
                return

            # Up-to-date (or no server current): we can launch the program if requested.
            self._maybe_launch_program_now(cur)
        except Exception as e:
            msg = str(e)
            now_ts = time.time()
            should_print = False
            if msg != self._last_poll_exception_msg:
                should_print = True
            elif (now_ts - (self._last_poll_exception_print_ts or 0.0)) >= 60:
                should_print = True
            if should_print:
                print("poll exception", e)
                self._last_poll_exception_msg = msg
                self._last_poll_exception_print_ts = now_ts
            try:
                self.root.after(0, lambda: self.status_text.set("No connection"))
            except Exception:
                pass
    def detect_conflicts(self, zip_path, target_folder):
        # kept for compatibility — not used; conflict detection is in download_and_apply
        return []
    def unregister_local_server(self, server_url):
        servers = self.cfg.get("servers", [])
        new = [s for s in servers if normalize_url(s.get("url")) != normalize_url(server_url)]
        self.cfg["servers"] = new
        if self.cfg.get("current_server_index", 0) >= len(new):
            self.cfg["current_server_index"] = 0
        save_config(self.cfg)
    def send_heartbeat(self, sync_enabled=False):
        s = self.server
        if not s:
            return
        try:
            payload = {"id": self.idrec["id"], "sync_enabled": bool(sync_enabled), "name": self.cfg.get("display_name"), "key": s.get("key", "")}
            r = requests.post(s["url"].rstrip("/") + "/heartbeat", json=payload, timeout=HEARTBEAT_TIMEOUT_SECONDS)
            if r.status_code == 403:
                try:
                    err = r.json().get("error", "blocked")
                except Exception:
                    err = "blocked"
                self.root.after(0, lambda: self.status_text.set(f"Blocked by server: {err}"))
                self.root.after(0, self.stop_sync)
        except Exception:
            pass
    def stop_sync(self):
        self.sync_enabled = False
        self.init_button.config(text="Initialize (Enable Sync)")
        self.status_text.set("Sync disabled")
        self.stop_poll.set()
        self.stop_watcher()
        self.send_heartbeat(sync_enabled=False)
    def create_image(self):
        img = Image.new('RGB', (64, 64), (40,90,200))
        d = ImageDraw.Draw(img); d.rectangle((8,16,56,48), fill=(255,255,255)); d.text((18,20), "FS", fill=(0,0,0))
        return img
    def create_tray_icon(self):
        image = _load_tray_image() or self.create_image()

        def toggle_startup_from_tray(icon, item):
            new_val = not bool(self.cfg.get("start_on_startup", False))
            self.cfg["start_on_startup"] = new_val
            save_config(self.cfg)
            try:
                set_start_on_startup_enabled(new_val)
            except Exception:
                pass

        menu = pystray.Menu(
            pystray.MenuItem('Toggle Sync', lambda icon, item: self.toggle_sync_from_tray()),
            pystray.MenuItem(
                'Start on startup',
                toggle_startup_from_tray,
                checked=lambda item: bool(self.cfg.get("start_on_startup", False)),
            ),
            pystray.MenuItem('Show', lambda icon, item: self.show_window()),
            pystray.MenuItem('Exit', lambda icon, item: self.exit_app()),
        )
        self.tray = pystray.Icon("foldersharer", image, "FolderSharer", menu)
        t = threading.Thread(target=self.tray.run, daemon=True); t.start()
    def toggle_sync_from_tray(self): self.root.after(0, self.toggle_sync)
    def show_window(self): self.root.deiconify(); self.root.lift()
    def exit_app(self):
        try: self.tray.stop()
        except Exception: pass
        os._exit(0)
    def on_close(self): self.root.withdraw(); self.status_text.set("Exited to tray")
    def try_autostart(self):
        if self._autostart_done:
            return
        self._autostart_done = True

        enable_sync_startup = bool(self.cfg.get("enable_sync_startup", True))
        only_sync_when_program_closes = bool(self.cfg.get("only_sync_when_program_closes", False))
        start_with_program = bool(self.cfg.get("start_with_program", False))

        should_start_sync_now = enable_sync_startup and bool(getattr(self, "sync_folder", None))
        if start_with_program and only_sync_when_program_closes:
            should_start_sync_now = False

        if should_start_sync_now and not self.sync_enabled:
            self.start_sync()

        if start_with_program:
            # Launch only when we're ready (after successful poll and up-to-date)
            self._launch_program_when_ready = True

def main():
    _set_windows_app_user_model_id("FolderSharer.Client")
    root = tk.Tk()
    _apply_window_icon(root)
    app = ClientApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
