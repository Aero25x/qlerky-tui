#!/usr/bin/env python3
"""
qlerky_tui — btop-style Mail + TOTP TUI  (pure stdlib)

Keys:
  h/l  or  1/2/3   switch panel focus
  j/k  ↑↓          navigate list
  Tab              cycle focus
  Enter            connect account
  a                add account
  d                delete account
  i                import accounts from file
  t                import TOTP secret
  y / Y            copy TOTP current / next code
  r / F5           manual inbox refresh
  /                search / filter
  ESC              close search
  ?                help overlay
  q / Ctrl+C       quit
"""

import base64
import curses
import datetime
import email
import email.header
import email.utils
import hashlib
import hmac
import imaplib
import json
import os
import platform
import re
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional

# ── Windows curses shim ───────────────────────────────────────────────────────
if platform.system() == "Windows":
    try:
        import windows_curses  # noqa: F401  (patches curses in-place)
    except ImportError:
        print("ERROR: on Windows, install windows-curses first:", file=sys.stderr)
        print("  pip install windows-curses", file=sys.stderr)
        sys.exit(1)

# ── config ────────────────────────────────────────────────────────────────────
CONFIG_DIR = Path.home() / ".config" / "qlerky_tui"
ACCOUNTS_FILE = CONFIG_DIR / "accounts.json"
TOTP_FILE = CONFIG_DIR / "totp.json"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

IMAP_MAP = {
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),
    "yahoo.com": ("imap.mail.yahoo.com", 993),
    "yahoo.co.uk": ("imap.mail.yahoo.com", 993),
    "ymail.com": ("imap.mail.yahoo.com", 993),
    "outlook.com": ("outlook.office365.com", 993),
    "hotmail.com": ("outlook.office365.com", 993),
    "live.com": ("outlook.office365.com", 993),
    "msn.com": ("outlook.office365.com", 993),
    "icloud.com": ("imap.mail.me.com", 993),
    "me.com": ("imap.mail.me.com", 993),
    "mac.com": ("imap.mail.me.com", 993),
    "protonmail.com": ("127.0.0.1", 1143),
    "proton.me": ("127.0.0.1", 1143),
    "fastmail.com": ("imap.fastmail.com", 993),
    "fastmail.fm": ("imap.fastmail.com", 993),
    "zoho.com": ("imap.zoho.com", 993),
    "gmx.com": ("imap.gmx.com", 993),
    "gmx.net": ("imap.gmx.net", 993),
    "mail.ru": ("imap.mail.ru", 993),
    "bk.ru": ("imap.mail.ru", 993),
    "list.ru": ("imap.mail.ru", 993),
    "inbox.ru": ("imap.mail.ru", 993),
    "yandex.ru": ("imap.yandex.ru", 993),
    "yandex.com": ("imap.yandex.com", 993),
    "ya.ru": ("imap.yandex.ru", 993),
    "aol.com": ("imap.aol.com", 993),
}

CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")

REFRESH_INTERVAL = 15  # seconds between auto-inbox-refresh


def guess_imap(addr: str):
    dom = addr.split("@")[-1].lower() if "@" in addr else addr
    if dom in IMAP_MAP:
        return IMAP_MAP[dom]
    for k, v in IMAP_MAP.items():
        if dom.endswith("." + k):
            return v
    return (f"imap.{dom}", 993)


def load_json(p: Path, d):
    try:
        return json.loads(p.read_text()) if p.exists() else d
    except Exception:
        return d


def save_json(p: Path, d):
    p.write_text(json.dumps(d, indent=2, ensure_ascii=False))


# ── TOTP ──────────────────────────────────────────────────────────────────────
def totp(secret: str, offset=0) -> str:
    try:
        s = secret.upper().replace(" ", "")
        s += "=" * ((8 - len(s) % 8) % 8)
        key = base64.b32decode(s)
        t = struct.pack(">Q", int(time.time() // 30) + offset)
        h = hmac.new(key, t, hashlib.sha1).digest()
        o = h[-1] & 0xF
        code = (struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1_000_000
        return str(code).zfill(6)
    except Exception:
        return "------"


def totp_left() -> int:
    return 30 - int(time.time()) % 30


def parse_otpauth(uri: str) -> Optional[dict]:
    try:
        p = urllib.parse.urlparse(uri)
        if p.scheme != "otpauth" or p.netloc != "totp":
            return None
        label = urllib.parse.unquote(p.path.lstrip("/"))
        params = dict(urllib.parse.parse_qsl(p.query))
        issuer, account = params.get("issuer", ""), label
        if ":" in label:
            i2, account = label.split(":", 1)
            issuer = issuer or i2
        return {
            "label": issuer or account,
            "secret": params.get("secret", ""),
            "issuer": issuer,
            "account": account.strip(),
        }
    except Exception:
        return None


def env_totp():
    for v in ("TOTP_QR", "TOTP_URI", "OTP_URI"):
        val = os.environ.get(v, "").strip()
        if val:
            return parse_otpauth(val)
    return None


# ── email helpers ─────────────────────────────────────────────────────────────
def decode_hdr(val: str) -> str:
    parts = email.header.decode_header(val or "")
    out = []
    for part, enc in parts:
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(str(part))
    return " ".join(out)


def strip_html(html_str: str) -> str:
    import html as _html

    h = html_str
    h = re.sub(r"<br\s*/?>", "\n", h, flags=re.I)
    h = re.sub(r"</(p|div|tr|li|h[1-6])>", "\n", h, flags=re.I)
    h = re.sub(r"<(p|div|tr|li|h[1-6])[^>]*>", "\n", h, flags=re.I)
    h = re.sub(r"<[^>]+>", "", h)
    h = _html.unescape(h)
    lines = [l.strip() for l in h.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def extract_body(m) -> str:
    plain = html = None
    if m.is_multipart():
        for part in m.walk():
            ct = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                continue
            if ct == "text/plain" and plain is None:
                plain = text
            elif ct == "text/html" and html is None:
                html = text
    else:
        try:
            payload = m.get_payload(decode=True)
            text = (
                payload.decode(m.get_content_charset() or "utf-8", errors="replace")
                if payload
                else ""
            )
        except Exception:
            text = ""
        if m.get_content_type() == "text/plain":
            plain = text
        else:
            html = text
    if plain:
        return plain
    if html:
        return strip_html(html)
    return ""


# ── IMAP client ───────────────────────────────────────────────────────────────
class MailClient:
    def __init__(self, acc: dict):
        self.acc = acc
        self.conn: Optional[imaplib.IMAP4_SSL] = None
        self.messages: list = []
        self.status = "disconnected"
        self.error = ""
        self._lock = threading.Lock()
        self._fetching = False  # FIX: track first-fetch in progress

    def _open(self) -> bool:
        """Open a fresh SSL connection and login. Returns True on success."""
        import ssl as _ssl

        try:
            host = self.acc.get("imap_host", "imap.gmail.com")
            port = int(self.acc.get("imap_port", 993))
            ctx = _ssl.create_default_context()
            c = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            c.login(self.acc["email"], self.acc["password"])
            self.conn = c
            return True
        except Exception as e:
            self.conn = None
            self.status = "error"
            self.error = str(e)[:120]
            return False

    def connect(self):
        self.status = "connecting..."
        self.error = ""
        if self._open():
            self.status = "connected"
            self.fetch_inbox()

    def disconnect(self):
        try:
            if self.conn:
                self.conn.logout()
        except Exception:
            pass
        self.conn = None
        self.status = "disconnected"

    def fetch_inbox(self, limit=30):
        """Fetch headers. Reconnects automatically if connection dropped.
        FIX: preserve existing body/codes on refresh so content panel
        doesn't flash back to 'loading' every 15 seconds."""
        self._fetching = True
        # try to reuse, or reconnect once
        if not self.conn:
            if not self._open():
                self._fetching = False
                return
        try:
            self.conn.select("INBOX")
        except Exception:
            if not self._open():
                self._fetching = False
                return
            try:
                self.conn.select("INBOX")
            except Exception as e:
                self.error = str(e)[:120]
                self._fetching = False
                return

        try:
            _, data = self.conn.search(None, "ALL")
            ids = data[0].split()[-limit:][::-1]
            msgs = []

            # FIX: build a lookup of already-fetched bodies keyed by uid
            with self._lock:
                existing = {m["uid"]: m for m in self.messages}

            for uid in ids:
                try:
                    _, raw = self.conn.fetch(
                        uid, "(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])"
                    )
                except Exception:
                    continue
                if not raw or not raw[0]:
                    continue
                hdr = email.message_from_bytes(raw[0][1])
                subj = decode_hdr(hdr.get("Subject", "(no subject)"))
                frm = decode_hdr(hdr.get("From", ""))
                date_str = hdr.get("Date", "")
                try:
                    dts = email.utils.parsedate_to_datetime(date_str).strftime(
                        "%m/%d %H:%M"
                    )
                except Exception:
                    dts = date_str[:16]

                # FIX: carry over body/codes if already loaded for this uid
                prev = existing.get(uid, {})
                msgs.append(
                    {
                        "uid": uid,
                        "subject": subj,
                        "from": frm,
                        "date": dts,
                        "body": prev.get("body", None),  # keep loaded body
                        "codes": prev.get("codes", []),  # keep extracted codes
                    }
                )
            with self._lock:
                self.messages = msgs
            self.status = "connected"
        except Exception as e:
            self.error = str(e)[:120]
            self.conn = None  # force reconnect next time
        finally:
            self._fetching = False

    def fetch_body(self, idx: int):
        """Fetch full RFC822 body on a SEPARATE connection (thread-safe)."""
        if idx >= len(self.messages):
            return
        # guard against duplicate threads
        with self._lock:
            if self.messages[idx].get("body") == "__loading__":
                return
            self.messages[idx]["body"] = "__loading__"

        uid = self.messages[idx]["uid"]
        try:
            host = self.acc.get("imap_host", "imap.gmail.com")
            port = int(self.acc.get("imap_port", 993))
            import ssl as _ssl

            ctx = _ssl.create_default_context()
            c2 = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            c2.login(self.acc["email"], self.acc["password"])
            c2.select("INBOX")
            _, raw = c2.fetch(uid, "(RFC822)")
            try:
                c2.logout()
            except Exception:
                pass
            m = email.message_from_bytes(raw[0][1])
            body = extract_body(m)
            subj = self.messages[idx].get("subject", "")
            codes = list(dict.fromkeys(CODE_RE.findall(f"{subj}\n{body}")))
            with self._lock:
                self.messages[idx]["body"] = body if body else ""
                self.messages[idx]["codes"] = codes
        except Exception as e:
            with self._lock:
                self.messages[idx]["body"] = f"[Error: {e}]"
                self.messages[idx]["codes"] = []


# ── clipboard ─────────────────────────────────────────────────────────────────
def clipboard(text: str) -> bool:
    # Windows
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["clip"],
                input=text.encode("utf-16-le"),
                check=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            return True
        except Exception:
            pass
        try:
            # PowerShell fallback
            subprocess.run(
                ["powershell", "-command", f"Set-Clipboard -Value '{text}'"],
                check=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            return True
        except Exception:
            pass
        return False
    # macOS / Linux
    for cmd in (
        ["pbcopy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["wl-copy"],
    ):
        try:
            subprocess.run(
                cmd,
                input=text.encode(),
                check=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            return True
        except Exception:
            continue
    return False


# ── colors ────────────────────────────────────────────────────────────────────
C_BORDER = 1
C_TITLE = 2
C_SEL = 3
C_HDR = 4
C_OK = 5
C_ERR = 6
C_WARN = 7
C_DIM = 8
C_CODE = 9
C_KEY = 10
C_ACCENT = 11
C_BTN = 12
C_HOTKEY = 13


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    bg = -1
    curses.init_pair(C_BORDER, curses.COLOR_CYAN, bg)
    curses.init_pair(C_TITLE, curses.COLOR_CYAN, bg)
    curses.init_pair(C_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_HDR, curses.COLOR_WHITE, bg)
    curses.init_pair(C_OK, curses.COLOR_GREEN, bg)
    curses.init_pair(C_ERR, curses.COLOR_RED, bg)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
    curses.init_pair(C_DIM, 8, bg)
    curses.init_pair(C_CODE, curses.COLOR_GREEN, bg)
    curses.init_pair(C_KEY, curses.COLOR_CYAN, bg)
    curses.init_pair(C_ACCENT, curses.COLOR_MAGENTA, bg)
    curses.init_pair(C_BTN, curses.COLOR_WHITE, bg)
    curses.init_pair(C_HOTKEY, curses.COLOR_CYAN, bg)


# ── safe drawing ──────────────────────────────────────────────────────────────
TL = "╭"
TR = "╮"
BL = "╰"
BR = "╯"
BH = "─"
BV = "│"
LT = "├"
RT = "┤"
BF = "█"
BE = "░"


def _put(win, y, x, s, a=0):
    if not s:
        return
    H, W = win.getmaxyx()
    if y < 0 or y >= H or x < 0 or x >= W:
        return
    avail = W - x
    s = s[:avail]
    if not s:
        return
    try:
        win.addstr(y, x, s, a)
    except curses.error:
        pass


def draw_box(win, y, x, h, w, title="", active=False, rbtns=None):
    ab = curses.color_pair(C_BORDER)
    at = curses.color_pair(C_TITLE) | curses.A_BOLD
    aacc = curses.color_pair(C_ACCENT) | curses.A_BOLD
    abtn = curses.color_pair(C_BTN)
    ahk = curses.color_pair(C_HOTKEY) | curses.A_BOLD

    for i in range(1, h - 1):
        _put(win, y + i, x, BV, ab)
        _put(win, y + i, x + w - 1, BV, ab)
    _put(win, y + h - 1, x, BL, ab)
    _put(win, y + h - 1, x + 1, BH * (w - 2), ab)
    _put(win, y + h - 1, x + w - 1, BR, ab)
    _put(win, y, x, TL, ab)
    _put(win, y, x + w - 1, TR, ab)

    inner = w - 2
    left = (f"─*{title}" if active else f"─{title}") if title else ""

    rbtn_w = 0
    if rbtns:
        for hk, lbl in rbtns:
            rbtn_w += 2 + 1 + len(lbl) + 1
        rbtn_w += 1

    fill = max(0, inner - len(left) - rbtn_w)

    px = x + 1
    if left:
        _put(win, y, px, left, at if active else ab)
        if active:
            _put(win, y, px + 1, "*", aacc)
        px += len(left)

    _put(win, y, px, BH * fill, ab)
    px += fill

    if rbtns:
        for hk, lbl in rbtns:
            _put(win, y, px, "──", ab)
            px += 2
            _put(win, y, px, " ", abtn)
            px += 1
            idx = lbl.find(hk) if hk else -1
            if idx >= 0:
                _put(win, y, px, lbl[:idx], abtn)
                px += idx
                _put(win, y, px, hk, ahk)
                px += 1
                _put(win, y, px, lbl[idx + 1 :] + " ", abtn)
                px += len(lbl) - idx
            else:
                _put(win, y, px, lbl + " ", abtn)
                px += len(lbl) + 1
        _put(win, y, px, "─", ab)


def draw_hline(win, y, x, w, label=""):
    ab = curses.color_pair(C_BORDER)
    ad = curses.color_pair(C_DIM)
    _put(win, y, x, LT, ab)
    if label:
        lbl = f"─{label}─"
        _put(win, y, x + 1, lbl, ad)
        rest = w - 2 - len(lbl)
        if rest > 0:
            _put(win, y, x + 1 + len(lbl), BH * rest, ab)
    else:
        _put(win, y, x + 1, BH * (w - 2), ab)
    _put(win, y, x + w - 1, RT, ab)


def draw_bar(win, y, x, width, pct, col=C_OK):
    pct = max(0.0, min(1.0, pct))
    filled = int(pct * width)
    empty = width - filled
    _put(win, y, x, BF * filled, curses.color_pair(col))
    _put(win, y, x + filled, BE * empty, curses.color_pair(C_DIM) | curses.A_DIM)


# ── prompt / confirm dialogs ──────────────────────────────────────────────────
def dlg_prompt(win, y, x, label, maxlen=60, default="", secret=False) -> Optional[str]:
    curses.curs_set(1)
    win.keypad(True)
    win.timeout(-1)
    _, W = win.getmaxyx()
    _put(win, y, x, label, curses.color_pair(C_TITLE) | curses.A_BOLD)
    px = x + len(label)
    buf = list(default)
    while True:
        avail = max(0, W - px - 1)
        _put(win, y, px, " " * min(maxlen + 1, avail), 0)
        disp = ("*" * len(buf)) if secret else "".join(buf)
        _put(win, y, px, disp[:avail], curses.color_pair(C_OK))
        win.refresh()
        try:
            ch = win.getch()
        except Exception:
            break
        if ch in (10, 13):
            curses.curs_set(0)
            return "".join(buf).strip()
        elif ch == 27:
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= ch < 256 and len(buf) < maxlen:
            buf.append(chr(ch))
    curses.curs_set(0)
    return "".join(buf).strip()


def dlg_confirm(scr, msg: str) -> bool:
    H, W = scr.getmaxyx()
    dw = max(min(len(msg) + 14, W - 4), 44)
    dh = 7
    dy, dx = (H - dh) // 2, (W - dw) // 2
    win = curses.newwin(dh, dw, dy, dx)
    win.keypad(True)
    win.timeout(-1)
    draw_box(win, 0, 0, dh, dw, "confirm", active=True)
    _put(win, 2, 2, msg[: dw - 4], curses.color_pair(C_WARN) | curses.A_BOLD)
    _put(win, 4, 4, " y ", curses.color_pair(C_HOTKEY) | curses.A_BOLD)
    _put(win, 4, 7, " Yes    ", curses.color_pair(C_BTN))
    _put(win, 4, 15, " n ", curses.color_pair(C_HOTKEY) | curses.A_BOLD)
    _put(win, 4, 18, " No", curses.color_pair(C_BTN))
    win.refresh()
    result = False
    while True:
        ch = win.getch()
        if ch in (ord("y"), ord("Y"), 10, 13):
            result = True
            break
        if ch in (ord("n"), ord("N"), 27):
            result = False
            break
    del win
    scr.touchwin()
    scr.refresh()
    return result


# ── APP ───────────────────────────────────────────────────────────────────────
class App:
    FA = 0
    FT = 1
    FE = 2

    def __init__(self, stdscr):
        self.scr = stdscr
        self.focus = self.FA

        self.accounts: list = load_json(ACCOUNTS_FILE, [])
        self.totp_list: list = load_json(TOTP_FILE, [])

        self.ai = 0
        self.ti = 0
        self.ei = 0
        self.sb = 0

        self.search = ""
        self.searching = False
        self._note = ("", 0.0)

        self.clients: dict = {}
        self.client: Optional[MailClient] = None

        self._running = True
        self._help = False
        self._last_refresh = 0.0

        init_colors()
        curses.curs_set(0)
        curses.set_escdelay(50)
        self.scr.keypad(True)
        self.scr.timeout(400)

        q = env_totp()
        if q:
            self._add_totp(q, silent=True)

    # ── helpers ───────────────────────────────────────────────────────────────
    def note(self, msg: str, t=3.0):
        self._note = (msg, time.time() + t)

    def _save_acc(self):
        save_json(ACCOUNTS_FILE, self.accounts)

    def _save_totp(self):
        save_json(TOTP_FILE, self.totp_list)

    def _add_totp(self, e: dict, silent=False):
        for x in self.totp_list:
            if x.get("secret") == e.get("secret"):
                if not silent:
                    self.note(f"TOTP exists: {e['label']}")
                return
        self.totp_list.append(e)
        self._save_totp()
        if not silent:
            self.note(f"Added TOTP: {e['label']}")

    def facc(self):
        q = self.search.lower()
        if not q:
            return list(enumerate(self.accounts))
        return [
            (i, a)
            for i, a in enumerate(self.accounts)
            if q in a.get("email", "").lower() or q in a.get("label", "").lower()
        ]

    def ftotp(self):
        q = self.search.lower()
        if not q:
            return list(enumerate(self.totp_list))
        return [
            (i, t)
            for i, t in enumerate(self.totp_list)
            if q in t.get("label", "").lower() or q in t.get("issuer", "").lower()
        ]

    def do_connect(self, list_idx: int):
        fa = self.facc()
        if list_idx >= len(fa):
            return
        _, acc = fa[list_idx]
        em = acc["email"]
        if em not in self.clients:
            self.clients[em] = MailClient(acc)
        c = self.clients[em]
        self.client = c
        if c.status in ("disconnected", "error"):
            threading.Thread(target=c.connect, daemon=True).start()
            self._last_refresh = time.time()
            self.note(f"Connecting {em}…")

    def do_refresh(self):
        if self.client and self.client.status == "connected":
            self._last_refresh = time.time()
            threading.Thread(target=self.client.fetch_inbox, daemon=True).start()
            self.note("Refreshing…")

    def do_load_body(self, idx: int):
        if not self.client:
            return
        msgs = self.client.messages
        if idx < len(msgs) and msgs[idx].get("body") not in (None, "__loading__"):
            return
        if idx < len(msgs) and msgs[idx].get("body") is None:
            threading.Thread(
                target=self.client.fetch_body, args=(idx,), daemon=True
            ).start()

    # ── dialogs ───────────────────────────────────────────────────────────────
    def dlg_accounts(self):
        """Universal add/import dialog — handles single entry, bulk paste and file."""
        H, W = self.scr.getmaxyx()
        dh = min(H - 2, 28)
        dw = min(W - 2, 72)
        dy = (H - dh) // 2
        dx = (W - dw) // 2

        def _make_win(title):
            w = curses.newwin(dh, dw, dy, dx)
            draw_box(w, 0, 0, dh, dw, title, active=True)
            return w

        # ── main screen ───────────────────────────────────────────────────────
        win = _make_win("Add / Import Accounts")
        hints = [
            ("", "Enter one account, paste many, or load a file."),
            ("", "IMAP host/port auto-detected from email domain."),
            ("", ""),
            ("  email@example.com:password", C_CODE),
            ("  email@example.com:password:host:993", C_CODE),
            ("  /path/to/accounts.json", C_CODE),
            ("  /path/to/list.txt", C_CODE),
            ("", ""),
            ("", "Separator is auto-detected ( : ; | TAB space )."),
            ("", "For JSON files just enter the file path."),
        ]
        row = 1
        for text, attr in hints:
            if row >= dh - 5:
                break
            if text == "":
                if isinstance(attr, str) and attr:
                    _put(win, row, 2, attr[: dw - 4], curses.color_pair(C_DIM))
                row += 1
                continue
            _put(
                win,
                row,
                2,
                text[: dw - 4],
                curses.color_pair(attr)
                if isinstance(attr, int)
                else curses.color_pair(C_DIM),
            )
            row += 1

        _put(
            win,
            dh - 4,
            2,
            "Type/paste lines below. Empty line = done.",
            curses.color_pair(C_DIM),
        )
        win.refresh()

        # ── collect lines ─────────────────────────────────────────────────────
        lines = []
        input_row = dh - 3
        while True:
            # clear input row fully before each prompt
            _put(win, input_row, 2, " " * (dw - 4), 0)
            prompt = "> " if not lines else f"+{len(lines)} > "
            ln = dlg_prompt(win, input_row, 2, prompt, dw - len(prompt) - 4)
            if ln is None or ln == "":
                break
            lines.append(ln)
            # show confirmation one row above input, clipped cleanly
            confirm = f"  \u2713  {ln}"
            _put(
                win,
                input_row - 1,
                2,
                (confirm[: dw - 5]).ljust(dw - 5),
                curses.color_pair(C_OK),
            )
            win.refresh()

        del win
        self.scr.touchwin()
        self.scr.refresh()

        if not lines:
            return

        # ── process collected input ───────────────────────────────────────────
        total_added = 0
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue

            # ── file path? ────────────────────────────────────────────────────
            p = Path(raw).expanduser()
            if p.exists() and p.is_file():
                added = self._import_text(p.read_text())
                total_added += added
                continue

            # ── JSON blob pasted directly? ────────────────────────────────────
            if raw.startswith("[") or raw.startswith("{"):
                total_added += self._import_text(raw)
                continue

            # ── single line: auto-detect separator ───────────────────────────
            sep = self._detect_sep(raw)
            total_added += self._import_text(raw, sep)

        self.note(f"Added {total_added} account(s)")

    def _detect_sep(self, line: str) -> str:
        """Guess separator from a single line. Prefer : then ; | TAB space."""
        # if line has @ it's email — find first non-email char after the domain
        # simplest: try each candidate and see if left part looks like an email
        for sep in (":", ";", "|", "\t", " "):
            parts = line.split(sep)
            if len(parts) >= 2 and "@" in parts[0]:
                return sep
        return ":"

    def dlg_del(self):
        fa = self.facc()
        if not fa or self.ai >= len(fa):
            return
        orig_i, acc = fa[self.ai]
        em = acc.get("email", "?")
        if dlg_confirm(self.scr, f"Delete '{em}'?"):
            if em in self.clients:
                try:
                    self.clients[em].disconnect()
                except Exception:
                    pass
                del self.clients[em]
            if self.client and self.client.acc.get("email") == em:
                self.client = None
            self.accounts.pop(orig_i)
            self._save_acc()
            self.ai = max(0, self.ai - 1)
            self.note(f"Deleted {em}")

    def _import_text(self, text: str, sep: str = ":") -> int:
        """Parse text (JSON or delimited lines) and add accounts. Returns count added."""
        added = 0
        try:
            data = json.loads(text)
            for item in data if isinstance(data, list) else []:
                if isinstance(item, dict) and "email" in item:
                    if not any(a["email"] == item["email"] for a in self.accounts):
                        if "imap_host" not in item:
                            hg, pg = guess_imap(item["email"])
                            item.setdefault("imap_host", hg)
                            item.setdefault("imap_port", pg)
                        item.setdefault("label", item["email"].split("@")[0])
                        self.accounts.append(item)
                        added += 1
            self._save_acc()
            return added
        except (json.JSONDecodeError, ValueError):
            pass

        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            # auto-detect separator per line if not forced
            s = sep if sep != ":" or ":" in ln else self._detect_sep(ln)
            parts = ln.split(s)
            if len(parts) < 2:
                continue
            em2 = parts[0].strip()
            pw2 = s.join(parts[1:]).strip()
            if not em2 or "@" not in em2 or not pw2:
                continue
            hg, pg = guess_imap(em2)
            a = {
                "email": em2,
                "password": pw2,
                "imap_host": hg,
                "imap_port": pg,
                "label": em2.split("@")[0],
            }
            if not any(x["email"] == em2 for x in self.accounts):
                self.accounts.append(a)
                added += 1
        self._save_acc()
        return added

        H, W = self.scr.getmaxyx()
        dh, dw = 14, min(W - 4, 68)
        win = curses.newwin(dh, dw, (H - dh) // 2, (W - dw) // 2)
        draw_box(win, 0, 0, dh, dw, "Import TOTP", active=True)
        eq = env_totp()
        for i, ln in enumerate(
            [
                "  1. Paste  otpauth:// URI",
                "  2. Manual  secret + label",
                f"  3. Env     {'found: ' + eq['label'] if eq else '$TOTP_QR not set'}",
            ]
        ):
            _put(win, 2 + i, 1, ln, curses.color_pair(C_DIM))

        choice = dlg_prompt(win, dh - 3, 2, "Choice [1/2/3  ESC=cancel]: ", 3)
        if choice is None:
            del win
            self.scr.touchwin()
            self.scr.refresh()
            return

        win.clear()
        if choice == "1":
            draw_box(win, 0, 0, dh, dw, "Paste otpauth URI", active=True)
            win.refresh()
            uri = dlg_prompt(win, dh - 3, 2, "URI: ", dw - 8)
            if uri is not None:
                e = parse_otpauth(uri)
                if e:
                    self._add_totp(e)
                else:
                    self.note("Invalid URI")

        elif choice == "2":
            draw_box(win, 0, 0, dh, dw, "Manual TOTP", active=True)
            win.refresh()
            sec = dlg_prompt(win, 5, 2, "Secret (base32): ", 40)
            if sec is None:
                del win
                self.scr.touchwin()
                self.scr.refresh()
                return
            lbl = dlg_prompt(win, 7, 2, "Label/Issuer:    ", 30)
            if lbl is None:
                del win
                self.scr.touchwin()
                self.scr.refresh()
                return

            # pre-fill account email from currently selected/connected account
            prefill_email = ""
            if self.client:
                prefill_email = self.client.acc.get("email", "")
            elif self.accounts and self.ai < len(self.accounts):
                prefill_email = self.accounts[self.ai].get("email", "")

            if prefill_email:
                # show it, skip the prompt
                _put(
                    win,
                    9,
                    2,
                    f"Account (email):  {prefill_email}",
                    curses.color_pair(C_DIM),
                )
                win.refresh()
                acct = prefill_email
            else:
                acct = dlg_prompt(win, 9, 2, "Account (email): ", 40)
                if acct is None:
                    del win
                    self.scr.touchwin()
                    self.scr.refresh()
                    return

            if sec:
                self._add_totp(
                    {
                        "label": lbl or "Unknown",
                        "secret": sec.upper(),
                        "issuer": lbl,
                        "account": acct or "",
                    }
                )

        elif choice == "3":
            if eq:
                self._add_totp(eq)
            else:
                self.note("TOTP_QR not in env")

        del win
        self.scr.touchwin()
        self.scr.refresh()

    def dlg_market(self):
        """HiddenCode market — Telegram bot."""
        URL = "https://t.me/hcmarket_bot"
        DESC = [
            ("HC Market — by HiddenCode", C_TITLE),
            ("", None),
            ("Tools, bots and utilities crafted by the", C_DIM),
            ("HiddenCode team. Privacy-first software", C_DIM),
            ("for people who value their data.", C_DIM),
            ("", None),
            ("Find Qlerky and more on Telegram:", C_DIM),
            (URL, C_CODE),
        ]

        def _make_qr(data: str):
            try:
                import qrcode as _q

                qr = _q.QRCode(border=1)
                qr.add_data(data)
                qr.make(fit=True)
                return qr.get_matrix()
            except ImportError:
                pass
            try:
                import io

                import segno as _s

                buf = io.StringIO()
                _s.make(data, error="m").save(buf, kind="txt", border=1)
                lines = buf.getvalue().splitlines()
                return [[c == "1" for c in l] for l in lines if l]
            except ImportError:
                pass
            return None

        matrix = _make_qr(URL)

        H, W = self.scr.getmaxyx()
        qr_rows = ((len(matrix) + 1) // 2) if matrix else 0
        qr_cols = len(matrix[0]) if matrix else 0
        text_w = max(len(t) for t, _ in DESC) + 6
        dw = min(W - 2, max(text_w, qr_cols + 4))
        dh = min(H - 2, len(DESC) + qr_rows + 4)
        dy = max(0, (H - dh) // 2)
        dx = max(0, (W - dw) // 2)

        win = curses.newwin(dh, dw, dy, dx)
        win.keypad(True)
        win.timeout(-1)
        draw_box(win, 0, 0, dh, dw, "HC Market", active=True)

        row = 1
        for text, col in DESC:
            if row >= dh - 2:
                break
            if not text:
                row += 1
                continue
            attr = (
                (
                    curses.color_pair(col) | curses.A_BOLD
                    if col == C_TITLE
                    else curses.color_pair(col)
                )
                if col
                else 0
            )
            _put(win, row, 2, text[: dw - 4], attr)
            row += 1

        if matrix:
            qx = max(1, (dw - qr_cols) // 2)
            for pair in range((len(matrix) + 1) // 2):
                ry = row + pair
                if ry >= dh - 2:
                    break
                top = matrix[pair * 2]
                bot = (
                    matrix[pair * 2 + 1]
                    if pair * 2 + 1 < len(matrix)
                    else [False] * len(top)
                )
                s = ""
                for t, b in zip(top, bot):
                    s += "█" if t and b else ("▀" if t else ("▄" if b else " "))
                _put(win, ry, qx, s[: dw - 2], curses.color_pair(C_HDR))
        else:
            _put(
                win, row, 2, "Install qrcode for QR display.", curses.color_pair(C_WARN)
            )

        _put(win, dh - 2, 2, "[ any key to close ]", curses.color_pair(C_DIM))
        win.refresh()
        win.getch()
        del win
        self.scr.touchwin()
        self.scr.refresh()

    def dlg_qlerky(self):
        """Show Qlerky app promo dialog with QR code."""
        URL = "https://play.google.com/store/apps/details?id=com.hiddenflame.qlerkypassword"
        DESC = [
            "Qlerky — Offline Password Manager",
            "Simple & secure 2FA + password manager for Android.",
            "Encrypted locally, works 100% offline, no servers.",
            "",
            "Scan to open Google Play:",
        ]

        def _make_qr(data: str):
            """Generate QR matrix using qrcode lib if available, else None."""
            try:
                import qrcode as _q

                qr = _q.QRCode(border=1)
                qr.add_data(data)
                qr.make(fit=True)
                return qr.get_matrix()
            except ImportError:
                pass
            # Fallback: try segno
            try:
                import io

                import segno as _s

                buf = io.StringIO()
                _s.make(data, error="m").save(buf, kind="txt", border=1)
                lines = buf.getvalue().splitlines()
                return [[c == "1" for c in l] for l in lines if l]
            except ImportError:
                pass
            return None

        matrix = _make_qr(URL)

        H, W = self.scr.getmaxyx()
        qr_rows = ((len(matrix) + 1) // 2) if matrix else 0
        qr_cols = len(matrix[0]) if matrix else 0

        text_w = max(len(l) for l in DESC) + 6
        dw = min(W - 2, max(text_w, qr_cols + 4))
        dh = min(H - 2, len(DESC) + qr_rows + 5)
        dy = max(0, (H - dh) // 2)
        dx = max(0, (W - dw) // 2)

        win = curses.newwin(dh, dw, dy, dx)
        win.keypad(True)
        win.timeout(-1)
        draw_box(win, 0, 0, dh, dw, "Qlerky Password Manager", active=True)

        row = 1
        for line in DESC:
            if row >= dh - 1:
                break
            if not line:
                row += 1
                continue
            attr = (
                curses.color_pair(C_TITLE) | curses.A_BOLD
                if row == 1
                else curses.color_pair(C_DIM)
            )
            _put(win, row, 2, line[: dw - 4], attr)
            row += 1

        if matrix:
            # half-block rendering: two QR rows → one terminal row
            qx = max(1, (dw - qr_cols) // 2)
            for pair in range((len(matrix) + 1) // 2):
                ry = row + pair
                if ry >= dh - 2:
                    break
                top = matrix[pair * 2]
                bot = (
                    matrix[pair * 2 + 1]
                    if pair * 2 + 1 < len(matrix)
                    else [False] * len(top)
                )
                s = ""
                for t, b in zip(top, bot):
                    s += "█" if t and b else ("▀" if t else ("▄" if b else " "))
                _put(win, ry, qx, s[: dw - 2], curses.color_pair(C_HDR))
        else:
            # no qrcode lib — show URL in a box so user can copy it
            _put(
                win,
                row,
                2,
                "Install qrcode lib for QR display.",
                curses.color_pair(C_WARN),
            )
            _put(win, row + 1, 2, "URL:", curses.color_pair(C_DIM))
            # wrap URL across lines
            url_parts = [URL[i : i + dw - 6] for i in range(0, len(URL), dw - 6)]
            for j, part in enumerate(url_parts[:3]):
                if row + 2 + j < dh - 2:
                    _put(win, row + 2 + j, 2, part, curses.color_pair(C_CODE))

        _put(win, dh - 2, 2, "[ any key to close ]", curses.color_pair(C_DIM))
        win.refresh()
        win.getch()
        del win
        self.scr.touchwin()
        self.scr.refresh()

    # ── render ────────────────────────────────────────────────────────────────
    def render(self):
        H, W = self.scr.getmaxyx()
        self.scr.erase()

        if H < 18 or W < 60:
            _put(
                self.scr,
                0,
                0,
                f"Too small ({W}×{H}), need ≥60×18",
                curses.color_pair(C_ERR),
            )
            self.scr.refresh()
            return

        left_w = max(22, W * 26 // 100)
        right_w = W - left_w

        has_totp = len(self.totp_list) > 0
        # top border + column header + N entries + bottom border = N+3, min 5
        totp_h = min(max(5, H * 30 // 100), len(self.totp_list) + 4) if has_totp else 3
        bot_h = H - totp_h

        has_msgs = bool(self.client and self.client.messages)
        emails_w = right_w * 55 // 100
        content_w = right_w - emails_w

        self._draw_acc(0, 0, H, left_w)
        self._draw_totp(0, left_w, totp_h, right_w)

        if has_msgs:
            self._draw_emails(totp_h, left_w, bot_h, emails_w)
            self._draw_content(totp_h, left_w + emails_w, bot_h, content_w)
            _put(self.scr, totp_h, left_w + emails_w, LT, curses.color_pair(C_BORDER))
        else:
            self._draw_emails(totp_h, left_w, bot_h, right_w)

        if totp_h > 0 and bot_h > 0:
            _put(self.scr, totp_h, left_w, LT, curses.color_pair(C_BORDER))
            if has_msgs:
                _put(
                    self.scr, totp_h, left_w + emails_w, LT, curses.color_pair(C_BORDER)
                )

        msg, exp = self._note
        if msg and time.time() < exp:
            note = f" {msg} "
            nx = max(left_w, W - len(note) - 1)
            _put(
                self.scr,
                H - 1,
                nx,
                note[: W - nx],
                curses.color_pair(C_WARN) | curses.A_BOLD,
            )

        self.scr.refresh()

        if self._help:
            self._draw_help(H, W)

    # ── account list ─────────────────────────────────────────────────────────
    def _draw_acc(self, y, x, h, w):
        act = self.focus == self.FA
        draw_box(
            self.scr,
            y,
            x,
            h,
            w,
            "account list",
            act,
            rbtns=[("a", "add"), ("d", "del")] if act else None,
        )

        fa = self.facc()
        iw = w - 2
        vis = h - 3
        off = max(0, self.ai - vis + 2)

        for row, (oi, acc) in enumerate(fa[off : off + vis]):
            ry = y + 1 + row
            if ry >= y + h - 2:
                break
            em = acc.get("email", "?")
            c = self.clients.get(em)
            sym, sc = " ", C_DIM
            if c:
                if c.status == "connected":
                    sym, sc = "●", C_OK
                elif c.status == "connecting...":
                    sym, sc = "◌", C_WARN
                elif c.status == "error":
                    sym, sc = "✗", C_ERR
            sel = oi == self.ai
            ra = (
                curses.color_pair(C_SEL) | curses.A_BOLD
                if sel
                else curses.color_pair(C_DIM)
            )
            _put(self.scr, ry, x + 1, " " * iw, ra)
            _put(self.scr, ry, x + 1, sym, curses.color_pair(sc) if not sel else ra)
            _put(self.scr, ry, x + 3, em[: iw - 4], ra)

        if self.searching or self.search:
            _put(
                self.scr,
                y + h - 2,
                x + 1,
                f"/{self.search}▌"[:iw],
                curses.color_pair(C_WARN) | curses.A_BOLD,
            )

        cnt = f"┤{len(fa)}/{len(self.accounts)}├"
        _put(self.scr, y + h - 1, x + 2, cnt, curses.color_pair(C_DIM))
        if act:
            hints = "┤Enter:connect  /:search├"
            hx = x + w - len(hints) - 1
            if hx > x + len(cnt) + 4:
                _put(self.scr, y + h - 1, hx, hints, curses.color_pair(C_DIM))

    # ── TOTP panel ───────────────────────────────────────────────────────────
    def _draw_totp(self, y, x, h, w):
        act = self.focus == self.FT
        sec = totp_left()
        col = C_OK if sec > 15 else (C_WARN if sec > 7 else C_ERR)

        draw_box(
            self.scr,
            y,
            x,
            h,
            w,
            "totp",
            act,
            rbtns=[("t", "import"), ("p", "get app"), ("m", "market")]
            if act
            else [("p", "get app"), ("m", "market")],
        )
        # Draw timer right after the title word "totp"
        # draw_box writes: ╭─totp (active: ╭─*totp), so totp ends at x+1+1+4=x+6 (or x+7 active)
        timer_x = x + (8 if act else 7)
        _put(
            self.scr, y, timer_x, f"{sec:2d}s─", curses.color_pair(col) | curses.A_BOLD
        )

        if not self.totp_list:
            _put(
                self.scr,
                y + 1,
                x + 2,
                "No TOTP entries — press t to import",
                curses.color_pair(C_DIM),
            )
            return

        cl = x + 2
        cw2 = x + 20
        cv = x + 29
        cb = x + 37
        cnw = cb + 2
        cnv = cnw + 5

        ha = curses.color_pair(C_HDR) | curses.A_BOLD
        hk = curses.color_pair(C_HOTKEY) | curses.A_BOLD
        hd = curses.color_pair(C_DIM)
        _put(self.scr, y + 1, cl, "Service", ha)
        _put(self.scr, y + 1, cw2, "current", ha)
        _put(self.scr, y + 1, cnw, "next", ha)
        # copy hints on the right of the header row
        hint_y = y + 1
        hint_x = x + w - 18
        if hint_x > cnv + 6:
            _put(self.scr, hint_y, hint_x, "y", hk)
            _put(self.scr, hint_y, hint_x + 1, "=copy cur  ", hd)
            _put(self.scr, hint_y, hint_x + 11, "Y", hk)
            _put(self.scr, hint_y, hint_x + 12, "=next", hd)

        ft = self.ftotp()
        vis = h - 3
        off = max(0, self.ti - vis + 2)
        for row, (oi, entry) in enumerate(ft[off : off + vis]):
            ry = y + 2 + row
            if ry >= y + h - 1:
                break
            sel = oi == self.ti
            ba = curses.color_pair(C_SEL) | curses.A_BOLD if sel else 0
            lbl = (entry.get("label") or entry.get("issuer") or "?")[:16]
            cur = totp(entry["secret"], 0)
            nxt = totp(entry["secret"], 1)

            code_col = curses.color_pair(col) | curses.A_BOLD

            if sel:
                _put(self.scr, ry, x + 1, " " * (w - 2), ba)
            _put(self.scr, ry, cl, lbl, ba)
            _put(
                self.scr,
                ry,
                cw2,
                "current",
                curses.color_pair(C_DIM) if not sel else ba,
            )
            _put(self.scr, ry, cv, cur, code_col if not sel else ba)
            if cnw < x + w - 10:
                _put(
                    self.scr,
                    ry,
                    cnw,
                    "next",
                    curses.color_pair(C_DIM) if not sel else ba,
                )
            if cnv < x + w - 6:
                _put(
                    self.scr, ry, cnv, nxt, curses.color_pair(C_DIM) if not sel else ba
                )

        # hint on bottom border
        hint = "┤y:copy current  Y:copy next├"
        bx = x + w - len(hint) - 1
        if bx > x + 4:
            _put(self.scr, y + h - 1, bx, hint, curses.color_pair(C_DIM))

    # ── email list ────────────────────────────────────────────────────────────
    def _draw_emails(self, y, x, h, w):
        act = self.focus == self.FE
        title = "Last emails"
        if self.client:
            em = self.client.acc.get("email", "")
            title = f"inbox: {em[: w - 22]}"

        elapsed = time.time() - self._last_refresh
        secs_nr = max(0, int(REFRESH_INTERVAL - elapsed))
        draw_box(
            self.scr,
            y,
            x,
            h,
            w,
            title,
            act,
            rbtns=[("r", f"refresh ({secs_nr}s)")] if act else None,
        )

        if not self.client:
            _put(
                self.scr,
                y + 2,
                x + 3,
                "Select account  →  Enter to connect",
                curses.color_pair(C_DIM),
            )
            return

        c = self.client
        if c.status != "connected":
            attr = curses.color_pair(C_ERR if c.status == "error" else C_WARN)
            _put(self.scr, y + 2, x + 3, (c.error or c.status)[: w - 6], attr)
            return

        msgs = c.messages

        # FIX: show "Loading inbox…" while first fetch is in progress
        if not msgs:
            if c._fetching:
                _put(
                    self.scr, y + 2, x + 3, "Loading inbox…", curses.color_pair(C_WARN)
                )
            else:
                _put(self.scr, y + 2, x + 3, "Inbox empty.", curses.color_pair(C_DIM))
            return

        iw = w - 2
        vis = h - 2
        off = max(0, self.ei - vis + 2)
        for row, msg in enumerate(msgs[off : off + vis]):
            ry = y + 1 + row
            if ry >= y + h - 1:
                break
            idx = row + off
            sel = idx == self.ei
            ba = curses.color_pair(C_SEL) | curses.A_BOLD if sel else 0

            codes = msg.get("codes", [])
            code_tag = f" {codes[0]}" if codes else ""
            subj = msg.get("subject", "(no subject)")
            frm = msg.get("from", "")
            m2 = re.match(r'^"?([^"<@\n]{1,25})"?\s*<?', frm)
            disp = m2.group(1).strip() if m2 else frm[:20]
            line = f"{disp}: {subj}"

            if sel:
                _put(self.scr, ry, x + 1, " " * iw, ba)
            _put(self.scr, ry, x + 2, line[: iw - len(code_tag) - 2], ba)
            if code_tag:
                _put(
                    self.scr,
                    ry,
                    x + iw - len(code_tag) - 1,
                    code_tag,
                    curses.color_pair(C_CODE) | curses.A_BOLD if not sel else ba,
                )

    # ── extracted codes + body ────────────────────────────────────────────────
    def _draw_content(self, y, x, h, w):
        draw_box(self.scr, y, x, h, w, "extracted codes")
        if not self.client or not self.client.messages:
            return
        msgs = self.client.messages
        if self.ei >= len(msgs):
            return

        msg = msgs[self.ei]
        codes = msg.get("codes", [])
        body = msg.get("body")
        iw = w - 2

        if body is None:
            self.do_load_body(self.ei)

        loading = body in (None, "__loading__")

        cr = max(1, min(len(codes), max(2, h // 4)))
        if codes:
            for i, code in enumerate(codes[:cr]):
                ry = y + 1 + i
                if ry >= y + h - 3:
                    break
                _put(
                    self.scr, ry, x + 2, code, curses.color_pair(C_CODE) | curses.A_BOLD
                )
        else:
            _put(
                self.scr,
                y + 1,
                x + 2,
                "(loading…)" if loading else "(no codes)",
                curses.color_pair(C_DIM),
            )

        dvy = y + cr + 2
        if dvy < y + h - 2:
            draw_hline(self.scr, dvy, x, w, "content")

        by = dvy + 1
        if by >= y + h - 1:
            return

        if loading:
            _put(self.scr, by, x + 2, "loading…", curses.color_pair(C_DIM))
        elif body == "":
            _put(self.scr, by, x + 2, "(empty)", curses.color_pair(C_DIM))
        else:
            lines = []
            for para in (body or "").splitlines():
                lines.extend(textwrap.wrap(para, max(1, iw - 2)) or [""])
            visb = h - (by - y) - 1
            for i, ln in enumerate(lines[self.sb : self.sb + visb]):
                ry = by + i
                if ry >= y + h - 1:
                    break
                _put(self.scr, ry, x + 2, ln[: iw - 2], curses.color_pair(C_DIM))

    # ── help overlay ─────────────────────────────────────────────────────────
    def _draw_help(self, H, W):
        dh, dw = 28, 56
        dy, dx = (H - dh) // 2, (W - dw) // 2
        if dy < 0 or dx < 0:
            return
        # create once, reuse on subsequent frames
        if not hasattr(self, "_help_win") or self._help_win is None:
            self._help_win = curses.newwin(dh, dw, dy, dx)
            win = self._help_win
            draw_box(win, 0, 0, dh, dw, "help", active=True)
            rows = [
                ("Navigation", None),
                ("  h/l  or  1/2/3", "Switch panel"),
                ("  j/k  ↑↓", "Move up / down"),
                ("  Tab", "Cycle focus"),
                ("  Enter", "Connect account"),
                ("", None),
                ("Accounts", None),
                ("  a / i", "Add / import accounts"),
                ("  d", "Delete selected"),
                ("", None),
                ("TOTP", None),
                ("  y", "Copy current code"),
                ("  Y", "Copy next code"),
                ("  t", "Import TOTP secret"),
                ("", None),
                ("Email", None),
                ("  r / F5", "Refresh inbox"),
                ("  PgUp/PgDn", "Scroll body"),
                ("", None),
                ("  /", "Search / filter"),
                ("  ESC", "Clear search"),
                ("  ?", "Toggle help"),
                ("  q / Ctrl+C", "Quit"),
            ]
            for row, (k, v) in enumerate(rows[: dh - 2]):
                ry = 1 + row
                if v is None:
                    _put(win, ry, 2, k, curses.color_pair(C_TITLE) | curses.A_BOLD)
                else:
                    _put(win, ry, 2, k, curses.color_pair(C_KEY))
                    _put(win, ry, 2 + len(k), v, curses.color_pair(C_DIM))
        self._help_win.refresh()

    def _close_help(self):
        if hasattr(self, "_help_win") and self._help_win is not None:
            del self._help_win
            self._help_win = None
            self.scr.touchwin()
            self.scr.refresh()

    # ── input ─────────────────────────────────────────────────────────────────
    # Cyrillic layout (ЙЦУКЕН) → Latin equivalents for all hotkeys
    _CYR = {
        ord("й"): ord("q"),
        ord("Й"): ord("Q"),
        ord("ц"): ord("w"),
        ord("Ц"): ord("W"),
        ord("у"): ord("e"),
        ord("У"): ord("E"),
        ord("к"): ord("r"),
        ord("К"): ord("R"),
        ord("е"): ord("t"),
        ord("Е"): ord("T"),
        ord("н"): ord("y"),
        ord("Н"): ord("Y"),
        ord("г"): ord("u"),
        ord("Г"): ord("U"),
        ord("ш"): ord("i"),
        ord("Ш"): ord("I"),
        ord("щ"): ord("o"),
        ord("Щ"): ord("O"),
        ord("з"): ord("p"),
        ord("З"): ord("P"),
        ord("ф"): ord("a"),
        ord("Ф"): ord("A"),
        ord("ы"): ord("s"),
        ord("Ы"): ord("S"),
        ord("в"): ord("d"),
        ord("В"): ord("D"),
        ord("а"): ord("f"),
        ord("А"): ord("F"),
        ord("п"): ord("g"),
        ord("П"): ord("G"),
        ord("р"): ord("h"),
        ord("Р"): ord("H"),
        ord("о"): ord("j"),
        ord("О"): ord("J"),
        ord("л"): ord("k"),
        ord("Л"): ord("K"),
        ord("д"): ord("l"),
        ord("Д"): ord("L"),
        ord("я"): ord("z"),
        ord("Я"): ord("Z"),
        ord("ч"): ord("x"),
        ord("Ч"): ord("X"),
        ord("с"): ord("c"),
        ord("С"): ord("C"),
        ord("м"): ord("v"),
        ord("М"): ord("V"),
        ord("и"): ord("b"),
        ord("И"): ord("B"),
        ord("т"): ord("n"),
        ord("Т"): ord("N"),
        ord("ь"): ord("m"),
        ord("Ь"): ord("M"),
    }

    def handle(self, ch):
        # Transparently remap Cyrillic to Latin so hotkeys work in any layout
        ch = self._CYR.get(ch, ch)
        if ch == ord("?"):
            now = time.time()
            last = getattr(self, "_help_toggled_at", 0)
            if now - last < 0.3:  # debounce: ignore rapid re-trigger
                return
            self._help_toggled_at = now
            self._help = not self._help
            if not self._help:
                self._close_help()
            return
        if self._help:
            if ch in (27, 10, 13):  # ESC or Enter also closes
                self._help = False
                self._close_help()
            return  # all other keys ignored while help is open

        if self.searching:
            if ch in (10, 13, 27):
                self.searching = False
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                self.search = self.search[:-1]
            elif 32 <= ch < 256:
                self.search += chr(ch)
            return

        if ch == 27:
            if self.search:
                self.search = ""
            return

        if ch in (ord("/"), 11):
            self.searching = True
            self.search = ""
            return

        if ch == 9:
            self.focus = (self.focus + 1) % 3
            return
        if ch in (ord("h"), curses.KEY_LEFT):
            self.focus = max(0, self.focus - 1)
            return
        if ch in (ord("l"), curses.KEY_RIGHT):
            self.focus = min(2, self.focus + 1)
            return
        if ch == ord("1"):
            self.focus = self.FA
            return
        if ch == ord("2"):
            self.focus = self.FT
            return
        if ch == ord("3"):
            self.focus = self.FE
            return

        if ch == ord("q"):
            self._running = False
            return
        if ch == ord("a"):
            self.dlg_accounts()
            return
        if ch == ord("i"):
            self.dlg_accounts()
            return
        if ch == ord("t"):
            self.dlg_totp()
            return
        if ch == ord("p"):
            self.dlg_qlerky()
            return
        if ch == ord("m"):
            self.dlg_market()
            return
        if ch in (ord("r"), curses.KEY_F5):
            self.do_refresh()
            return
        if ch == ord("d") and self.focus == self.FA:
            self.dlg_del()
            return

        if ch == ord("y"):
            ft = self.ftotp()
            if ft and self.ti < len(ft):
                _, e = ft[self.ti]
                c2 = totp(e["secret"], 0)
                self.note(f"Copied {c2}" + (" → clipboard" if clipboard(c2) else ""))
            return
        if ch == ord("Y"):
            ft = self.ftotp()
            if ft and self.ti < len(ft):
                _, e = ft[self.ti]
                c2 = totp(e["secret"], 1)
                self.note(
                    f"Copied NEXT {c2}" + (" → clipboard" if clipboard(c2) else "")
                )
            return

        up = ch in (ord("k"), curses.KEY_UP)
        down = ch in (ord("j"), curses.KEY_DOWN)
        enter = ch in (10, 13, curses.KEY_ENTER)

        if self.focus == self.FA:
            fa = self.facc()
            if up and self.ai > 0:
                self.ai -= 1
            elif down and self.ai < len(fa) - 1:
                self.ai += 1
            elif enter:
                self.do_connect(self.ai)
                self.focus = self.FE

        elif self.focus == self.FT:
            ft = self.ftotp()
            if up and self.ti > 0:
                self.ti -= 1
            elif down and self.ti < len(ft) - 1:
                self.ti += 1

        elif self.focus == self.FE:
            if self.client:
                msgs = self.client.messages
                if up:
                    self.ei = max(0, self.ei - 1)
                    self.sb = 0
                elif down:
                    self.ei = min(len(msgs) - 1, self.ei + 1)
                    self.sb = 0
                elif enter:
                    self.do_load_body(self.ei)
                elif ch == curses.KEY_PPAGE:
                    self.sb = max(0, self.sb - 5)
                elif ch == curses.KEY_NPAGE:
                    self.sb += 5

    # ── main loop ─────────────────────────────────────────────────────────────
    def run(self):
        while self._running:
            try:
                now = time.time()
                if (
                    self.client
                    and self.client.status == "connected"
                    and now - self._last_refresh >= REFRESH_INTERVAL
                ):
                    self._last_refresh = now
                    threading.Thread(
                        target=self.client.fetch_inbox, daemon=True
                    ).start()

                self.render()
                ch = self.scr.getch()
                if ch == 3:
                    break
                if ch == -1:
                    continue
                # flush any extra queued events (e.g. key repeat) before handling
                if ch == ord("?") and not self._help:
                    # drain remaining chars so we don't immediately re-close
                    self.scr.nodelay(True)
                    while self.scr.getch() != -1:
                        pass
                    self.scr.nodelay(False)
                self.handle(ch)
            except KeyboardInterrupt:
                break
            except curses.error:
                pass

        for c in self.clients.values():
            try:
                c.disconnect()
            except Exception:
                pass


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    print("\033[2J\033[H", end="", flush=True)
    try:
        curses.wrapper(lambda scr: App(scr).run())
    except Exception as e:
        print(f"Fatal: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
