# ============================================================
#  SOC Platform - macOS Student Activity Monitor
#  Mirrors the StudentActivityMonitor interface from student_monitor.py
#  but uses macOS-native APIs and paths.
#
#  DO NOT import student_monitor here — this is the macOS replacement.
#  Windows code:  windows_monitors.py / windows_eventlog.py (untouched)
#  Linux code:    student_monitor.py                         (untouched)
#  macOS code:    this file (mac_monitor.py)
# ============================================================

from __future__ import annotations

import os
import sys
import re
import glob
import json
import time
import sqlite3
import socket
import shutil
import subprocess
import tempfile

try:
    import psutil
except ImportError:
    print("[MacMonitor] Install psutil: pip install psutil")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
#  SHARED CATEGORY DEFINITIONS  (same as student_monitor.py)
# ══════════════════════════════════════════════════════════════

BLOCKED_CATEGORIES = {
    "GAMING_ONLINE": [
        "miniclip.com", "poki.com", "coolmathgames.com", "friv.com",
        "y8.com", "kongregate.com", "addictinggames.com", "newgrounds.com",
        "crazygames.com", "kizi.com", "unblocked-games.com",
        "chess.com", "lichess.org", "battleship-game.org",
        "steamcommunity.com", "store.steampowered.com",
    ],
    "GAMING_APP": [
        "steam", "epicgames", "origin", "battlenet", "uplay",
        "minecraft", "roblox", "fortnite", "valorant", "csgo",
        "leagueoflegends", "dota2", "pubg",
    ],
    "SOCIAL_MEDIA": [
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "snapchat.com", "tiktok.com", "pinterest.com", "reddit.com",
        "tumblr.com", "discord.com", "discord.gg",
        "whatsapp.com", "web.whatsapp.com", "telegram.org",
    ],
    "VIDEO_STREAMING": [
        "youtube.com", "youtu.be", "netflix.com", "primevideo.com",
        "hotstar.com", "jiocinema.com", "voot.com",
        "zee5.com", "sonyliv.com", "twitch.tv", "dailymotion.com",
        "vimeo.com",
    ],
    "CHEATING_SITES": [
        "chegg.com", "coursehero.com", "studocu.com", "scribd.com",
        "slader.com", "bartleby.com", "brainly.com",
        "homework.com", "homeworklib.com",
        "pastebin.com", "pastecode.io", "hastebin.com",
    ],
    "ALLOWED_CODING": [
        "stackoverflow.com", "github.com", "docs.python.org",
        "developer.mozilla.org", "w3schools.com", "geeksforgeeks.org",
        "cppreference.com", "linux.die.net", "man7.org",
        "google.com", "duckduckgo.com",
    ],
}

ALL_BLOCKED = {
    domain: category
    for category, domains in BLOCKED_CATEGORIES.items()
    if category != "ALLOWED_CODING"
    for domain in domains
}


# ══════════════════════════════════════════════════════════════
#  1. BROWSER MONITOR  (macOS paths)
#     Chrome/Brave/Edge → ~/Library/Application Support/…
#     Firefox           → ~/Library/Application Support/Firefox/Profiles/
# ══════════════════════════════════════════════════════════════
class MacBrowserMonitor:
    """
    Reads browser history SQLite databases on macOS.
    Uses macOS-specific paths under ~/Library/Application Support.
    Same detection logic as Linux BrowserMonitor.
    """

    def __init__(self):
        self._last_checked: dict = {}
        self._db_paths: list = []
        self._find_browsers()
        self._baseline()

    def _find_browsers(self):
        home = os.path.expanduser("~")
        app_support = f"{home}/Library/Application Support"
        paths = []

        chrome_paths = [
            (f"{app_support}/Google/Chrome/Default/History",        "chrome"),
            (f"{app_support}/Google/Chrome Beta/Default/History",   "chrome"),
            (f"{app_support}/Chromium/Default/History",             "chromium"),
            (f"{app_support}/BraveSoftware/Brave-Browser/Default/History", "brave"),
            (f"{app_support}/Microsoft Edge/Default/History",       "edge"),
            (f"{app_support}/Vivaldi/Default/History",              "vivaldi"),
            (f"{app_support}/Opera Software/Opera Stable/History",  "opera"),
        ]
        # Also scan Profile 1, Profile 2 … for multi-profile browsers
        for pattern, bname in [
            (f"{app_support}/Google/Chrome/Profile */History",        "chrome"),
            (f"{app_support}/BraveSoftware/Brave-Browser/Profile */History", "brave"),
            (f"{app_support}/Microsoft Edge/Profile */History",       "edge"),
        ]:
            for p in glob.glob(pattern):
                chrome_paths.append((p, bname))

        for p, bname in chrome_paths:
            if os.path.exists(p):
                paths.append((bname, p))
                print(f"[MacBrowserMonitor] Found {bname}: {p}")

        # Firefox on macOS
        ff_base = f"{home}/Library/Application Support/Firefox/Profiles"
        if os.path.exists(ff_base):
            for profile in glob.glob(f"{ff_base}/*/places.sqlite"):
                if os.path.exists(profile):
                    paths.append(("firefox", profile))
                    print(f"[MacBrowserMonitor] Found firefox: {profile}")

        # Safari — reads from ~/Library/Safari/History.db (WebKit format)
        safari_db = f"{home}/Library/Safari/History.db"
        if os.path.exists(safari_db):
            paths.append(("safari", safari_db))
            print(f"[MacBrowserMonitor] Found safari: {safari_db}")

        self._db_paths = paths
        if not paths:
            print("[MacBrowserMonitor] No browser history DBs found — "
                  "open a browser at least once to create a profile.")

    def _get_latest_visit_time(self, btype: str, db_path: str) -> int:
        try:
            tmp = os.path.join(
                tempfile.gettempdir(),
                f"soc_mac_browser_{os.path.basename(db_path)}_{abs(hash(db_path))}"
            )
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            if btype == "firefox":
                row = conn.execute("SELECT MAX(visit_date) FROM moz_historyvisits").fetchone()
            elif btype == "safari":
                # Safari History.db: history_visits.visit_time is seconds since 2001-01-01
                row = conn.execute("SELECT MAX(visit_time) FROM history_visits").fetchone()
            else:
                row = conn.execute("SELECT MAX(last_visit_time) FROM urls").fetchone()
            conn.close()
            return row[0] if row and row[0] else 0
        except Exception as e:
            print(f"[MacBrowserMonitor] baseline error: {e}")
            return 0

    def _baseline(self):
        remove = []
        for btype, path in self._db_paths:
            ts = self._get_latest_visit_time(btype, path)
            self._last_checked[path] = ts if ts else 0
            if btype == "safari" and ts == 0:
                # Safari requires Full Disk Access — skip silently after one note
                print("[MacBrowserMonitor] Safari history requires Full Disk Access; skipping.")
                remove.append((btype, path))
            elif ts:
                print(f"[MacBrowserMonitor] Baseline {btype}: tracking from latest entry ✓")
            else:
                print(f"[MacBrowserMonitor] Baseline {btype}: empty, watching for new visits")
        for item in remove:
            self._db_paths.remove(item)

    def _get_new_visits(self, btype: str, db_path: str, since: int) -> list:
        visits = []
        try:
            tmp = os.path.join(
                tempfile.gettempdir(),
                f"soc_mac_browser_{os.path.basename(db_path)}_{abs(hash(db_path))}"
            )
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)

            if btype == "firefox":
                rows = conn.execute("""
                    SELECT p.url, p.title, v.visit_date
                    FROM moz_places p
                    JOIN moz_historyvisits v ON p.id = v.place_id
                    WHERE v.visit_date > ?
                    ORDER BY v.visit_date DESC LIMIT 50
                """, (since,)).fetchall()
            elif btype == "safari":
                # Safari stores visit_time as seconds since 2001-01-01 (CoreData epoch)
                rows = conn.execute("""
                    SELECT i.url, i.title, v.visit_time
                    FROM history_visits v
                    JOIN history_items i ON v.history_item = i.id
                    WHERE v.visit_time > ?
                    ORDER BY v.visit_time DESC LIMIT 50
                """, (since,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT url, title, last_visit_time
                    FROM urls
                    WHERE last_visit_time > ?
                    ORDER BY last_visit_time DESC LIMIT 50
                """, (since,)).fetchall()

            conn.close()
            visits = [(r[0] or '', r[1] or '', r[2] or 0) for r in rows]
        except Exception as e:
            print(f"[MacBrowserMonitor] DB read error ({btype}): {e}")
        return visits

    def _extract_domain(self, url: str) -> str:
        url = url.lower().strip()
        for prefix in ['https://', 'http://', 'www.']:
            if url.startswith(prefix):
                url = url[len(prefix):]
        return url.split('/')[0].split('?')[0]

    def _extract_search_query(self, url: str):
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url.lower())
            params = urllib.parse.parse_qs(parsed.query)
            search_engines = {
                "google.com": "q", "bing.com": "q", "yahoo.com": "p",
                "duckduckgo.com": "q", "yandex.com": "text", "baidu.com": "wd",
                "search.brave.com": "q",
            }
            domain = parsed.netloc.replace("www.", "")
            for engine, param in search_engines.items():
                if engine in domain and param in params:
                    return params[param][0]
        except Exception:
            pass
        return None

    def _check_url(self, url: str, title: str):
        domain = self._extract_domain(url)
        if not domain:
            return None
        for blocked_domain, category in ALL_BLOCKED.items():
            if domain == blocked_domain or domain.endswith('.' + blocked_domain):
                return (category, domain)
        title_lower = title.lower()
        if any(k in title_lower for k in ['game', 'play now', 'gaming']):
            return ('GAMING_TITLE_MATCH', domain)
        return None

    def check(self) -> list:
        events = []
        seen_urls = set()

        for btype, db_path in self._db_paths:
            since    = self._last_checked.get(db_path, 0)
            visits   = self._get_new_visits(btype, db_path, since)
            max_time = since

            for url, title, visit_time in visits:
                if visit_time > max_time:
                    max_time = visit_time

                url_key = url[:100]
                if url_key in seen_urls:
                    continue
                seen_urls.add(url_key)

                query = self._extract_search_query(url)
                if query:
                    events.append(
                        f"BROWSER_SEARCH: Student searched | "
                        f"Query={query} | URL={url[:80]} | Browser={btype}"
                    )

                result = self._check_url(url, title)
                if result:
                    category, domain = result
                    events.append(
                        f"BROWSER_BLOCKED: Student visited restricted site | "
                        f"Category={category} | Domain={domain} | "
                        f"URL={url[:80]} | Title={title[:60]} | Browser={btype}"
                    )

                skip_prefixes = ("chrome://", "chrome-extension://", "about:", "data:", "safari-extension://")
                if not any(url.startswith(p) for p in skip_prefixes) and not query:
                    domain = self._extract_domain(url)
                    if domain:
                        events.append(
                            f"BROWSER_VISIT: Student visited URL | "
                            f"Domain={domain} | URL={url[:100]} | "
                            f"Title={title[:60]} | Browser={btype}"
                        )

            if max_time > since:
                self._last_checked[db_path] = max_time

        return events


# ══════════════════════════════════════════════════════════════
#  2. ACTIVE WINDOW MONITOR  (macOS — uses osascript)
#     xdotool is Linux-only; on macOS we use AppleScript via osascript
# ══════════════════════════════════════════════════════════════
class MacActiveWindowMonitor:
    """
    Monitors the currently active window title on macOS using osascript.
    Replaces xdotool-based ActiveWindowMonitor used on Linux.
    """

    SUSPICIOUS_WINDOW_KEYWORDS = [
        "whatsapp", "telegram", "discord", "signal", "messenger",
        "facebook", "instagram", "twitter", "reddit",
        "steam", "game", "minecraft", "roblox", "clash",
        "netflix", "youtube", "hotstar", "prime video",
        "chegg", "course hero",
    ]

    ALLOWED_WINDOW_KEYWORDS = [
        "terminal", "code", "vim", "nano", "textedit",
        "python", "gcc", "safari", "chrome", "brave", "firefox",
        "finder", "xcode", "soc platform",
    ]

    # AppleScript using ONLY System Events — avoids "Choose Application" dialog.
    # 'tell application frontApp' with a variable triggers macOS app picker popup.
    # Reading window titles via System Events directly does not require
    # controlling individual apps and needs no extra permission prompt.
    _APPLESCRIPT = (
        'tell application "System Events"\n'
        '  set frontProc to first application process whose frontmost is true\n'
        '  set appName to name of frontProc\n'
        '  set winTitle to ""\n'
        '  try\n'
        '    set winTitle to name of first window of frontProc\n'
        '  end try\n'
        '  return appName & " - " & winTitle\n'
        'end tell'
    )

    def __init__(self):
        self._last_window = ""
        self._osascript_ok = self._check_osascript()
        self._permission_warned = False

    def _check_osascript(self) -> bool:
        try:
            result = subprocess.run(
                ["osascript", "-e", 'return "ok"'],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                print("[MacWindowMonitor] osascript available ✓")
                return True
        except Exception:
            pass
        print("[MacWindowMonitor] osascript not available — window monitoring disabled")
        return False

    def _get_active_window(self) -> str:
        if not self._osascript_ok:
            return ""
        try:
            result = subprocess.run(
                ["osascript", "-e", self._APPLESCRIPT],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                if (not self._permission_warned and
                        "not allowed assistive access" in (result.stderr or "").lower()):
                    print("[MacWindowMonitor] Permission needed: System Settings > Privacy & Security > Accessibility.")
                    self._permission_warned = True
                return ""
            return result.stdout.strip()
        except Exception:
            return ""

    def check(self) -> list:
        events = []
        title  = self._get_active_window()

        if not title or title == self._last_window:
            return events

        title_lower = title.lower()
        for keyword in self.SUSPICIOUS_WINDOW_KEYWORDS:
            if keyword in title_lower:
                events.append(
                    f"SUSPICIOUS_WINDOW: Student switched to off-task app | "
                    f"WindowTitle={title} | Keyword={keyword} | "
                    f"Action=Student may be distracted or cheating"
                )
                break

        self._last_window = title
        return events


# ══════════════════════════════════════════════════════════════
#  3. DNS / NETWORK MONITOR  (cross-platform via psutil — same logic)
# ══════════════════════════════════════════════════════════════
class MacDNSMonitor:
    """Network connection monitor using psutil — works on macOS."""

    def __init__(self):
        self._seen_domains: set = set()
        self._baseline()

    def _get_active_connections(self) -> set:
        domains = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in ('ESTABLISHED', 'SYN_SENT') and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if ip.startswith(('127.', '10.', '192.168.', '172.')):
                        continue
                    if port not in (80, 443, 8080, 8443):
                        continue
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        domains.add(hostname.lower())
                    except Exception:
                        pass
        except Exception:
            pass
        return domains

    def _baseline(self):
        self._seen_domains = self._get_active_connections()

    def _check_domain(self, domain: str):
        for blocked, category in ALL_BLOCKED.items():
            if domain == blocked or domain.endswith('.' + blocked):
                return (category, domain)
        return None

    def check(self) -> list:
        events  = []
        current = self._get_active_connections()
        new     = current - self._seen_domains

        for domain in new:
            result = self._check_domain(domain)
            if result:
                category, matched = result
                events.append(
                    f"DNS_BLOCKED: Network connection to restricted site | "
                    f"Category={category} | Domain={domain} | "
                    f"Matched={matched} | Detected via network connection"
                )

        self._seen_domains = current
        return events


# ══════════════════════════════════════════════════════════════
#  4. USB MONITOR  (macOS — uses diskutil / ioreg)
#     Linux reads /sys/bus/usb/devices which doesn't exist on macOS
# ══════════════════════════════════════════════════════════════
class MacUSBMonitor:
    """
    Detects newly connected USB mass-storage devices on macOS.
    Uses `diskutil list -plist` to list disk volumes and track changes.
    Falls back to `system_profiler SPUSBDataType -json` for richer info.
    """

    def __init__(self):
        self._known_disks: set = self._get_external_disks()
        print(f"[MacUSBMonitor] Baseline: {len(self._known_disks)} external disk(s)")

    def _get_external_disks(self) -> set:
        """Return a set of identifiers for currently attached external disks."""
        disks = set()
        try:
            result = subprocess.run(
                ["diskutil", "list", "-plist", "external"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import plistlib
                data = plistlib.loads(result.stdout.encode())
                for disk in data.get("AllDisksAndPartitions", []):
                    disk_id = disk.get("DeviceIdentifier", "")
                    if disk_id:
                        disks.add(disk_id)
        except Exception as e:
            print(f"[MacUSBMonitor] diskutil error: {e}")
        return disks

    def _get_usb_info(self) -> dict:
        """Get richer USB device info via system_profiler."""
        info = {}
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get("SPUSBDataType", []):
                    name = device.get("_name", "Unknown Device")
                    vendor = device.get("vendor_id", "?")
                    product = device.get("product_id", "?")
                    serial = device.get("serial_num", "NoSerial")
                    info[name] = {
                        "name": name, "vendor": vendor,
                        "product": product, "serial": serial
                    }
        except Exception:
            pass
        return info

    def check(self) -> list:
        events = []
        current = self._get_external_disks()
        new_disks  = current - self._known_disks
        gone_disks = self._known_disks - current

        if new_disks:
            usb_info = self._get_usb_info()

        for disk_id in new_disks:
            # Try to get friendly name from system_profiler
            name = "Unknown USB Device"
            for dev_name, info in (usb_info.items() if new_disks else []):
                # Match by any available info
                name = dev_name
                break
            events.append(
                f"LAB_USB_INSERT: EXAM VIOLATION - USB device inserted! | "
                f"DiskID={disk_id} | Name={name} | "
                f"Action=NOTIFY INSTRUCTOR IMMEDIATELY"
            )

        for disk_id in gone_disks:
            events.append(
                f"LAB_USB_REMOVE: USB device removed | "
                f"DiskID={disk_id} | "
                f"Action=Student may have transferred files"
            )

        self._known_disks = current
        return events


# ══════════════════════════════════════════════════════════════
#  5. SHELL COMMAND MONITOR  (macOS — zsh default since macOS Catalina)
#     Injects hooks into ~/.zshrc and ~/.bashrc (same technique as Linux)
#     macOS default shell is zsh since Catalina (10.15)
# ══════════════════════════════════════════════════════════════
class MacShellCommandMonitor:
    """
    Captures shell commands on macOS via:
    1. Injecting PROMPT_COMMAND / precmd hooks into ~/.zshrc and ~/.bashrc
    2. Tailing ~/.zsh_history and ~/.bash_history as fallback
    """

    SOC_LOG = os.path.expanduser("~/.soc_cmd_log")

    SKIP_COMMANDS = {
        "ls", "ll", "la", "pwd", "cd", "clear", "exit", "history",
        "echo", "cat", "man", "help", "whoami", "date", "uptime",
        "top", "htop", "df", "du", "free", "ps", "sleep", "true",
        "false", "which", "type", "alias", "unalias", "export", "env",
        "open",  # macOS-specific no-op for monitoring purposes
    }

    def __init__(self):
        self._soc_log_size  = 0
        self._hist_files: dict = {}
        self._inject_hooks()
        self._init_history_files()

    def _inject_hooks(self):
        home    = os.path.expanduser("~")
        soc_log = self.SOC_LOG

        bash_hook = (
            '\n# SOC_MONITOR_HOOK\n'
            'if [[ -z "$SOC_HOOK_LOADED" ]]; then\n'
            '  export SOC_HOOK_LOADED=1\n'
            '  export PROMPT_COMMAND=\'__soc_log_cmd() { '
            'local last; last=$(HISTTIMEFORMAT="" builtin history 1 | sed "s/^[ 0-9]*//"); '
            f'echo "$(date +%H:%M:%S) [bash] $last" >> {soc_log}; '
            '} ; __soc_log_cmd\'\n'
            'fi\n'
        )

        zsh_hook = (
            '\n# SOC_MONITOR_HOOK\n'
            'if [[ -z "$SOC_HOOK_LOADED" ]]; then\n'
            '  export SOC_HOOK_LOADED=1\n'
            '  __soc_precmd() {\n'
            '    local last=$(fc -ln -1 2>/dev/null | sed "s/^[[:space:]]*//")\n'
            f'   echo "$(date +%H:%M:%S) [zsh] $last" >> {soc_log}\n'
            '  }\n'
            '  autoload -Uz add-zsh-hook\n'
            '  add-zsh-hook precmd __soc_precmd\n'
            'fi\n'
        )

        for rc_file, hook in [
            (f"{home}/.zshrc",  zsh_hook),
            (f"{home}/.bashrc", bash_hook),
        ]:
            try:
                existing = open(rc_file).read() if os.path.exists(rc_file) else ""
                if "SOC_MONITOR_HOOK" not in existing:
                    with open(rc_file, "a") as f:
                        f.write(hook)
                    print(f"[MacShellMonitor] Injected hook into {rc_file} ✓")
                else:
                    print(f"[MacShellMonitor] Hook already present in {rc_file} ✓")
            except Exception as e:
                print(f"[MacShellMonitor] Could not inject hook into {rc_file}: {e}")

        if not os.path.exists(soc_log):
            try:
                open(soc_log, "w").close()
            except Exception:
                pass

        try:
            self._soc_log_size = os.path.getsize(soc_log)
        except Exception:
            self._soc_log_size = 0

    def _init_history_files(self):
        home = os.path.expanduser("~")
        # macOS default: zsh history; bash also possible
        for p in [
            f"{home}/.zsh_history",
            f"{home}/.zhistory",
            f"{home}/.bash_history",
            f"{home}/.config/fish/fish_history",
        ]:
            if os.path.exists(p):
                st = os.stat(p)
                self._hist_files[p] = (st.st_size, st.st_ino)
                print(f"[MacShellMonitor] Watching history: {p}")

    def _read_new_from_soc_log(self) -> list:
        lines = []
        try:
            if not os.path.exists(self.SOC_LOG):
                return lines
            size = os.path.getsize(self.SOC_LOG)
            if size <= self._soc_log_size:
                return lines
            with open(self.SOC_LOG, "rb") as f:
                f.seek(self._soc_log_size)
                new_bytes = f.read(size - self._soc_log_size)
            self._soc_log_size = size
            text = new_bytes.decode("utf-8", errors="replace")
            lines = [l.strip() for l in text.splitlines() if l.strip()]
        except Exception:
            pass
        return lines

    def _read_new_from_history(self, path: str, last_size: int) -> list:
        try:
            st = os.stat(path)
            if st.st_size <= last_size:
                return []
            with open(path, "rb") as f:
                f.seek(last_size)
                raw = f.read(st.st_size - last_size)
            self._hist_files[path] = (st.st_size, st.st_ino)
            text = raw.decode("utf-8", errors="replace")
            return [l.strip() for l in text.splitlines() if l.strip()]
        except Exception:
            return []

    def _clean_zsh_line(self, line: str) -> str:
        if line.startswith(": ") and ";" in line:
            return line.split(";", 1)[1].strip()
        return line

    def _should_skip(self, cmd: str) -> bool:
        if not cmd:
            return True
        base = cmd.split()[0].lstrip("(").split("/")[-1]
        return base in self.SKIP_COMMANDS

    def check(self) -> list:
        events    = []
        seen_cmds = set()

        # Method A — SOC injected log
        for raw_line in self._read_new_from_soc_log():
            parts = raw_line.split(" ", 2)
            if len(parts) == 3 and parts[1].startswith("["):
                shell = parts[1].strip("[]")
                cmd   = parts[2].strip()
            else:
                shell = "shell"
                cmd   = raw_line
            if self._should_skip(cmd):
                continue
            key = cmd[:80]
            if key in seen_cmds:
                continue
            seen_cmds.add(key)
            events.append(
                f"SHELL_COMMAND: Student ran command | "
                f"Shell={shell} | Command={cmd[:120]} | Source=live"
            )

        # Method B — history file fallback
        home = os.path.expanduser("~")
        for p in [f"{home}/.zsh_history", f"{home}/.bash_history"]:
            if p not in self._hist_files and os.path.exists(p):
                st = os.stat(p)
                self._hist_files[p] = (st.st_size, st.st_ino)

        for path, (last_size, last_inode) in list(self._hist_files.items()):
            try:
                st = os.stat(path)
                if st.st_ino != last_inode:
                    self._hist_files[path] = (0, st.st_ino)
                    last_size = 0
                new_lines = self._read_new_from_history(path, last_size)
                shell = "zsh" if "zsh" in path else "bash"
                for line in new_lines:
                    cmd = self._clean_zsh_line(line)
                    if self._should_skip(cmd) or cmd.startswith("#"):
                        continue
                    key = cmd[:80]
                    if key in seen_cmds:
                        continue
                    seen_cmds.add(key)
                    events.append(
                        f"SHELL_COMMAND: Student ran command | "
                        f"Shell={shell} | Command={cmd[:120]} | Source=history"
                    )
            except Exception:
                pass

        return events


# ══════════════════════════════════════════════════════════════
#  6. SCREENSHOT MONITOR  (macOS paths + screencapture process)
#     macOS saves to ~/Desktop by default; also watches ~/Pictures
# ══════════════════════════════════════════════════════════════
class MacScreenshotMonitor:
    """
    Detects screenshots on macOS:
    - Watches ~/Desktop (default macOS screenshot location)
    - Watches ~/Pictures and ~/Downloads
    - Detects screencapture / Screenshot.app processes
    """

    _SCREENSHOT_TOOLS = [
        "screencapture",   # macOS built-in CLI
        "Screenshot",      # Screenshot.app (macOS 10.14+)
        "Snagit",          # Popular third-party
        "CleanMyMac",      # Has screenshot feature
        "Monosnap",
        "Skitch",
        "Lightshot",
    ]

    def __init__(self):
        self._last_check = time.time()
        self._known_screenshots: set = set()
        self._screenshot_dirs = self._get_screenshot_dirs()
        self._baseline_screenshots()
        print(f"[MacScreenshotMonitor] Watching {len(self._screenshot_dirs)} directories ✓")

    def _get_screenshot_dirs(self) -> list:
        home = os.path.expanduser("~")
        dirs = [
            f"{home}/Desktop",           # macOS default screenshot location
            f"{home}/Pictures",
            f"{home}/Pictures/Screenshots",
            f"{home}/Downloads",
            f"{home}/Documents",
        ]
        return [d for d in dirs if os.path.isdir(d)]

    def _baseline_screenshots(self):
        for directory in self._screenshot_dirs:
            try:
                for f in os.listdir(directory):
                    fpath = os.path.join(directory, f)
                    if os.path.isfile(fpath) and self._is_screenshot_file(f):
                        self._known_screenshots.add(fpath)
            except Exception:
                pass

    def _is_screenshot_file(self, filename: str) -> bool:
        fname = filename.lower()
        image_extensions = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff")
        if not fname.endswith(image_extensions):
            return False
        # macOS default naming: "Screenshot 2024-01-15 at 12.30.45 PM.png"
        if "screenshot" in fname or "screen shot" in fname:
            return True
        # Date-time patterns (auto-named)
        if re.search(r'\d{4}[-_]\d{2}[-_]\d{2}', fname):
            return True
        return False

    def _check_screenshot_processes(self) -> list:
        events = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    pname = (pinfo['name'] or '').strip()
                    create_time = pinfo.get('create_time', 0)
                    if create_time < self._last_check:
                        continue
                    for tool in self._SCREENSHOT_TOOLS:
                        if tool.lower() in pname.lower():
                            cmdline = ' '.join(pinfo.get('cmdline') or [])[:100]
                            events.append(
                                f"SCREENSHOT_TAKEN: Screenshot tool detected | "
                                f"Tool={pname} | PID={pinfo['pid']} | Cmdline={cmdline}"
                            )
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return events

    def _check_new_screenshot_files(self) -> list:
        events = []
        current_time = time.time()

        for directory in self._screenshot_dirs:
            try:
                for f in os.listdir(directory):
                    fpath = os.path.join(directory, f)
                    if fpath in self._known_screenshots:
                        continue
                    if not os.path.isfile(fpath):
                        continue
                    if not self._is_screenshot_file(f):
                        continue
                    try:
                        mtime = os.path.getmtime(fpath)
                        if current_time - mtime > 30:
                            self._known_screenshots.add(fpath)
                            continue
                    except Exception:
                        continue
                    self._known_screenshots.add(fpath)
                    fsize = os.path.getsize(fpath) // 1024
                    events.append(
                        f"SCREENSHOT_TAKEN: New screenshot file created | "
                        f"File={f} | Path={directory} | Size={fsize}KB"
                    )
            except Exception:
                pass

        return events

    def check(self) -> list:
        events = []
        events.extend(self._check_screenshot_processes())
        events.extend(self._check_new_screenshot_files())
        self._last_check = time.time()
        return events


# ══════════════════════════════════════════════════════════════
#  7. MAC STUDENT ACTIVITY MONITOR — orchestrator
#     Drop-in replacement for student_monitor.StudentActivityMonitor
#     Same interface: collect() -> list[tuple[str, str]]
# ══════════════════════════════════════════════════════════════
class MacStudentActivityMonitor:
    """
    Combines all macOS-specific monitors.
    Provides the same collect() interface as StudentActivityMonitor (Linux)
    so agent.py needs minimal changes.
    """

    def __init__(self):
        print("[MacMonitor] Initializing macOS student activity monitors...")
        self.browser    = MacBrowserMonitor()
        self.window     = MacActiveWindowMonitor()
        self.dns        = MacDNSMonitor()
        self.usb        = MacUSBMonitor()
        self.shell      = MacShellCommandMonitor()
        self.screenshot = MacScreenshotMonitor()
        print("[MacMonitor] macOS monitors ready ✓")

    def collect(self) -> list:
        """
        Returns list of (source, event_string) tuples —
        identical interface to StudentActivityMonitor.collect()
        """
        results = []
        checks = [
            ("BROWSER",    self.browser.check),
            ("WINDOW",     self.window.check),
            ("DNS",        self.dns.check),
            ("LAB_USB",    self.usb.check),
            ("SHELL",      self.shell.check),
            ("SCREENSHOT", self.screenshot.check),
        ]
        for source, fn in checks:
            try:
                for event in fn():
                    results.append((source, event))
                    print(f"[MacMonitor][{source}] {event[:120]}")
            except Exception as e:
                print(f"[MacMonitor][{source}] Error: {e}")
        return results
