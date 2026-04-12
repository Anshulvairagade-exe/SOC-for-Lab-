import tempfile
# ============================================================
#  SOC Platform - Student Activity Monitor
#  Built for college SOC lab — monitors what students do
#  during practicals and exams.
#
#  Monitors:
#  1. BrowserMonitor   → active browser tabs & URLs visited
#  2. AppMonitor       → which applications are open/active
#  3. ScreenshotMonitor→ periodic screenshots (optional)
#  4. ClipboardMonitor → detects code copied from internet
# ============================================================

import os
import sys
import time
import subprocess
import re
import sqlite3
import glob
import socket

try:
    import psutil
except ImportError:
    print("[StudentMonitor] Install psutil: pip install psutil")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
#  CATEGORY DEFINITIONS
#  Add/remove domains from any category as needed
# ══════════════════════════════════════════════════════════════

BLOCKED_CATEGORIES = {

    "GAMING_ONLINE": [
        "miniclip.com", "poki.com", "coolmathgames.com", "friv.com",
        "y8.com", "kongregate.com", "addictinggames.com", "newgrounds.com",
        "armor games.com", "agame.com", "gameflare.com", "silvergames.com",
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
        "hotstar.com", "jiocinema.com", "mx player.com", "voot.com",
        "zee5.com", "sonyliv.com", "twitch.tv", "dailymotion.com",
        "vimeo.com",
    ],

    "CHEATING_SITES": [
        "chegg.com", "coursehero.com", "studocu.com", "scribd.com",
        "slader.com", "bartleby.com", "brainly.com",
        "homework.com", "homeworklib.com",
        # Answer/code sharing that suggests copying
        "pastebin.com", "pastecode.io", "hastebin.com",
    ],

    "ALLOWED_CODING": [
        # These are ALLOWED during practicals — don't alert on these
        "stackoverflow.com", "github.com", "docs.python.org",
        "developer.mozilla.org", "w3schools.com", "geeksforgeeks.org",
        "cppreference.com", "linux.die.net", "man7.org",
        "google.com", "duckduckgo.com",   # Search engines are OK
    ],
}

# All forbidden domains flattened
ALL_BLOCKED = {
    domain: category
    for category, domains in BLOCKED_CATEGORIES.items()
    if category != "ALLOWED_CODING"
    for domain in domains
}


# ══════════════════════════════════════════════════════════════
#  1. BROWSER URL MONITOR
#     Reads Chrome/Firefox browser history databases directly
#     Works without any browser extension
# ══════════════════════════════════════════════════════════════
class BrowserMonitor:
    """
    Reads browser history SQLite databases directly from disk.
    Detects URLs visited in Chrome and Firefox.
    Checks them against the blocked categories list.

    No browser extension needed — reads the DB files directly.
    """

    def __init__(self):
        self._last_checked = {}   # { db_path: last_visit_time }
        self._db_paths     = []
        self._find_browsers()
        self._baseline()

    def _find_browsers(self):
        """Locate Chrome, Chromium, Brave, Edge, Firefox history database files."""
        home = os.path.expanduser("~")
        print(f"[BrowserMonitor] Searching for browsers in HOME={home}")
        paths = []

        # ── Standard ~/.config paths ──
        chrome_search_paths = [
            f"{home}/.config/google-chrome/Default/History",
            f"{home}/.config/google-chrome/Profile 1/History",
            f"{home}/.config/chromium/Default/History",
            f"{home}/.config/BraveSoftware/Brave-Browser/Default/History",
            f"{home}/.config/BraveSoftware/Brave-Browser/Profile 1/History",
            f"{home}/.config/brave/Default/History",
            f"{home}/.config/microsoft-edge/Default/History",
        ]
        for p in chrome_search_paths:
            exists = os.path.exists(p)
            if exists:
                bname = "brave" if "brave" in p.lower() else \
                        "chromium" if "chromium" in p.lower() else \
                        "edge" if "edge" in p.lower() else "chrome"
                paths.append((bname, p))
                print(f"[BrowserMonitor] Found {bname}: {p}")

        # ── Snap Brave — scans all version folders dynamically ──
        # e.g. ~/snap/brave/603/.config/BraveSoftware/Brave-Browser/Default/History
        snap_brave_glob = glob.glob(
            f"{home}/snap/brave/*/.config/BraveSoftware/Brave-Browser/Default/History"
        ) + glob.glob(
            f"{home}/snap/brave/*/.config/BraveSoftware/Brave-Browser/Profile */History"
        )
        for p in snap_brave_glob:
            # Skip the 'current' symlink — it causes permission errors
            if "/current/" in p:
                continue
            if os.path.exists(p) and p not in [x[1] for x in paths]:
                paths.append(("chrome", p))   # brave uses Chrome SQLite format
                print(f"[BrowserMonitor] Found brave (snap): {p}")

        # ── Firefox ──
        ff_base = f"{home}/.mozilla/firefox"
        if os.path.exists(ff_base):
            for profile in glob.glob(f"{ff_base}/*.default*/places.sqlite"):
                if os.path.exists(profile):
                    paths.append(("firefox", profile))
                    print(f"[BrowserMonitor] Found firefox: {profile}")

        self._db_paths = paths
        if not paths:
            print("[BrowserMonitor] No browser history DBs found — "
                  "make sure a browser has been opened at least once")

    def _baseline(self):
        """Record the latest visit time in each browser DB — only alert on NEW visits after this point."""
        for btype, path in self._db_paths:
            ts = self._get_latest_visit_time(btype, path)
            # If DB has history, start from the latest entry (don't re-alert old history)
            # If DB is empty or unreadable, ts=0 — will catch everything going forward
            self._last_checked[path] = ts if ts else 0
            if ts and ts > 0:
                print(f"[BrowserMonitor] Baseline {btype}: tracking from latest entry ✓")
            else:
                print(f"[BrowserMonitor] Baseline {btype}: empty history, watching for new visits")

    def _get_latest_visit_time(self, btype: str, db_path: str):
        """Get the most recent visit timestamp from the DB."""
        try:
            tmp = os.path.join(tempfile.gettempdir(), f"soc_browser_{os.path.basename(db_path)}_{abs(hash(db_path))}")
            import shutil; shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            if btype == "firefox":
                row = conn.execute("SELECT MAX(visit_date) FROM moz_historyvisits").fetchone()
            else:  # chrome, brave, chromium, edge — all use Chrome format
                row = conn.execute("SELECT MAX(last_visit_time) FROM urls").fetchone()
            conn.close()
            return row[0] if row and row[0] else 0
        except Exception as e:
            print(f"Error: {e}")
            return 0

    def _extract_search_query(self, url: str) -> str | None:
        """
        Extract the search query from common search engine URLs.
        Returns the search string, or None if not a search URL.
        """
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url.lower())
            params = urllib.parse.parse_qs(parsed.query)

            # Google, Bing, Yahoo, DuckDuckGo, Baidu all use 'q'
            # Bing also uses 'q', Yandex uses 'text'
            search_engines = {
                "google.com": "q",
                "bing.com": "q",
                "yahoo.com": "p",
                "duckduckgo.com": "q",
                "yandex.com": "text",
                "baidu.com": "wd",
                "search.brave.com": "q",
            }
            domain = parsed.netloc.replace("www.", "")
            for engine, param in search_engines.items():
                if engine in domain:
                    if param in params:
                        return params[param][0]
        except Exception as e:
            print(f"Error: {e}")
            pass
        return None

    def _get_new_visits(self, btype: str, db_path: str, since: int) -> list:
        """
        Return list of (url, title, visit_time) for visits after `since`.
        """
        visits = []
        try:
            import shutil
            tmp = os.path.join(tempfile.gettempdir(), f"soc_browser_{os.path.basename(db_path)}_{abs(hash(db_path))}")
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)

            if btype == "firefox":
                # Firefox timestamps are microseconds since Unix epoch
                rows = conn.execute("""
                    SELECT p.url, p.title, v.visit_date
                    FROM moz_places p
                    JOIN moz_historyvisits v ON p.id = v.place_id
                    WHERE v.visit_date > ?
                    ORDER BY v.visit_date DESC
                    LIMIT 50
                """, (since,)).fetchall()
            else:
                # chrome, brave, chromium, edge — all use Chrome format
                rows = conn.execute("""
                    SELECT url, title, last_visit_time
                    FROM urls
                    WHERE last_visit_time > ?
                    ORDER BY last_visit_time DESC
                    LIMIT 50
                """, (since,)).fetchall()

            conn.close()
            visits = [(r[0] or '', r[1] or '', r[2] or 0) for r in rows]
        except Exception as e:
            print(f"[BrowserMonitor] DB read error: {e}")
        return visits

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        url = url.lower().strip()
        for prefix in ['https://', 'http://', 'www.']:
            if url.startswith(prefix):
                url = url[len(prefix):]
        return url.split('/')[0].split('?')[0]

    def _check_url(self, url: str, title: str) -> tuple[str, str] | None:
        """
        Check if a URL matches a blocked category.
        Returns (category, domain) or None if allowed.
        """
        domain = self._extract_domain(url)
        if not domain:
            return None

        # Check exact domain match
        for blocked_domain, category in ALL_BLOCKED.items():
            if domain == blocked_domain or domain.endswith('.' + blocked_domain):
                return (category, domain)

        # Check if title contains game/social keywords
        title_lower = title.lower()
        if any(k in title_lower for k in ['game', 'play now', 'gaming']):
            return ('GAMING_TITLE_MATCH', domain)

        return None   # Allowed

    def check(self) -> list[str]:
        events = []
        seen_urls = set()   # Deduplicate across multiple DB versions

        for btype, db_path in self._db_paths:
            since    = self._last_checked.get(db_path, 0)
            visits   = self._get_new_visits(btype, db_path, since)
            max_time = since

            for url, title, visit_time in visits:
                if visit_time > max_time:
                    max_time = visit_time

                # Deduplicate same URL seen across version 600/603 folders
                url_key = url[:100]
                if url_key in seen_urls:
                    continue
                seen_urls.add(url_key)

                # ── Search query detection (always log, regardless of blocked) ──
                query = self._extract_search_query(url)
                if query:
                    events.append(
                        f"BROWSER_SEARCH: Student searched | "
                        f"Query={query} | URL={url[:80]} | Browser={btype}"
                    )

                # ── Blocked site detection ──
                result = self._check_url(url, title)
                if result:
                    category, domain = result
                    events.append(
                        f"BROWSER_BLOCKED: Student visited restricted site | "
                        f"Category={category} | Domain={domain} | "
                        f"URL={url[:80]} | Title={title[:60]} | Browser={btype}"
                    )

                # ── General URL visit (log ALL page loads, not just blocked) ──
                # Skip internal/blank pages and search results pages (already captured above)
                skip_prefixes = ("chrome://", "chrome-extension://", "about:", "data:")
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
#  2. ACTIVE WINDOW MONITOR
#     Tracks which application window is currently focused
#     Uses xdotool (Linux) — shows what student is looking at
# ══════════════════════════════════════════════════════════════
class ActiveWindowMonitor:
    """
    Monitors the currently active/focused window title.
    Uses `xdotool getactivewindow getwindowname` on Linux.
    Alerts when students switch to non-lab applications.
    """

    # Window title keywords that are suspicious during exam
    SUSPICIOUS_WINDOW_KEYWORDS = [
        # Chat apps
        "whatsapp", "telegram", "discord", "signal", "messenger",
        # Social
        "facebook", "instagram", "twitter", "reddit",
        # Games
        "steam", "game", "minecraft", "roblox", "clash",
        # Streaming
        "netflix", "youtube", "hotstar", "prime video",
        # Cheating
        "chegg", "course hero",
    ]

    # These are OK during lab
    ALLOWED_WINDOW_KEYWORDS = [
        "terminal", "code", "vim", "nano", "gedit",
        "python", "gcc", "firefox", "chrome", "brave",
        "files", "thunar", "nautilus",
        "soc platform",
    ]

    def __init__(self):
        self._last_window    = ""
        self._xdotool_ok     = self._check_xdotool()

    def _check_xdotool(self) -> bool:
        try:
            result = subprocess.run(["which", "xdotool"],
                                    capture_output=True, timeout=2)
            if result.returncode == 0:
                print("[WindowMonitor] xdotool found ✓")
                return True
        except Exception as e:
            print(f"Error: {e}")
            pass
        print("[WindowMonitor] xdotool not found — install with: sudo apt install xdotool")
        return False

    def _get_active_window(self) -> str:
        """Get the title of the currently focused window."""
        if not self._xdotool_ok:
            return ""
        try:
            result = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=2,
                env={**os.environ, "DISPLAY": ":0"}
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"Error: {e}")
            return ""

    def check(self) -> list[str]:
        events   = []
        title    = self._get_active_window()

        if not title or title == self._last_window:
            return events

        title_lower = title.lower()

        # Check for suspicious window
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
#  3. DNS / NETWORK REQUEST MONITOR
#     Watches /proc/net/tcp and DNS cache to catch site visits
#     even if browser history is cleared
# ══════════════════════════════════════════════════════════════
class DNSMonitor:
    """
    Monitors DNS lookups by watching which hostnames the machine
    resolves. Works by reading /proc/net/tcp connections and
    reverse-resolving IPs to catch site visits.

    Also reads systemd-resolved cache if available.
    """

    def __init__(self):
        self._seen_domains = set()
        self._baseline()

    def _get_active_connections(self) -> set:
        """Get all remote hostnames from active TCP connections."""
        domains = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in ('ESTABLISHED', 'SYN_SENT') and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    # Skip local/private IPs
                    if ip.startswith(('127.', '10.', '192.168.', '172.')):
                        continue
                    # Only check web ports
                    if port not in (80, 443, 8080, 8443):
                        continue
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        domains.add(hostname.lower())
                    except Exception as e:
                        print(f"Error: {e}")
                        pass
        except Exception as e:
            print(f"Error: {e}")
            pass
        return domains

    def _baseline(self):
        self._seen_domains = self._get_active_connections()

    def _check_domain(self, domain: str) -> tuple | None:
        """Check if domain matches a blocked category."""
        for blocked, category in ALL_BLOCKED.items():
            if domain == blocked or domain.endswith('.' + blocked):
                return (category, domain)
        return None

    def check(self) -> list[str]:
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
#  4. USB ALERT MONITOR (Enhanced for lab use)
#     Raises CRITICAL alert immediately when any USB storage
#     is connected — common exam cheating method
# ══════════════════════════════════════════════════════════════
class LabUSBMonitor:
    """
    Enhanced USB monitor specifically for lab/exam use.
    CRITICAL alert the moment any storage device is inserted.
    Logs device details for evidence.
    """

    def __init__(self):
        self._known_storage = self._get_usb_storage()
        print(f"[LabUSBMonitor] Baseline: {len(self._known_storage)} storage devices")

    def _get_usb_storage(self) -> dict:
        """Get all connected USB storage devices with details."""
        devices = {}
        usb_path = "/sys/bus/usb/devices"
        if not os.path.exists(usb_path):
            return devices

        for entry in os.listdir(usb_path):
            base = f"{usb_path}/{entry}"
            # Check if it's a mass storage device
            is_storage = os.path.exists(f"{base}/bDeviceClass") and \
                         any(os.path.exists(f"{base}/{sub}/bInterfaceClass")
                             for sub in os.listdir(base)
                             if os.path.isdir(f"{base}/{sub}"))

            vendor_f  = f"{base}/idVendor"
            product_f = f"{base}/idProduct"
            mfr_f     = f"{base}/manufacturer"
            pname_f   = f"{base}/product"
            serial_f  = f"{base}/serial"

            if os.path.exists(vendor_f):
                try:
                    vendor   = open(vendor_f).read().strip()
                    product  = open(product_f).read().strip() if os.path.exists(product_f) else "?"
                    mfr      = open(mfr_f).read().strip() if os.path.exists(mfr_f) else "Unknown"
                    pname    = open(pname_f).read().strip() if os.path.exists(pname_f) else "Unknown"
                    serial   = open(serial_f).read().strip() if os.path.exists(serial_f) else "NoSerial"
                    devices[entry] = {
                        "vendor": vendor, "product": product,
                        "manufacturer": mfr, "name": pname, "serial": serial
                    }
                except Exception as e:
                    print(f"Error: {e}")
                    pass
        return devices

    def check(self) -> list[str]:
        events  = []
        current = self._get_usb_storage()
        new_devs  = {k: v for k, v in current.items() if k not in self._known_storage}
        gone_devs = {k: v for k, v in self._known_storage.items() if k not in current}

        for dev_id, info in new_devs.items():
            events.append(
                f"LAB_USB_INSERT: EXAM VIOLATION - USB device inserted! | "
                f"DeviceID={dev_id} | Manufacturer={info['manufacturer']} | "
                f"Name={info['name']} | VendorID={info['vendor']} | "
                f"ProductID={info['product']} | Serial={info['serial']} | "
                f"Action=NOTIFY INSTRUCTOR IMMEDIATELY"
            )

        for dev_id, info in gone_devs.items():
            events.append(
                f"LAB_USB_REMOVE: USB device removed | "
                f"DeviceID={dev_id} | Name={info['name']} | "
                f"Serial={info['serial']} | "
                f"Action=Student may have transferred files"
            )

        self._known_storage = current
        return events


# ══════════════════════════════════════════════════════════════
#  5. SHELL COMMAND MONITOR
#     Two methods to catch terminal commands in real-time:
#
#  METHOD A — SOC history file (primary, most reliable)
#    Agent writes a shared history file at ~/.soc_cmd_log
#    via PROMPT_COMMAND injected into ~/.bashrc and ~/.zshrc.
#    This fires after EVERY command, immediately.
#
#  METHOD B — /proc scanner (fallback, catches running procs)
#    Scans /proc/<pid>/cmdline for interesting child processes
#    of known terminals — catches long-running commands.
# ══════════════════════════════════════════════════════════════
class ShellCommandMonitor:
    """
    Captures shell commands in real-time by:
    1. Injecting `PROMPT_COMMAND` hooks into ~/.bashrc and ~/.zshrc
       so each command is appended to ~/.soc_cmd_log immediately.
    2. Also tails ~/.bash_history / ~/.zsh_history as backup.
    3. Scans /proc for new child processes of terminal apps.
    """

    SOC_LOG = os.path.expanduser("~/.soc_cmd_log")

    # Commands too boring to alert on
    SKIP_COMMANDS = {
        "ls", "ll", "la", "pwd", "cd", "clear", "exit", "history",
        "echo", "cat", "man", "help", "whoami", "date", "uptime",
        "top", "htop", "df", "du", "free", "ps", "sleep", "true",
        "false", "which", "type", "alias", "unalias", "export", "env",
    }

    # Shell names
    SHELL_NAMES = {"bash", "zsh", "sh", "fish", "ksh", "dash"}

    def __init__(self):
        self._soc_log_size  = 0
        self._hist_files    = {}   # { path: (size, inode) }
        self._seen_procs    = set()  # PIDs already reported

        self._inject_hooks()
        self._init_history_files()
        self._init_proc_baseline()

    def _inject_hooks(self):
        """
        Inject PROMPT_COMMAND into ~/.bashrc and precmd into ~/.zshrc
        so every command is written to ~/.soc_cmd_log immediately.
        Only injects once (checks for SOC marker).
        """
        home = os.path.expanduser("~")
        soc_log = self.SOC_LOG

        # Bash hook — fires after every command via PROMPT_COMMAND
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

        # Zsh hook — precmd fires after every command
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
            (f"{home}/.bashrc", bash_hook),
            (f"{home}/.zshrc",  zsh_hook),
        ]:
            try:
                existing = open(rc_file).read() if os.path.exists(rc_file) else ""
                if "SOC_MONITOR_HOOK" not in existing:
                    with open(rc_file, "a") as f:
                        f.write(hook)
                    print(f"[ShellMonitor] Injected hook into {rc_file} ✓")
                else:
                    print(f"[ShellMonitor] Hook already present in {rc_file} ✓")
            except Exception as e:
                print(f"[ShellMonitor] Could not inject hook into {rc_file}: {e}")

        # Init the SOC log file if it doesn't exist
        if not os.path.exists(soc_log):
            try:
                open(soc_log, "w").close()
            except Exception as e:
                print(f"Error: {e}")
                pass

        # Record current size as baseline (don't re-alert old commands)
        try:
            self._soc_log_size = os.path.getsize(soc_log)
        except Exception as e:
            print(f"Error: {e}")
            self._soc_log_size = 0

    def _init_history_files(self):
        """Also watch bash/zsh history as backup."""
        home = os.path.expanduser("~")
        for p in [f"{home}/.bash_history", f"{home}/.zsh_history",
                  f"{home}/.zhistory", f"{home}/.config/fish/fish_history"]:
            if os.path.exists(p):
                st = os.stat(p)
                self._hist_files[p] = (st.st_size, st.st_ino)
                print(f"[ShellMonitor] Backup history: {p}")

    def _init_proc_baseline(self):
        """Snapshot existing shell child processes so we only alert on new ones."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                if proc.info['name'] in self.SHELL_NAMES:
                    self._seen_procs.add(proc.info['pid'])
        except Exception as e:
            print(f"Error: {e}")
            pass

    def _read_new_from_soc_log(self) -> list[str]:
        """Read new lines appended to ~/.soc_cmd_log since last check."""
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
        except Exception as e:
            print(f"Error: {e}")
            pass
        return lines

    def _read_new_from_history(self, path: str, last_size: int) -> list[str]:
        """Read newly appended lines from a history file."""
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
        except Exception as e:
            print(f"Error: {e}")
            return []

    def _clean_zsh_line(self, line: str) -> str:
        """Strip zsh extended history format: ': timestamp:elapsed;command'"""
        if line.startswith(": ") and ";" in line:
            return line.split(";", 1)[1].strip()
        return line

    def _should_skip(self, cmd: str) -> bool:
        if not cmd:
            return True
        base = cmd.split()[0].lstrip("(").split("/")[-1]  # handle /bin/bash, (bash), etc.
        return base in self.SKIP_COMMANDS

    def check(self) -> list[str]:
        events = []
        seen_cmds = set()   # deduplicate between methods

        # ── Method A: SOC injected log (real-time, most reliable) ──
        for raw_line in self._read_new_from_soc_log():
            # Format: "HH:MM:SS [shell] command"
            parts = raw_line.split(" ", 2)
            if len(parts) == 3 and parts[1].startswith("["):
                ts   = parts[0]
                shell = parts[1].strip("[]")
                cmd  = parts[2].strip()
            else:
                shell = "shell"
                cmd   = raw_line
                ts    = ""

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

        # ── Method B: backup history files (for sessions opened before agent) ──
        home = os.path.expanduser("~")
        # Check for new history files created after init
        for p in [f"{home}/.bash_history", f"{home}/.zsh_history"]:
            if p not in self._hist_files and os.path.exists(p):
                st = os.stat(p)
                self._hist_files[p] = (st.st_size, st.st_ino)

        for path, (last_size, last_inode) in list(self._hist_files.items()):
            try:
                st = os.stat(path)
                if st.st_ino != last_inode:   # file rotated
                    self._hist_files[path] = (0, st.st_ino)
                    last_size = 0
                new_lines = self._read_new_from_history(path, last_size)
                shell = "bash" if "bash" in path else "zsh" if "zsh" in path else "sh"
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
            except Exception as e:
                print(f"Error: {e}")
                pass

        return events


# ══════════════════════════════════════════════════════════════
#  6. SCREENSHOT MONITOR — detects when student takes screenshots
# ══════════════════════════════════════════════════════════════
class ScreenshotMonitor:
    """
    Detects when a student takes a screenshot using:
    - gnome-screenshot, scrot, flameshot, spectacle, xfce4-screenshooter
    - Print Screen key (via process detection)
    - Watching common screenshot directories for new files
    """
    
    def __init__(self):
        self._screenshot_tools = [
            "gnome-screenshot", "scrot", "flameshot", "spectacle",
            "xfce4-screenshooter", "shutter", "kazam", "peek",
            "import",  # ImageMagick
            "maim", "screencapture"
        ]
        self._last_check = time.time()
        self._known_screenshots = set()
        self._screenshot_dirs = self._get_screenshot_dirs()
        self._baseline_screenshots()
        print(f"[ScreenshotMonitor] Watching {len(self._screenshot_dirs)} directories ✓")
    
    def _get_screenshot_dirs(self) -> list:
        """Get common screenshot save locations."""
        home = os.path.expanduser("~")
        dirs = [
            f"{home}/Pictures",
            f"{home}/Pictures/Screenshots",
            f"{home}/Screenshots",
            f"{home}/Desktop",
            f"{home}",
            "/tmp",
        ]
        return [d for d in dirs if os.path.isdir(d)]
    
    def _baseline_screenshots(self):
        """Record existing screenshot files so we only detect NEW ones."""
        for directory in self._screenshot_dirs:
            try:
                for f in os.listdir(directory):
                    fpath = os.path.join(directory, f)
                    if os.path.isfile(fpath) and self._is_screenshot_file(f):
                        self._known_screenshots.add(fpath)
            except Exception as e:
                print(f"Error: {e}")
                pass
    
    def _is_screenshot_file(self, filename: str) -> bool:
        """Check if filename looks like a screenshot."""
        fname = filename.lower()
        # Common screenshot naming patterns
        screenshot_patterns = [
            "screenshot", "screen shot", "capture", "scrot",
            "flameshot", "spectacle", "shutter"
        ]
        # Must be an image file
        image_extensions = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
        if not fname.endswith(image_extensions):
            return False
        # Check for screenshot patterns or timestamp patterns (like 2024-01-15_12-30-45)
        if any(p in fname for p in screenshot_patterns):
            return True
        # Date-time pattern in filename (common for auto-named screenshots)
        if re.search(r'\d{4}[-_]\d{2}[-_]\d{2}[-_]\d{2}[-_]\d{2}', fname):
            return True
        return False
    
    def _check_screenshot_processes(self) -> list:
        """Detect running screenshot tool processes."""
        events = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    pname = (pinfo['name'] or '').lower()
                    create_time = pinfo.get('create_time', 0)
                    
                    # Only check processes started since last check
                    if create_time < self._last_check:
                        continue
                    
                    # Check if it's a screenshot tool
                    for tool in self._screenshot_tools:
                        if tool in pname:
                            cmdline = ' '.join(pinfo.get('cmdline') or [])[:100]
                            events.append(
                                f"SCREENSHOT_TAKEN: Screenshot tool detected | "
                                f"Tool={pname} | PID={pinfo['pid']} | "
                                f"Cmdline={cmdline}"
                            )
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"Error: {e}")
            pass
        return events
    
    def _check_new_screenshot_files(self) -> list:
        """Detect new screenshot files in common directories."""
        events = []
        current_time = time.time()
        
        for directory in self._screenshot_dirs:
            try:
                for f in os.listdir(directory):
                    fpath = os.path.join(directory, f)
                    
                    # Skip if already known
                    if fpath in self._known_screenshots:
                        continue
                    
                    if not os.path.isfile(fpath):
                        continue
                    
                    # Check if it's a screenshot file
                    if not self._is_screenshot_file(f):
                        continue
                    
                    # Check if file was created recently (last 30 seconds)
                    try:
                        mtime = os.path.getmtime(fpath)
                        if current_time - mtime > 30:
                            self._known_screenshots.add(fpath)
                            continue
                    except Exception as e:
                        print(f"Error: {e}")
                        continue
                    
                    # New screenshot detected!
                    self._known_screenshots.add(fpath)
                    fsize = os.path.getsize(fpath) // 1024  # KB
                    events.append(
                        f"SCREENSHOT_TAKEN: New screenshot file created | "
                        f"File={f} | Path={directory} | Size={fsize}KB"
                    )
            except Exception as e:
                print(f"Error: {e}")
                pass
        
        return events
    
    def check(self) -> list:
        """Check for screenshot activity."""
        events = []
        
        # Method 1: Check for screenshot tool processes
        events.extend(self._check_screenshot_processes())
        
        # Method 2: Check for new screenshot files
        events.extend(self._check_new_screenshot_files())
        
        self._last_check = time.time()
        return events


# ══════════════════════════════════════════════════════════════
#  7. STUDENT ACTIVITY MONITOR — orchestrator
# ══════════════════════════════════════════════════════════════
class StudentActivityMonitor:
    """
    Combines all student-facing monitors into one.
    Drop-in addition to SystemMonitor.collect()
    """
    def __init__(self):
        print("[StudentMonitor] Initializing student activity monitors...")
        self.browser    = BrowserMonitor()
        self.window     = ActiveWindowMonitor()
        self.dns        = DNSMonitor()
        self.usb        = LabUSBMonitor()
        self.shell      = ShellCommandMonitor()
        self.screenshot = ScreenshotMonitor()
        print("[StudentMonitor] Student monitors ready ✓")

    def collect(self) -> list[tuple[str, str]]:
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
                    print(f"[StudentMonitor][{source}] {event[:120]}")
            except Exception as e:
                print(f"Error: {e}")
        return results
