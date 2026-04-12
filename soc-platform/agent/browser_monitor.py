"""
Cross-platform browser history monitor.
Supports Chrome, Firefox, Edge, and Brave on Windows and Linux.
"""

import glob
import os
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

try:
    from shared.os_abstraction import get_os
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    from shared.os_abstraction import get_os


TRAINING_DOMAINS = (
    "hackthebox",
    "app.hackthebox.com",
    "academy.hackthebox.com",
    "tryhackme.com",
    "picoctf.org",
    "portswigger.net",
    "overthewire.org",
)


class BrowserHistoryMonitor:
    """Cross-platform browser history monitoring."""

    def __init__(self, allowed_domains: List[str] = None, check_interval_hours: int = 1):
        self.os_helper = get_os()
        self.allowed_domains = allowed_domains or []
        self.check_interval_hours = check_interval_hours
        self.browser_paths = self.os_helper.get_browser_history_paths()
        self.last_check: Dict[str, int] = {}
        self.temp_dir = Path(self.os_helper.get_temp_dir()) / "soc_browser"
        self.temp_dir.mkdir(exist_ok=True)
        self._initialize_baseline()

    def _db_key(self, browser: str, db_path: str) -> str:
        return f"{browser}:{db_path}"

    def _iter_db_paths(self, browser: str):
        for path_pattern in self.browser_paths.get(browser, []):
            if "*" in path_pattern:
                matched_paths = glob.glob(path_pattern)
            else:
                matched_paths = [path_pattern] if os.path.exists(path_pattern) else []

            for db_path in matched_paths:
                if os.path.exists(db_path):
                    yield db_path

    def _copy_db_to_temp(self, browser: str, db_path: str) -> Path:
        temp_db = self.temp_dir / f"{browser}_{abs(hash(db_path))}_{os.getpid()}.db"
        shutil.copy2(db_path, temp_db)
        return temp_db

    def _initialize_baseline(self):
        """Start tracking from the latest entry already present in each history DB."""
        for browser in self.browser_paths.keys():
            for db_path in self._iter_db_paths(browser):
                key = self._db_key(browser, db_path)
                try:
                    temp_db = self._copy_db_to_temp(browser, db_path)
                    if browser in ["chrome", "edge", "brave"]:
                        self.last_check[key] = self._get_latest_chromium_timestamp(str(temp_db))
                    elif browser == "firefox":
                        self.last_check[key] = self._get_latest_firefox_timestamp(str(temp_db))
                    else:
                        self.last_check[key] = 0
                    temp_db.unlink(missing_ok=True)
                except Exception as e:
                    print(f"[BrowserHistory] Baseline error for {db_path}: {e}")
                    self.last_check[key] = 0

    def _get_latest_chromium_timestamp(self, db_path: str) -> int:
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT MAX(last_visit_time) FROM urls").fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()

    def _get_latest_firefox_timestamp(self, db_path: str) -> int:
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT MAX(last_visit_date) FROM moz_places").fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()

    def collect_history(self, browsers: List[str] = None) -> List[Dict]:
        if browsers is None:
            browsers = list(self.browser_paths.keys())

        all_history = []
        for browser in browsers:
            if browser not in self.browser_paths:
                continue

            try:
                all_history.extend(self._collect_browser_history(browser))
            except Exception as e:
                print(f"[BrowserHistory] Error collecting {browser}: {e}")

        return all_history

    def _collect_browser_history(self, browser: str) -> List[Dict]:
        history = []

        for db_path in self._iter_db_paths(browser):
            try:
                temp_db = self._copy_db_to_temp(browser, db_path)
                if browser in ["chrome", "edge", "brave"]:
                    entries = self._query_chromium_history(str(temp_db), browser, db_path)
                elif browser == "firefox":
                    entries = self._query_firefox_history(str(temp_db), browser, db_path)
                else:
                    entries = []

                history.extend(entries)
                temp_db.unlink(missing_ok=True)
            except Exception as e:
                print(f"[BrowserHistory] Error reading {db_path}: {e}")

        return history

    def _query_chromium_history(self, db_path: str, browser: str, source_path: str) -> List[Dict]:
        entries = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            source_key = self._db_key(browser, source_path)
            last_timestamp = self.last_check.get(source_key, 0)

            query = """
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """

            cursor.execute(query, (last_timestamp,))

            for url, title, visit_count, chromium_time in cursor.fetchall():
                unix_timestamp = (chromium_time / 1000000.0) - 11644473600
                timestamp = datetime.fromtimestamp(unix_timestamp).isoformat()

                if self.allowed_domains and not self._is_allowed_domain(url):
                    continue

                entries.append(
                    {
                        "timestamp": timestamp,
                        "browser": browser,
                        "url": url,
                        "title": title or "(No title)",
                        "visit_count": visit_count,
                        "source_path": source_path,
                    }
                )

                if chromium_time > self.last_check.get(source_key, 0):
                    self.last_check[source_key] = chromium_time

            conn.close()
        except Exception as e:
            print(f"[BrowserHistory] Error querying Chromium DB: {e}")

        return entries

    def _query_firefox_history(self, db_path: str, browser: str, source_path: str) -> List[Dict]:
        entries = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            source_key = self._db_key(browser, source_path)
            last_timestamp = self.last_check.get(source_key, 0)

            query = """
                SELECT url, title, visit_count, last_visit_date
                FROM moz_places
                WHERE last_visit_date > ?
                ORDER BY last_visit_date DESC
                LIMIT 1000
            """

            cursor.execute(query, (last_timestamp,))

            for url, title, visit_count, firefox_time in cursor.fetchall():
                if firefox_time is None:
                    continue

                unix_timestamp = firefox_time / 1000000.0
                timestamp = datetime.fromtimestamp(unix_timestamp).isoformat()

                if self.allowed_domains and not self._is_allowed_domain(url):
                    continue

                entries.append(
                    {
                        "timestamp": timestamp,
                        "browser": browser,
                        "url": url,
                        "title": title or "(No title)",
                        "visit_count": visit_count,
                        "source_path": source_path,
                    }
                )

                if firefox_time > self.last_check.get(source_key, 0):
                    self.last_check[source_key] = firefox_time

            conn.close()
        except Exception as e:
            print(f"[BrowserHistory] Error querying Firefox DB: {e}")

        return entries

    def _is_allowed_domain(self, url: str) -> bool:
        if not self.allowed_domains:
            return True

        url_lower = url.lower()
        for domain in self.allowed_domains:
            if domain.lower() in url_lower:
                return True

        return False

    def cleanup_temp_files(self):
        try:
            for temp_file in self.temp_dir.glob("*.db"):
                temp_file.unlink(missing_ok=True)
        except Exception as e:
            print(f"[BrowserHistory] Cleanup error: {e}")


def format_for_soc(entry: Dict) -> str:
    """Format browser history entry for SOC platform."""
    url_lower = entry["url"].lower()
    title_lower = entry["title"].lower()
    training_tag = ""

    if any(domain in url_lower or domain in title_lower for domain in TRAINING_DOMAINS):
        training_tag = " TRAINING_PLATFORM=SECURITY_LAB"

    return (
        f"[{entry['timestamp']}] "
        f"Browser={entry['browser']} "
        f"URL={entry['url'][:100]} "
        f"Title=\"{entry['title'][:50]}\""
        f"{training_tag}"
    )


if __name__ == "__main__":
    print(f"[BrowserHistory] Running on {sys.platform}")

    monitor = BrowserHistoryMonitor()

    print("[BrowserHistory] Collecting history...")
    history = monitor.collect_history()

    print(f"[BrowserHistory] Found {len(history)} entries")
    for entry in history[:10]:
        print(format_for_soc(entry))

    monitor.cleanup_temp_files()
    print("[BrowserHistory] Test completed")
