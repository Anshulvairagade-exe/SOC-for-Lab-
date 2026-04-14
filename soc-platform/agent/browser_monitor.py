"""
Cross-platform browser history monitor.
Supports Chrome, Firefox, Edge, and Brave on Windows and Linux.
"""

import glob
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

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
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{db_path}{suffix}")
            if sidecar.exists():
                shutil.copy2(sidecar, Path(f"{temp_db}{suffix}"))
        return temp_db

    def _cleanup_temp_bundle(self, temp_db: Path):
        for suffix in ("", "-wal", "-shm"):
            Path(f"{temp_db}{suffix}").unlink(missing_ok=True)

    def _connect_read_only(self, db_path: str) -> sqlite3.Connection:
        source_uri = f"{Path(db_path).resolve().as_uri()}?mode=ro"
        return sqlite3.connect(source_uri, uri=True, timeout=1)

    def _extract_profile_name(self, source_path: str) -> str:
        source = Path(source_path)
        parent = source.parent.name
        return parent or "Default"

    def _extract_url_metadata(self, url: str, title: str) -> Dict[str, str]:
        metadata: Dict[str, str] = {}

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            domain = re.sub(r"^www\.", "", hostname)
            query_params = parse_qs(parsed.query)
            metadata["domain"] = domain or "unknown"
            metadata["activity"] = "PAGE_VISIT"

            search_query = (
                query_params.get("q", [None])[0]
                or query_params.get("query", [None])[0]
                or query_params.get("search", [None])[0]
                or query_params.get("p", [None])[0]
            )
            if search_query:
                metadata["search_query"] = search_query
                metadata["activity"] = "WEB_SEARCH"

            if domain in {"youtube.com", "m.youtube.com", "youtu.be"}:
                metadata["activity"] = "YOUTUBE_PAGE"
                if domain == "youtu.be":
                    video_id = parsed.path.strip("/")
                    if video_id:
                        metadata["activity"] = "YOUTUBE_VIDEO"
                        metadata["youtube_video_id"] = video_id
                elif parsed.path == "/watch":
                    video_id = query_params.get("v", [None])[0]
                    if video_id:
                        metadata["activity"] = "YOUTUBE_VIDEO"
                        metadata["youtube_video_id"] = video_id
                elif parsed.path.startswith("/shorts/"):
                    video_id = parsed.path.split("/shorts/", 1)[1].split("/", 1)[0]
                    if video_id:
                        metadata["activity"] = "YOUTUBE_SHORT"
                        metadata["youtube_video_id"] = video_id
                elif parsed.path == "/results" and search_query:
                    metadata["activity"] = "YOUTUBE_SEARCH"
        except Exception:
            metadata["domain"] = "unknown"
            metadata["activity"] = "PAGE_VISIT"

        if title:
            metadata["title_hint"] = title[:120]

        return metadata

    def _initialize_baseline(self):
        """Start tracking from the latest entry already present in each history DB."""
        for browser in self.browser_paths.keys():
            for db_path in self._iter_db_paths(browser):
                key = self._db_key(browser, db_path)
                try:
                    if browser in ["chrome", "edge", "brave"]:
                        self.last_check[key] = self._get_latest_chromium_timestamp(db_path)
                    elif browser == "firefox":
                        self.last_check[key] = self._get_latest_firefox_timestamp(db_path)
                    else:
                        self.last_check[key] = 0
                except Exception as e:
                    try:
                        temp_db = self._copy_db_to_temp(browser, db_path)
                        if browser in ["chrome", "edge", "brave"]:
                            self.last_check[key] = self._get_latest_chromium_timestamp(str(temp_db))
                        elif browser == "firefox":
                            self.last_check[key] = self._get_latest_firefox_timestamp(str(temp_db))
                        else:
                            self.last_check[key] = 0
                        self._cleanup_temp_bundle(temp_db)
                    except Exception as copy_exc:
                        print(f"[BrowserHistory] Baseline error for {db_path}: live={e} | copy={copy_exc}")
                        self.last_check[key] = 0

    def _get_latest_chromium_timestamp(self, db_path: str) -> int:
        conn = self._connect_read_only(db_path)
        try:
            row = conn.execute("SELECT MAX(last_visit_time) FROM urls").fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()

    def _get_latest_firefox_timestamp(self, db_path: str) -> int:
        conn = self._connect_read_only(db_path)
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
                if browser in ["chrome", "edge", "brave"]:
                    entries = self._query_chromium_history(db_path, browser, db_path)
                elif browser == "firefox":
                    entries = self._query_firefox_history(db_path, browser, db_path)
                else:
                    entries = []

                history.extend(entries)
            except Exception as live_exc:
                temp_db = None
                try:
                    temp_db = self._copy_db_to_temp(browser, db_path)
                    if browser in ["chrome", "edge", "brave"]:
                        entries = self._query_chromium_history(str(temp_db), browser, db_path)
                    elif browser == "firefox":
                        entries = self._query_firefox_history(str(temp_db), browser, db_path)
                    else:
                        entries = []

                    history.extend(entries)
                except Exception as copy_exc:
                    print(f"[BrowserHistory] Error reading {db_path}: live={live_exc} | copy={copy_exc}")
                finally:
                    if temp_db is not None:
                        self._cleanup_temp_bundle(temp_db)

        return history

    def _query_chromium_history(self, db_path: str, browser: str, source_path: str) -> List[Dict]:
        entries = []
        conn = self._connect_read_only(db_path)
        try:
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
                        "profile": self._extract_profile_name(source_path),
                        "url": url,
                        "title": title or "(No title)",
                        "visit_count": visit_count,
                        "source_path": source_path,
                        **self._extract_url_metadata(url, title or "(No title)"),
                    }
                )

                if chromium_time > self.last_check.get(source_key, 0):
                    self.last_check[source_key] = chromium_time
        finally:
            conn.close()

        return entries

    def _query_firefox_history(self, db_path: str, browser: str, source_path: str) -> List[Dict]:
        entries = []
        conn = self._connect_read_only(db_path)
        try:
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
                        "profile": self._extract_profile_name(source_path),
                        "url": url,
                        "title": title or "(No title)",
                        "visit_count": visit_count,
                        "source_path": source_path,
                        **self._extract_url_metadata(url, title or "(No title)"),
                    }
                )

                if firefox_time > self.last_check.get(source_key, 0):
                    self.last_check[source_key] = firefox_time
        finally:
            conn.close()

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
                self._cleanup_temp_bundle(temp_file)
        except Exception as e:
            print(f"[BrowserHistory] Cleanup error: {e}")


def format_for_soc(entry: Dict) -> str:
    """Format browser history entry for SOC platform."""
    url_lower = entry["url"].lower()
    title_lower = entry["title"].lower()
    training_tag = ""

    if any(domain in url_lower or domain in title_lower for domain in TRAINING_DOMAINS):
        training_tag = " TRAINING_PLATFORM=SECURITY_LAB"

    domain = entry.get("domain", "unknown")
    activity = entry.get("activity", "PAGE_VISIT")
    profile = entry.get("profile", "Default")
    search_query = entry.get("search_query")
    youtube_video_id = entry.get("youtube_video_id")
    extra_parts = [f"Domain={domain}", f"domain:{domain}", f"Profile=\"{profile}\"", f"Activity={activity}"]
    if search_query:
        extra_parts.append(f"SearchQuery=\"{search_query[:200]}\"")
    if youtube_video_id:
        extra_parts.append(f"YouTubeVideoID={youtube_video_id}")

    return (
        f"[{entry['timestamp']}] "
        f"Browser={entry['browser']} "
        f"URL={entry['url']} "
        f"Title=\"{entry['title'][:50]}\""
        f" {' '.join(extra_parts)}"
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
