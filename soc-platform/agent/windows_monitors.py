"""
Windows-specific monitors for USB, PowerShell, active windows, and processes.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

if sys.platform == "win32":
    import psutil
    import win32con
    import win32gui
    import win32process

    try:
        import wmi
    except ImportError:
        wmi = None
else:
    psutil = None
    wmi = None


TERMINAL_PROCESS_NAMES = {
    "cmd.exe",
    "conhost.exe",
    "powershell.exe",
    "pwsh.exe",
    "windows terminal.exe",
    "wt.exe",
    "bash.exe",
    "wsl.exe",
}

SUSPICIOUS_PROCESS_NAMES = {
    "anydesk.exe",
    "filezilla.exe",
    "procexp.exe",
    "procmon.exe",
    "putty.exe",
    "teamviewer.exe",
    "wireshark.exe",
    "winscp.exe",
    "xftp.exe",
}

APPLICATION_CATEGORY_RULES = {
    "TERMINAL": {"cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "wt.exe", "windows terminal.exe", "bash.exe", "wsl.exe"},
    "BROWSER": {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"},
    "COMMUNICATION": {"discord.exe", "telegram.exe", "slack.exe", "teams.exe", "whatsapp.exe", "zoom.exe"},
    "GAMING": {"steam.exe", "epicgameslauncher.exe", "riotclientservices.exe", "riotclientux.exe", "valorant.exe", "robloxplayerbeta.exe", "minecraft.exe"},
    "DEVELOPMENT": {"code.exe", "pycharm64.exe", "idea64.exe", "sublime_text.exe", "notepad++.exe"},
    "REMOTE_ACCESS": {"anydesk.exe", "teamviewer.exe", "winscp.exe", "putty.exe", "filezilla.exe"},
}

SUSPICIOUS_WINDOW_KEYWORDS = {
    "brainly",
    "chegg",
    "course hero",
    "discord",
    "facebook",
    "instagram",
    "minecraft",
    "netflix",
    "prime video",
    "pubg",
    "quizlet",
    "reddit",
    "roblox",
    "steam",
    "telegram",
    "tiktok",
    "twitter",
    "whatsapp",
    "youtube",
}


def _clean_text(value: Optional[str], fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    return text or fallback


def _contains_storage_keywords(*values: Optional[str]) -> bool:
    haystack = " ".join(str(value or "").lower() for value in values)
    return any(
        keyword in haystack
        for keyword in (
            "storage",
            "mass",
            "disk",
            "flash",
            "thumb",
            "pendrive",
            "removable",
            "volume",
        )
    )


def _categorize_application(process_name: Optional[str], window_title: Optional[str] = None) -> str:
    process_lower = str(process_name or "").lower()
    title_lower = str(window_title or "").lower()

    for category, names in APPLICATION_CATEGORY_RULES.items():
        if process_lower in names:
            return category

    if any(keyword in title_lower for keyword in SUSPICIOUS_WINDOW_KEYWORDS):
        return "OFFTASK_WINDOW"

    return "GENERAL"


class WindowsUSBMonitor:
    """Monitor USB device connections using multiple WMI views."""

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("WindowsUSBMonitor only works on Windows")
        if wmi is None:
            raise RuntimeError("WMI library not installed. Install with: pip install wmi")

        self.wmi = wmi.WMI()
        self.known_devices, errors = self._get_connected_devices()
        if errors and not self.known_devices:
            raise RuntimeError(f"WMI USB access failed: {' | '.join(errors)}")

    def _get_connected_devices(self) -> tuple[Dict[str, Dict], List[str]]:
        devices: Dict[str, Dict] = {}
        errors: List[str] = []

        try:
            for entity in self.wmi.query(
                "SELECT DeviceID, PNPDeviceID, Name, Description, Manufacturer, Status, PNPClass "
                "FROM Win32_PnPEntity "
                "WHERE PNPDeviceID LIKE 'USB%' OR PNPClass = 'USB'"
            ):
                device_id = _clean_text(getattr(entity, "PNPDeviceID", None) or getattr(entity, "DeviceID", None))
                devices[device_id] = {
                    "device_id": device_id,
                    "description": _clean_text(getattr(entity, "Name", None) or getattr(entity, "Description", None)),
                    "status": _clean_text(getattr(entity, "Status", None)),
                    "manufacturer": _clean_text(getattr(entity, "Manufacturer", None)),
                    "class": _clean_text(getattr(entity, "PNPClass", None)),
                    "is_storage": _contains_storage_keywords(
                        getattr(entity, "Name", None),
                        getattr(entity, "Description", None),
                        getattr(entity, "PNPClass", None),
                    ),
                }
        except Exception as exc:
            errors.append(f"Win32_PnPEntity={exc}")

        try:
            for disk in self.wmi.Win32_DiskDrive(InterfaceType="USB"):
                device_id = _clean_text(getattr(disk, "PNPDeviceID", None) or getattr(disk, "DeviceID", None))
                devices[device_id] = {
                    "device_id": device_id,
                    "description": _clean_text(
                        getattr(disk, "Caption", None)
                        or getattr(disk, "Model", None)
                        or getattr(disk, "Name", None)
                    ),
                    "status": _clean_text(getattr(disk, "Status", None)),
                    "manufacturer": _clean_text(getattr(disk, "Manufacturer", None)),
                    "class": "DiskDrive",
                    "is_storage": True,
                    "size_bytes": int(getattr(disk, "Size", 0) or 0),
                    "media_type": _clean_text(getattr(disk, "MediaType", None)),
                }
        except Exception as exc:
            errors.append(f"Win32_DiskDrive={exc}")

        if not devices:
            try:
                for hub in self.wmi.Win32_USBHub():
                    device_id = _clean_text(getattr(hub, "DeviceID", None))
                    devices[device_id] = {
                        "device_id": device_id,
                        "description": _clean_text(getattr(hub, "Description", None)),
                        "status": _clean_text(getattr(hub, "Status", None)),
                        "manufacturer": _clean_text(getattr(hub, "Manufacturer", None)),
                        "class": "USBHub",
                        "is_storage": False,
                    }
            except Exception as exc:
                errors.append(f"Win32_USBHub={exc}")

        return devices, errors

    def check_new_devices(self) -> List[Dict]:
        """Check for newly inserted or removed USB devices."""
        events = []

        try:
            current_devices, errors = self._get_connected_devices()
            if errors and not current_devices:
                raise RuntimeError(" | ".join(errors))

            for device_id, device in current_devices.items():
                if device_id not in self.known_devices:
                    events.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "USB_CONNECTED",
                            **device,
                        }
                    )

            for device_id, device in self.known_devices.items():
                if device_id not in current_devices:
                    events.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "USB_DISCONNECTED",
                            **device,
                        }
                    )

            self.known_devices = current_devices
        except Exception as exc:
            print(f"[WindowsUSB] Error checking devices: {exc}")

        return events


class WindowsPowerShellMonitor:
    """Monitor PowerShell command history."""

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("WindowsPowerShellMonitor only works on Windows")

        appdata = os.getenv("APPDATA", "")
        self.history_file = Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        self.last_position = 0
        self.last_inode = None

        if self.history_file.exists():
            self.last_position = self.history_file.stat().st_size
            self.last_inode = self.history_file.stat().st_ino

    def collect_new_commands(self) -> List[Dict]:
        """Read new PowerShell commands from history."""
        events = []

        if not self.history_file.exists():
            return events

        try:
            stat = self.history_file.stat()

            if self.last_inode is not None and stat.st_ino != self.last_inode:
                self.last_position = 0
                self.last_inode = stat.st_ino

            if stat.st_size > self.last_position:
                with open(self.history_file, "r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(self.last_position)
                    new_lines = handle.readlines()
                    self.last_position = handle.tell()

                for line in new_lines:
                    line = line.strip()
                    if line:
                        events.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "event_type": "POWERSHELL_COMMAND",
                                "command": line,
                            }
                        )
        except Exception as exc:
            print(f"[PowerShell] Error reading history: {exc}")

        return events


class WindowsActiveWindowMonitor:
    """Monitor active window and classify off-task applications."""

    def __init__(self, check_interval: int = 5):
        if sys.platform != "win32":
            raise RuntimeError("WindowsActiveWindowMonitor only works on Windows")

        self.check_interval = max(1, check_interval)
        self.last_window = None
        self.last_check = 0.0

    def get_active_window(self) -> Optional[Dict]:
        """Get the current foreground window information."""
        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd == 0:
                return None

            window_title = win32gui.GetWindowText(hwnd).strip()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)

            process_name = "Unknown"
            process_exe = "Unknown"
            username = "Unknown"
            cmdline = ""
            try:
                process = psutil.Process(pid)
                process_name = _clean_text(process.name())
                process_exe = _clean_text(process.exe())
                username = _clean_text(process.username())
                cmdline = " ".join(process.cmdline() or [])[:180]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            title_lower = window_title.lower()
            process_lower = process_name.lower()
            suspicious_keywords = sorted(
                keyword
                for keyword in SUSPICIOUS_WINDOW_KEYWORDS
                if keyword in title_lower or keyword in process_lower
            )
            app_category = _categorize_application(process_name, window_title)

            return {
                "timestamp": datetime.now().isoformat(),
                "event_type": "WINDOW_FOCUS_CHANGED",
                "window_title": window_title or "(No title)",
                "process_name": process_name,
                "process_exe": process_exe,
                "username": username,
                "pid": pid,
                "cmdline": cmdline,
                "is_suspicious": bool(suspicious_keywords),
                "matched_keywords": suspicious_keywords,
                "app_category": app_category,
            }
        except Exception as exc:
            print(f"[ActiveWindow] Error: {exc}")
            return None

    def check_window_change(self) -> Optional[Dict]:
        """Return an event when the active application changes."""
        now = time.time()
        if now - self.last_check < self.check_interval:
            return None

        self.last_check = now
        current = self.get_active_window()
        if current is None:
            return None

        current_key = (current["window_title"], current["process_name"], current["pid"])
        if self.last_window == current_key:
            return None

        self.last_window = current_key
        return current


class WindowsProcessMonitor:
    """Monitor process creation/termination and classify application activity."""

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("WindowsProcessMonitor only works on Windows")

        self.known_pids = {proc.pid for proc in psutil.process_iter(["pid"])}

    def _build_process_event(self, event_type: str, proc_info: Dict) -> Dict:
        create_time = proc_info.get("create_time") or 0
        start_time = datetime.fromtimestamp(create_time).isoformat() if create_time else ""
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "pid": proc_info.get("pid"),
            "name": _clean_text(proc_info.get("name")),
            "exe": _clean_text(proc_info.get("exe")),
            "username": _clean_text(proc_info.get("username")),
            "start_time": start_time,
            "cmdline": " ".join(proc_info.get("cmdline") or [])[:180],
        }

    def check_new_processes(self) -> List[Dict]:
        """Check for new or terminated processes and emit rule-friendly events."""
        events = []
        current_pids = set()

        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time", "cmdline"]):
                try:
                    proc_info = proc.info
                    pid = proc_info["pid"]
                    current_pids.add(pid)

                    if pid in self.known_pids:
                        continue

                    process_name = _clean_text(proc_info.get("name")).lower()
                    events.append(self._build_process_event("PROCESS_STARTED", proc_info))
                    app_category = _categorize_application(proc_info.get("name"))
                    if app_category != "GENERAL":
                        app_event = self._build_process_event("APPLICATION_ANALYSIS", proc_info)
                        app_event["app_category"] = app_category
                        if app_category in {"COMMUNICATION", "GAMING", "REMOTE_ACCESS"}:
                            app_event["offtask"] = True
                        events.append(app_event)

                    if process_name in TERMINAL_PROCESS_NAMES:
                        events.append(self._build_process_event("TERMINAL_OPENED", proc_info))

                    if process_name in SUSPICIOUS_PROCESS_NAMES:
                        suspicious_event = self._build_process_event("SUSPICIOUS_PROCESS", proc_info)
                        suspicious_event["reason"] = "matched_watchlist"
                        events.append(suspicious_event)

                    self.known_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            terminated = self.known_pids - current_pids
            for pid in terminated:
                events.append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "PROCESS_TERMINATED",
                        "pid": pid,
                    }
                )
                self.known_pids.remove(pid)
        except Exception as exc:
            print(f"[ProcessMonitor] Error: {exc}")

        return events


def format_usb_event(event: Dict) -> str:
    """Format USB event for logging and rule matching."""
    device = event.get("description", "Unknown USB Device")
    device_id = event.get("device_id", "Unknown")
    manufacturer = event.get("manufacturer", "Unknown")
    status = event.get("status", "Unknown")
    device_class = event.get("class", "Unknown")

    if event["event_type"] == "USB_CONNECTED":
        tokens = ["USB_CONNECT", "LAB_USB_INSERT"]
        if event.get("is_storage"):
            tokens.append("STORAGE_MOUNTED")
        return (
            f"{' '.join(tokens)}: USB device inserted | "
            f"Device={device} | DeviceID={device_id} | Manufacturer={manufacturer} | "
            f"Class={device_class} | Status={status}"
        )

    return (
        "USB_DISCONNECT LAB_USB_REMOVE: USB device removed | "
        f"Device={device} | DeviceID={device_id} | Manufacturer={manufacturer} | "
        f"Class={device_class}"
    )


def format_powershell_event(event: Dict) -> str:
    """Format PowerShell command for logging."""
    return f"POWERSHELL_COMMAND: PowerShell history captured | Command={event['command']}"


def format_window_event(event: Dict) -> str:
    """Format window change event."""
    base = (
        f"WINDOW_FOCUS_CHANGED APP_ANALYSIS: Application focus changed | "
        f"WindowTitle={event['window_title']} | Process={event['process_name']} | "
        f"PID={event['pid']} | User={event.get('username', 'Unknown')} | "
        f"Category={event.get('app_category', 'GENERAL')}"
    )
    if event.get("is_suspicious"):
        keywords = ",".join(event.get("matched_keywords", [])) or "unknown"
        return f"{base} | SUSPICIOUS_WINDOW OFFTASK_APPLICATION | Matched={keywords}"
    return base


def format_process_event(event: Dict) -> str:
    """Format process event."""
    if event["event_type"] == "PROCESS_STARTED":
        return (
            f"PROCESS_STARTED: Running process detected | "
            f"Name={event['name']} | PID={event['pid']} | User={event.get('username', 'Unknown')} | "
            f"Path={event.get('exe', 'Unknown')} | Cmdline={event.get('cmdline', '')}"
        )

    if event["event_type"] == "TERMINAL_OPENED":
        return (
            f"TERMINAL_OPENED: Terminal application started | "
            f"Name={event['name']} | PID={event['pid']} | User={event.get('username', 'Unknown')} | "
            f"Cmdline={event.get('cmdline', '')}"
        )

    if event["event_type"] == "APPLICATION_ANALYSIS":
        off_task_token = " OFFTASK_APPLICATION" if event.get("offtask") else ""
        return (
            f"APPLICATION_ANALYSIS{off_task_token}: Application started | "
            f"Name={event['name']} | PID={event['pid']} | User={event.get('username', 'Unknown')} | "
            f"Category={event.get('app_category', 'GENERAL')} | Path={event.get('exe', 'Unknown')}"
        )

    if event["event_type"] == "SUSPICIOUS_PROCESS":
        return (
            f"SUSPICIOUS_PROCESS: Watchlist application started | "
            f"Name={event['name']} | PID={event['pid']} | User={event.get('username', 'Unknown')} | "
            f"Path={event.get('exe', 'Unknown')} | Reason={event.get('reason', 'watchlist')}"
        )

    return f"PROCESS_TERMINATED: Process ended | PID={event['pid']}"


if __name__ == "__main__":
    if sys.platform != "win32":
        print("This module only works on Windows")
        sys.exit(1)

    print("[WindowsMonitors] Testing monitors...")

    ps_monitor = WindowsPowerShellMonitor()
    cmds = ps_monitor.collect_new_commands()
    print(f"\n[PowerShell] Recent commands: {len(cmds)}")
    for cmd in cmds[-5:]:
        print(f"  {format_powershell_event(cmd)}")

    win_monitor = WindowsActiveWindowMonitor()
    current = win_monitor.get_active_window()
    if current:
        print(f"\n[ActiveWindow] Current: {current['window_title']} ({current['process_name']})")

    if wmi:
        usb_monitor = WindowsUSBMonitor()
        print(f"\n[USB] Known devices: {len(usb_monitor.known_devices)}")

    print("\n[WindowsMonitors] All tests completed")
