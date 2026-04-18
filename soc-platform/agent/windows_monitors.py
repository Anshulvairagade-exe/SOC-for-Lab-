"""
Windows-specific monitors for USB, PowerShell, active windows, and processes.
"""

import ctypes
import hashlib
import re
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

if sys.platform == "win32":
    import psutil
    import win32clipboard
    import win32con
    import win32gui
    import win32process

    try:
        import wmi
    except ImportError:
        wmi = None
else:
    psutil = None
    win32clipboard = None
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

SCREENSHOT_PROCESS_NAMES = {
    "greenshot.exe",
    "lightshot.exe",
    "screenclippinghost.exe",
    "screentogif.exe",
    "screensketch.exe",
    "sharex.exe",
    "snagit32.exe",
    "snagitcapture.exe",
    "snagiteditor.exe",
    "snippingtool.exe",
    "mspaint.exe",
    "ms-screenclip.exe",
    "clip.exe",
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

CLIPBOARD_BITMAP_FORMATS = [
    getattr(win32con, "CF_DIBV5", 17) if sys.platform == "win32" else 17,
    win32con.CF_DIB if sys.platform == "win32" else 8,
    win32con.CF_BITMAP if sys.platform == "win32" else 2,
]


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

    def _record_device(self, devices: Dict[str, Dict], device_id: str, values: Dict):
        existing = devices.get(device_id, {})
        merged = {**existing, **values}
        merged["device_id"] = device_id
        merged["description"] = _clean_text(merged.get("description"))
        merged["status"] = _clean_text(merged.get("status"))
        merged["manufacturer"] = _clean_text(merged.get("manufacturer"))
        merged["class"] = _clean_text(merged.get("class"))
        merged["is_storage"] = bool(merged.get("is_storage"))
        devices[device_id] = merged

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
                self._record_device(
                    devices,
                    device_id,
                    {
                    "description": _clean_text(getattr(entity, "Name", None) or getattr(entity, "Description", None)),
                    "status": _clean_text(getattr(entity, "Status", None)),
                    "manufacturer": _clean_text(getattr(entity, "Manufacturer", None)),
                    "class": _clean_text(getattr(entity, "PNPClass", None)),
                    "is_storage": _contains_storage_keywords(
                        getattr(entity, "Name", None),
                        getattr(entity, "Description", None),
                        getattr(entity, "PNPClass", None),
                    ),
                    },
                )
        except Exception as exc:
            errors.append(f"Win32_PnPEntity={exc}")

        try:
            for disk in self.wmi.Win32_DiskDrive(InterfaceType="USB"):
                device_id = _clean_text(getattr(disk, "PNPDeviceID", None) or getattr(disk, "DeviceID", None))
                self._record_device(
                    devices,
                    device_id,
                    {
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
                    },
                )
        except Exception as exc:
            errors.append(f"Win32_DiskDrive={exc}")

        try:
            for volume in self.wmi.Win32_LogicalDisk(DriveType=2):
                drive_letter = _clean_text(getattr(volume, "DeviceID", None))
                device_id = f"LOGICAL::{drive_letter}"
                volume_name = _clean_text(getattr(volume, "VolumeName", None), fallback="")
                description = volume_name if volume_name else drive_letter
                self._record_device(
                    devices,
                    device_id,
                    {
                        "description": f"{description} ({drive_letter})",
                        "status": _clean_text(getattr(volume, "Status", None)),
                        "manufacturer": "LogicalDisk",
                        "class": "LogicalDisk",
                        "is_storage": True,
                        "mount_point": drive_letter,
                        "filesystem": _clean_text(getattr(volume, "FileSystem", None)),
                        "volume_name": volume_name or drive_letter,
                    },
                )
        except Exception as exc:
            errors.append(f"Win32_LogicalDisk={exc}")

        if not devices:
            try:
                for hub in self.wmi.Win32_USBHub():
                    device_id = _clean_text(getattr(hub, "DeviceID", None))
                    self._record_device(
                        devices,
                        device_id,
                        {
                        "description": _clean_text(getattr(hub, "Description", None)),
                        "status": _clean_text(getattr(hub, "Status", None)),
                        "manufacturer": _clean_text(getattr(hub, "Manufacturer", None)),
                        "class": "USBHub",
                        "is_storage": False,
                        },
                    )
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

        appdata = Path(os.getenv("APPDATA", ""))
        self.history_files = [
            appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
            appdata / "Microsoft" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
        ]
        self.file_state: Dict[Path, Dict[str, int]] = {}

        for history_file in self.history_files:
            if history_file.exists():
                stat = history_file.stat()
                self.file_state[history_file] = {
                    "position": stat.st_size,
                    "inode": getattr(stat, "st_ino", 0),
                }

    def collect_new_commands(self) -> List[Dict]:
        """Read new PowerShell commands from history."""
        events = []

        for history_file in self.history_files:
            if not history_file.exists():
                continue

            try:
                stat = history_file.stat()
                state = self.file_state.setdefault(
                    history_file,
                    {"position": 0, "inode": getattr(stat, "st_ino", 0)},
                )

                if state["inode"] and getattr(stat, "st_ino", 0) != state["inode"]:
                    state["position"] = 0
                    state["inode"] = getattr(stat, "st_ino", 0)

                if stat.st_size <= state["position"]:
                    continue

                with open(history_file, "r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(state["position"])
                    new_lines = handle.readlines()
                    state["position"] = handle.tell()

                shell_name = "pwsh" if "Microsoft\\PowerShell" in str(history_file) else "powershell"
                for line in new_lines:
                    line = line.strip()
                    if line:
                        events.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "event_type": "POWERSHELL_COMMAND",
                                "command": line,
                                "shell": shell_name,
                                "history_file": str(history_file),
                            }
                        )
            except Exception as exc:
                print(f"[PowerShell] Error reading {history_file}: {exc}")

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
        self.screenshot_dirs = self._get_screenshot_dirs()
        self.known_screenshot_files = set()
        self.last_clipboard_hash = ""
        self.last_clipboard_sequence = self._get_clipboard_sequence_number()
        self.last_snapshot_key_down = False
        self._baseline_screenshots()

    def _get_screenshot_dirs(self) -> List[Path]:
        user_profile = Path(os.getenv("USERPROFILE", str(Path.home())))
        candidates = [
            user_profile / "Pictures",
            user_profile / "Pictures" / "Screenshots",
            user_profile / "Desktop",
            user_profile / "Downloads",
            user_profile / "OneDrive" / "Pictures" / "Screenshots",
            user_profile / "OneDrive" / "Desktop",
        ]
        return [path for path in candidates if path.exists() and path.is_dir()]

    def _baseline_screenshots(self):
        for directory in self.screenshot_dirs:
            try:
                for file_path in directory.iterdir():
                    if file_path.is_file() and self._looks_like_screenshot(file_path.name):
                        self.known_screenshot_files.add(str(file_path))
            except OSError:
                continue

    def _looks_like_screenshot(self, filename: str) -> bool:
        lowered = filename.lower()
        if not lowered.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
            return False

        patterns = (
            "screen shot",
            "screenshot",
            "screen_capture",
            "screen capture",
            "snip",
            "snipping",
            "capture",
            "clip",
            "image",
        )
        if any(pattern in lowered for pattern in patterns):
            return True

        # Date-time pattern: YYYY-MM-DD HH-MM or similar
        if bool(re.search(r"\d{4}[-_]\d{2}[-_]\d{2}.*\d{2}[-_]\d{2}", lowered)):
            return True

        # Microsoft Snip & Sketch naming: "Screenshot YYYY-MM-DD HHMMSS.png"
        if bool(re.search(r"screenshot\s+\d{4}[-_]\d{2}[-_]\d{2}", lowered)):
            return True

        return False

    def _collect_screenshot_file_events(self) -> List[Dict]:
        events = []
        now = time.time()

        for directory in self.screenshot_dirs:
            try:
                for file_path in directory.iterdir():
                    if not file_path.is_file():
                        continue

                    key = str(file_path)
                    if key in self.known_screenshot_files:
                        continue

                    self.known_screenshot_files.add(key)
                    if not self._looks_like_screenshot(file_path.name):
                        continue

                    try:
                        if now - file_path.stat().st_mtime > 120:
                            continue
                    except OSError:
                        continue

                    print(f"[ProcessMonitor] Screenshot file detected: {file_path.name} in {directory}")
                    events.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "SCREENSHOT_TAKEN",
                            "tool_name": "file_watch",
                            "file_name": file_path.name,
                            "file_path": str(file_path),
                            "detection_method": "file",
                        }
                    )
            except OSError as e:
                print(f"[ProcessMonitor] Error scanning {directory}: {e}")
                continue

        return events

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

    def _get_clipboard_sequence_number(self) -> int:
        try:
            return int(ctypes.windll.user32.GetClipboardSequenceNumber())
        except Exception:
            return 0

    def _get_foreground_window_context(self) -> Dict[str, str]:
        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return {}
            window_title = win32gui.GetWindowText(hwnd).strip()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            process_name = "Unknown"
            try:
                process_name = _clean_text(psutil.Process(pid).name())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            return {
                "window_title": window_title or "(No title)",
                "window_process": process_name,
            }
        except Exception:
            return {}

    def _read_clipboard_image(self) -> tuple[bytes | None, str | None]:
        if win32clipboard is None:
            return None, None

        try:
            win32clipboard.OpenClipboard()
            for fmt in CLIPBOARD_BITMAP_FORMATS:
                if not win32clipboard.IsClipboardFormatAvailable(fmt):
                    continue
                data = win32clipboard.GetClipboardData(fmt)
                if isinstance(data, memoryview):
                    data = data.tobytes()
                if isinstance(data, bytearray):
                    data = bytes(data)
                if isinstance(data, bytes):
                    return data, str(fmt)
                if data:
                    return str(data).encode("utf-8", errors="ignore"), str(fmt)
        except Exception:
            return None, None
        finally:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass

        return None, None

    def _detect_printscreen_hotkey(self) -> List[Dict]:
        try:
            state = ctypes.windll.user32.GetAsyncKeyState(win32con.VK_SNAPSHOT)
            key_down = bool(state & 0x8000)
            was_pressed = bool(state & 0x0001) or (key_down and not self.last_snapshot_key_down)
            self.last_snapshot_key_down = key_down
            if not was_pressed:
                return []

            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "SCREENSHOT_TAKEN",
                "tool_name": "PrintScreen",
                "detection_method": "hotkey",
            }
            event.update(self._get_foreground_window_context())
            return [event]
        except Exception:
            return []

    def _detect_clipboard_screenshot(self) -> List[Dict]:
        sequence_number = self._get_clipboard_sequence_number()
        if not sequence_number or sequence_number == self.last_clipboard_sequence:
            return []

        self.last_clipboard_sequence = sequence_number
        payload, clipboard_format = self._read_clipboard_image()
        if not payload:
            return []

        payload_hash = hashlib.sha1(payload).hexdigest()
        if payload_hash == self.last_clipboard_hash:
            return []

        self.last_clipboard_hash = payload_hash
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SCREENSHOT_TAKEN",
            "tool_name": "clipboard_image",
            "detection_method": "clipboard",
            "clipboard_format": clipboard_format or "unknown",
        }
        event.update(self._get_foreground_window_context())
        return [event]

    def check_new_processes(self) -> List[Dict]:
        """Check for new or terminated processes and emit rule-friendly events."""
        events = []
        current_pids = set()
        screenshot_events = self._detect_printscreen_hotkey()
        events.extend(screenshot_events)

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

                    if process_name in SCREENSHOT_PROCESS_NAMES:
                        screenshot_event = self._build_process_event("SCREENSHOT_TAKEN", proc_info)
                        screenshot_event["tool_name"] = process_name
                        screenshot_event["detection_method"] = "process"
                        events.append(screenshot_event)
                        print(f"[ProcessMonitor] Screenshot detected: {process_name} (PID={pid})")

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

            file_events = self._collect_screenshot_file_events()
            events.extend(file_events)
            if not any(event.get("event_type") == "SCREENSHOT_TAKEN" for event in events):
                events.extend(self._detect_clipboard_screenshot())
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
    mount_point = event.get("mount_point", "")
    descriptor = " ".join([device, manufacturer, device_class]).lower()

    if event["event_type"] == "USB_CONNECTED":
        tokens = ["USB_CONNECT", "USB_ATTACH", "LAB_USB_INSERT"]
        if event.get("is_storage"):
            tokens.extend(["USB_MOUNT", "STORAGE_MOUNTED"])
        if "keyboard" in descriptor:
            tokens.append("USB_KEYBOARD")
        if "mouse" in descriptor:
            tokens.append("USB_MOUSE")
        if "hid" in descriptor and not {"USB_KEYBOARD", "USB_MOUSE"} & set(tokens):
            tokens.append("USB_HID_UNKNOWN")
        if "mtp" in descriptor:
            tokens.append("MTP_CONNECT")
        if "android" in descriptor:
            tokens.append("ANDROID_MOUNT")
        if "iphone" in descriptor or "ios" in descriptor or "apple mobile" in descriptor:
            tokens.append("IOS_MOUNT")
        detail_parts = [
            f"Device={device}",
            f"DeviceID={device_id}",
            f"Manufacturer={manufacturer}",
            f"Class={device_class}",
            f"Status={status}",
        ]
        if mount_point:
            detail_parts.append(f"MountPoint={mount_point}")
        return (
            f"{' '.join(tokens)}: USB device inserted | "
            + " | ".join(detail_parts)
        )

    return (
        "USB_DISCONNECT LAB_USB_REMOVE: USB device removed | "
        f"Device={device} | DeviceID={device_id} | Manufacturer={manufacturer} | "
        f"Class={device_class}"
    )


def format_powershell_event(event: Dict) -> str:
    """Format PowerShell command for logging."""
    shell = event.get("shell", "powershell")
    history_file = event.get("history_file", "unknown")
    return (
        "TERMINAL_COMMAND POWERSHELL_COMMAND: Terminal command captured | "
        f"Shell={shell} | Command=\"{event['command']}\" | HistoryFile=\"{history_file}\""
    )


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

    if event["event_type"] == "SCREENSHOT_TAKEN":
        tokens = "SCREENSHOT PRINTSCREEN SNIP_TOOL"
        details = [
            f"Tool={event.get('tool_name', event.get('name', 'unknown'))}",
            f"Method={event.get('detection_method', 'process')}",
        ]
        if event.get("pid"):
            details.append(f"PID={event['pid']}")
        if event.get("file_name"):
            details.append(f"File=\"{event['file_name']}\"")
        if event.get("file_path"):
            details.append(f"Path=\"{event['file_path']}\"")
        if event.get("cmdline"):
            details.append(f"Cmdline=\"{event['cmdline']}\"")
        if event.get("window_process"):
            details.append(f"WindowProcess=\"{event['window_process']}\"")
        if event.get("window_title"):
            details.append(f"WindowTitle=\"{event['window_title']}\"")
        if event.get("clipboard_format"):
            details.append(f"ClipboardFormat={event['clipboard_format']}")
        return f"{tokens}: Screenshot activity detected | " + " | ".join(details)

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
