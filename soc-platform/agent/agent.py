import os
import sys
import time
import json
import platform
import socket
import psutil

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(CURRENT_DIR, "..")
sys.path.append(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)
from shared.logger import get_logger
logger = get_logger("Agent")
from shared.config import (
    MANAGER_HOST,
    AGENT_MANAGER_HOST,
    MANAGER_PORT,
    AGENT_ID,
    AGENT_HOSTNAME,
    AGENT_SEND_INTERVAL,
    AGENT_HEARTBEAT_INTERVAL,
)
from shared.models import LogEvent
from shared.os_abstraction import get_os
from shared.security import SecureSocket

# --- Platform-conditional imports (no cross-contamination) ---
_PLATFORM = platform.system()   # 'Windows' | 'Linux' | 'Darwin'

if _PLATFORM == "Windows":
    import browser_monitor
    import windows_eventlog
    import windows_monitors
elif _PLATFORM == "Darwin":
    import mac_monitor          # macOS-specific monitors
else:  # Linux / other
    import student_monitor      # Linux student activity monitor

def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


class Agent:
    TERMINATE_TARGETS = {"chrome", "firefox", "brave", "terminal"}

    def __init__(self):
        self.agent_id = os.getenv("AGENT_ID", AGENT_ID)
        self.hostname = os.getenv("AGENT_HOSTNAME", AGENT_HOSTNAME)
        self.manager_host = os.getenv("AGENT_MANAGER_HOST", AGENT_MANAGER_HOST)
        if not self.manager_host:
            self.manager_host = MANAGER_HOST
        self.manager_port = int(os.getenv("MANAGER_PORT", MANAGER_PORT))
        self.send_interval = int(os.getenv("AGENT_SEND_INTERVAL", AGENT_SEND_INTERVAL))
        self.heartbeat_interval = int(os.getenv("AGENT_HEARTBEAT_INTERVAL", AGENT_HEARTBEAT_INTERVAL))
        
        self.os_helper = get_os()
        self.monitors = []
        self.formatters = {}
        self._command_buffer = ""
        
        logger.info(f"Starting | ID={self.agent_id} | Host={self.hostname}")
        self._init_monitors()

    def _init_monitors(self):
        if _PLATFORM == "Windows":
            try:
                self.monitors.append(("WINDOWS_EVENT", windows_eventlog.WindowsEventLogMonitor(["System", "Security", "Application"])))
                self.formatters["WINDOWS_EVENT"] = windows_eventlog.format_for_soc
                logger.info("[INIT] WINDOWS_EVENT monitor initialized")
                
                if _env_flag("MONITOR_USB_DEVICES", True):
                    try:
                        self.monitors.append(("USB", windows_monitors.WindowsUSBMonitor()))
                        self.formatters["USB"] = windows_monitors.format_usb_event
                        logger.info("[INIT] USB monitor initialized")
                    except Exception as e:
                        logger.info(f"[INIT] USB monitor skipped: {e}")
                    
                if _env_flag("MONITOR_SHELL_COMMANDS", True):
                    try:
                        self.monitors.append(("POWERSHELL", windows_monitors.WindowsPowerShellMonitor()))
                        self.formatters["POWERSHELL"] = windows_monitors.format_powershell_event
                        logger.info("[INIT] POWERSHELL monitor initialized")
                    except Exception as e:
                        logger.info(f"[INIT] POWERSHELL monitor failed: {e}")
                
                if _env_flag("MONITOR_ACTIVE_WINDOW", True):
                    try:
                        self.monitors.append(("WINDOW", windows_monitors.WindowsActiveWindowMonitor(check_interval=self.send_interval)))
                        self.formatters["WINDOW"] = windows_monitors.format_window_event
                        logger.info("[INIT] WINDOW monitor initialized")
                    except Exception as e:
                        logger.info(f"[INIT] WINDOW monitor failed: {e}")
                
                if _env_flag("MONITOR_PROCESSES", True):
                    try:
                        self.monitors.append(("PROCESS", windows_monitors.WindowsProcessMonitor()))
                        self.formatters["PROCESS"] = windows_monitors.format_process_event
                        logger.info("[INIT] PROCESS monitor initialized (screenshot/app detection)")
                    except Exception as e:
                        logger.info(f"[INIT] PROCESS monitor failed: {e}")
                
                if _env_flag("MONITOR_BROWSER_HISTORY", True):
                    try:
                        self.monitors.append(("BROWSER", browser_monitor.BrowserHistoryMonitor(allowed_domains=_env_csv("BROWSER_ALLOWED_DOMAINS"))))
                        self.formatters["BROWSER"] = browser_monitor.format_for_soc
                        logger.info("[INIT] BROWSER monitor initialized")
                    except Exception as e:
                        logger.info(f"[INIT] BROWSER monitor failed: {e}")
                logger.info(f"[INIT] Windows monitors summary: {len(self.monitors)} monitors active")
            except Exception as e:
                logger.error(f"Critical error initializing Windows monitors: {e}", exc_info=True)
        elif _PLATFORM == "Darwin":
            # macOS — use native macOS monitor (mac_monitor.py)
            try:
                self.monitors.append(("MacStudent", mac_monitor.MacStudentActivityMonitor()))
            except Exception as e:
                logger.info(f"Error initializing macOS monitors: {e}")
        else:
            # Linux / other — use student_monitor.py (unchanged)
            try:
                self.monitors.append(("Student", student_monitor.StudentActivityMonitor()))
            except Exception as e:
                logger.info(f"Error initializing Student monitor: {e}")

    def collect_logs(self):
        logs = []
        for name, monitor in self.monitors:
            try:
                if name == "WINDOWS_EVENT":
                    for e in monitor.collect_new_events():
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
                elif name == "USB":
                    for e in monitor.check_new_devices():
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
                elif name == "POWERSHELL":
                    for e in monitor.collect_new_commands():
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
                elif name == "WINDOW":
                    e = monitor.check_window_change()
                    if e:
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
                elif name == "PROCESS":
                    for e in monitor.check_new_processes():
                        source_name = "SCREENSHOT" if e.get("event_type") == "SCREENSHOT_TAKEN" else name
                        logs.append(LogEvent(self.agent_id, self.hostname, source_name, self.formatters[name](e)))
                elif name == "BROWSER":
                    for e in monitor.collect_history():
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
                elif name == "Student" or name == "MacStudent":
                    for source, event in monitor.collect():
                        logs.append(LogEvent(self.agent_id, self.hostname, source, event))
            except Exception as e:
                logger.info(f"Monitor {name} error: {e}")
        return logs

    def _target_patterns(self, target: str) -> list[str]:
        if target == "chrome":
            if _PLATFORM == "Windows":
                return ["chrome.exe", "chrome"]
            if _PLATFORM == "Darwin":
                return ["google chrome", "google chrome helper", "chrome", "chromium"]
            return ["chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]
        if target == "firefox":
            if _PLATFORM == "Windows":
                return ["firefox.exe", "firefox"]
            if _PLATFORM == "Darwin":
                return ["firefox", "firefox helper", "firefox-bin"]
            return ["firefox", "firefox-bin"]
        if target == "brave":
            if _PLATFORM == "Windows":
                return ["brave.exe", "brave"]
            if _PLATFORM == "Darwin":
                return ["brave browser", "brave browser helper", "brave"]
            return ["brave", "brave-browser", "brave-browser-stable"]
        if target == "terminal":
            if _PLATFORM == "Windows":
                return [
                    "cmd.exe", "cmd",
                    "powershell.exe", "powershell",
                    "pwsh.exe", "pwsh",
                    "wt.exe", "wt",
                    "windowsterminal.exe", "windowsterminal",
                ]
            if _PLATFORM == "Darwin":
                return [
                    "terminal", "terminal helper",
                    "iterm2", "itermserver",
                    "warp", "warp-terminal",
                    "alacritty", "kitty", "hyper",
                ]
            return [
                "gnome-terminal", "gnome-terminal-server", "xterm", "konsole",
                "xfce4-terminal", "tilix", "alacritty", "kitty", "kgx", "mate-terminal",
                "lxterminal", "terminator", "ptyxis", "guake", "deepin-terminal",
            ]
        return []

    def _target_matchers(self, target: str) -> set[str]:
        return {pattern.lower() for pattern in self._target_patterns(target)}

    def _normalized_name_variants(self, raw_value: str | None) -> set[str]:
        raw = str(raw_value or "").strip()
        if not raw:
            return set()

        normalized = raw.replace("\\", "/").strip().lower()
        variants = {normalized}
        if "/" in normalized:
            variants.add(normalized.rsplit("/", 1)[-1])

        expanded: set[str] = set()
        for value in variants:
            clean = value.strip()
            if not clean:
                continue
            if clean.endswith(".app"):
                clean = clean[:-4]
            expanded.add(clean)
            if clean.endswith(".exe"):
                expanded.add(clean[:-4])
        return expanded

    def _process_identity_names(self, proc: psutil.Process) -> set[str]:
        info = proc.info if isinstance(getattr(proc, "info", None), dict) else {}
        identities: set[str] = set()

        for key in ("name", "exe"):
            identities.update(self._normalized_name_variants(info.get(key)))

        try:
            identities.update(self._normalized_name_variants(proc.name()))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        try:
            identities.update(self._normalized_name_variants(proc.exe()))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return identities

    def _process_matches_target(self, proc: psutil.Process, target: str) -> bool:
        matchers = self._target_matchers(target)
        if not matchers:
            return False

        identities = self._process_identity_names(proc)
        if not identities:
            return False

        for matcher in matchers:
            for identity in identities:
                if identity == matcher or identity.startswith(f"{matcher} "):
                    return True
        return False

    def _select_target_process(self, target: str) -> psutil.Process | None:
        candidates: list[tuple[int, float, int, psutil.Process]] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            try:
                if proc.pid in {0, 1, os.getpid(), os.getppid()}:
                    continue
                if not self._process_matches_target(proc, target):
                    continue
                parent_matches = False
                try:
                    parent = proc.parent()
                    parent_matches = bool(parent and self._process_matches_target(parent, target))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    parent_matches = False
                descendants = 0
                try:
                    descendants = len(proc.children(recursive=True))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    descendants = 0
                candidates.append((
                    0 if not parent_matches else 1,
                    -float(proc.info.get("create_time") or 0.0),
                    -descendants,
                    proc,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][3]

    def _terminate_process_tree(self, proc: psutil.Process) -> tuple[bool, str]:
        try:
            root_name = proc.name()
            root_pid = proc.pid
            descendants = proc.children(recursive=True)
            targets = descendants + [proc]
            denied_pids: set[int] = set()
            for item in targets:
                try:
                    item.terminate()
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except psutil.AccessDenied:
                    denied_pids.add(item.pid)

            _, alive = psutil.wait_procs(targets, timeout=3)
            for item in alive:
                try:
                    item.kill()
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except psutil.AccessDenied:
                    denied_pids.add(item.pid)
            if alive:
                psutil.wait_procs(alive, timeout=2)

            try:
                root_alive = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                root_alive = False
            except psutil.AccessDenied:
                root_alive = False

            if root_alive:
                return False, f"Failed to terminate {root_name} (PID {root_pid}). Permission denied."

            message = f"Terminated {root_name} (PID {root_pid})."
            if denied_pids:
                denied_list = ", ".join(str(pid) for pid in sorted(denied_pids))
                message = f"{message} Some child processes could not be terminated (PID(s): {denied_list})."
            return True, message
        except psutil.NoSuchProcess:
            return False, "The selected process is no longer running."
        except Exception as e:
            return False, f"Failed to terminate process: {e}"

    def _terminate_processes(self, target: str, pid: int | None = None) -> tuple[bool, str]:
        if not self._target_patterns(target):
            return False, f"Unsupported process target: {target}"

        if pid is not None:
            try:
                proc = psutil.Process(pid)
            except psutil.NoSuchProcess:
                return False, f"Process PID {pid} is no longer running."
            except Exception as e:
                return False, f"Unable to inspect PID {pid}: {e}"

            if not self._process_matches_target(proc, target):
                return False, f"PID {pid} does not match target '{target}'."
            return self._terminate_process_tree(proc)

        proc = self._select_target_process(target)
        if proc is None:
            return False, f"No running '{target}' process found."
        success, message = self._terminate_process_tree(proc)
        if success:
            return True, f"{message} No other matching {target} instances were touched."
        return False, message

    def _handle_manager_command(self, command: dict) -> dict:
        command_id = command.get("command_id")
        action = str(command.get("action") or "").strip()
        payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}

        if action != "terminate_process":
            return {
                "type": "command_result",
                "command_id": command_id,
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "action": action,
                "success": False,
                "result_message": f"Unsupported action: {action}",
                "timestamp": time.time(),
            }

        target = str(payload.get("process_name") or "").strip().lower()
        if target not in self.TERMINATE_TARGETS:
            return {
                "type": "command_result",
                "command_id": command_id,
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "action": action,
                "success": False,
                "result_message": "Invalid process target.",
                "timestamp": time.time(),
            }

        pid = payload.get("pid")
        if pid is not None:
            try:
                pid = int(pid)
                if pid <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                pid = None

        success, message = self._terminate_processes(target, pid=pid)
        logger.info(f"Command result | id={command_id} | action={action} | success={success} | message={message}")
        return {
            "type": "command_result",
            "command_id": command_id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "action": action,
            "success": success,
            "result_message": message,
            "timestamp": time.time(),
        }

    def _drain_manager_commands(self, sock: socket.socket):
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break

            if not data:
                raise ConnectionError("Manager disconnected")

            self._command_buffer += data.decode("utf-8", errors="ignore")
            while "\n" in self._command_buffer:
                line, self._command_buffer = self._command_buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    command = json.loads(line)
                except Exception as e:
                    logger.info(f"Ignoring malformed manager message: {e}")
                    continue
                if command.get("type") != "command":
                    continue
                result = self._handle_manager_command(command)
                sock.sendall((json.dumps(result) + "\n").encode("utf-8"))

    def run(self):
        while True:
            try:
                logger.info(f"Connecting to Manager at {self.manager_host}:{self.manager_port}")
                # Create a secure TLS client socket directly without checking CA identity since self-signed
                with SecureSocket.create_client_socket(self.manager_host, self.manager_port) as sock:
                    sock.settimeout(0.5)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    logger.info(f"Connected.")
                    last_heartbeat = 0.0
                    while True:
                        logs = self.collect_logs()

                        now = time.time()
                        if now - last_heartbeat >= self.heartbeat_interval:
                            heartbeat = {"type": "heartbeat", "agent_id": self.agent_id, "hostname": self.hostname}
                            sock.sendall((json.dumps(heartbeat) + "\n").encode("utf-8"))
                            last_heartbeat = now
                         
                        for log in logs:
                            sock.sendall((json.dumps(log.to_dict()) + "\n").encode("utf-8"))
                        self._drain_manager_commands(sock)

                        logger.info(f"Sent {len(logs)} logs")
                        # When we just sent logs, run the next check quickly for near-real-time flow.
                        time.sleep(0.3 if logs else self.send_interval)
            except Exception as e:
                logger.info(f"Connection error: {e}. Retrying in 5s...")
                time.sleep(5)

if __name__ == "__main__":
    agent = Agent()
    agent.run()
