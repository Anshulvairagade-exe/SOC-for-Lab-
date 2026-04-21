import os
import sys
import time
import json
import platform
import socket

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(CURRENT_DIR, "..")
sys.path.append(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)
from shared.logger import get_logger
logger = get_logger("Agent")
from shared.config import (
    MANAGER_HOST,
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
    def __init__(self):
        self.agent_id = os.getenv("AGENT_ID", AGENT_ID)
        self.hostname = os.getenv("AGENT_HOSTNAME", AGENT_HOSTNAME)
        self.manager_host = os.getenv("MANAGER_HOST", "139.59.50.143")
        if self.manager_host == "139.59.50.143":
            self.manager_host = "139.59.50.143"
        self.manager_port = int(os.getenv("MANAGER_PORT", MANAGER_PORT))
        self.send_interval = int(os.getenv("AGENT_SEND_INTERVAL", AGENT_SEND_INTERVAL))
        self.heartbeat_interval = int(os.getenv("AGENT_HEARTBEAT_INTERVAL", AGENT_HEARTBEAT_INTERVAL))
        
        self.os_helper = get_os()
        self.monitors = []
        self.formatters = {}
        
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

    def run(self):
        while True:
            try:
                logger.info(f"Connecting to Manager at {self.manager_host}:{self.manager_port}")
                # Create a secure TLS client socket directly without checking CA identity since self-signed
                with SecureSocket.create_client_socket(self.manager_host, self.manager_port) as sock:
                    sock.settimeout(5.0)
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
                         
                        logger.info(f"Sent {len(logs)} logs")
                        # When we just sent logs, run the next check quickly for near-real-time flow.
                        time.sleep(0.3 if logs else self.send_interval)
            except Exception as e:
                logger.info(f"Connection error: {e}. Retrying in 5s...")
                time.sleep(5)

if __name__ == "__main__":
    agent = Agent()
    agent.run()
