import os
import sys
import time
import json
import platform

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(CURRENT_DIR, "..")
sys.path.append(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)
from shared.logger import get_logger
logger = get_logger("Agent")
from shared.config import MANAGER_HOST, MANAGER_PORT, AGENT_ID, AGENT_HOSTNAME, AGENT_SEND_INTERVAL
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
        self.manager_host = os.getenv("MANAGER_HOST", "127.0.0.1")
        if self.manager_host == "0.0.0.0":
            self.manager_host = "127.0.0.1"
        self.manager_port = int(os.getenv("MANAGER_PORT", MANAGER_PORT))
        self.send_interval = int(os.getenv("AGENT_SEND_INTERVAL", AGENT_SEND_INTERVAL))
        
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
                
                if _env_flag("MONITOR_USB_DEVICES", True):
                    try:
                        self.monitors.append(("USB", windows_monitors.WindowsUSBMonitor()))
                        self.formatters["USB"] = windows_monitors.format_usb_event
                    except Exception:
                        logger.info("WMI not running or unavailable. USB monitor skipped.")
                        pass
                    
                if _env_flag("MONITOR_SHELL_COMMANDS", True):
                    self.monitors.append(("POWERSHELL", windows_monitors.WindowsPowerShellMonitor()))
                    self.formatters["POWERSHELL"] = windows_monitors.format_powershell_event
                
                if _env_flag("MONITOR_ACTIVE_WINDOW", True):
                    self.monitors.append(("WINDOW", windows_monitors.WindowsActiveWindowMonitor(check_interval=self.send_interval)))
                    self.formatters["WINDOW"] = windows_monitors.format_window_event
                
                if _env_flag("MONITOR_PROCESSES", True):
                    self.monitors.append(("PROCESS", windows_monitors.WindowsProcessMonitor()))
                    self.formatters["PROCESS"] = windows_monitors.format_process_event
                
                if _env_flag("MONITOR_BROWSER_HISTORY", True):
                    self.monitors.append(("BROWSER", browser_monitor.BrowserHistoryMonitor(allowed_domains=_env_csv("BROWSER_ALLOWED_DOMAINS"))))
                    self.formatters["BROWSER"] = browser_monitor.format_for_soc
            except Exception as e:
                logger.info(f"Error initializing Windows monitors: {e}")
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
                        logs.append(LogEvent(self.agent_id, self.hostname, name, self.formatters[name](e)))
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
                    logger.info(f"Connected.")
                    while True:
                        logs = self.collect_logs()
                        heartbeat = {"type": "heartbeat", "agent_id": self.agent_id, "hostname": self.hostname}
                        sock.sendall((json.dumps(heartbeat) + "\n").encode("utf-8"))
                        
                        for log in logs:
                            sock.sendall((json.dumps(log.to_dict()) + "\n").encode("utf-8"))
                        
                        logger.info(f"Sent {len(logs)} logs")
                        time.sleep(self.send_interval)
            except Exception as e:
                logger.info(f"Connection error: {e}. Retrying in 5s...")
                time.sleep(5)

if __name__ == "__main__":
    agent = Agent()
    agent.run()
