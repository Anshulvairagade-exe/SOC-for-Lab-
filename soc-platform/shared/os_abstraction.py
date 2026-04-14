"""
OS Abstraction Layer for Cross-Platform SOC Monitoring
Provides unified interface for Windows and Ubuntu operations
"""

import platform
import os
from typing import List, Dict, Optional
from pathlib import Path

class OSType:
    """Operating System Types"""
    WINDOWS = "Windows"
    LINUX = "Linux"
    UNKNOWN = "Unknown"

class OSAbstraction:
    """Cross-platform OS operations abstraction"""
    
    def __init__(self):
        self.os_type = self._detect_os()
        self.is_windows = self.os_type == OSType.WINDOWS
        self.is_linux = self.os_type == OSType.LINUX
    
    def _detect_os(self) -> str:
        """Detect current operating system"""
        system = platform.system()
        if system == "Windows":
            return OSType.WINDOWS
        elif system == "Linux":
            return OSType.LINUX
        else:
            return OSType.UNKNOWN
    
    def get_default_log_sources(self) -> List[str]:
        """Get default log file paths for current OS"""
        if self.is_linux:
            return [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/kern.log"
            ]
        elif self.is_windows:
            # Windows Event Logs handled separately via pywin32
            return []
        return []
    
    def get_default_fim_paths(self) -> List[str]:
        """Get default file integrity monitoring paths"""
        if self.is_linux:
            return [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/hosts",
                "/etc/ssh/sshd_config"
            ]
        elif self.is_windows:
            return [
                r"C:\Windows\System32\drivers\etc\hosts",
                r"C:\Windows\System32\config\SAM",
                r"C:\Windows\System32\config\SYSTEM",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            ]
        return []
    
    def get_browser_history_paths(self) -> Dict[str, List[str]]:
        """Get browser history database paths for current OS"""
        home = str(Path.home())
        
        if self.is_linux:
            return {
                "chrome": [
                    f"{home}/.config/google-chrome/Default/History",
                    f"{home}/.config/chromium/Default/History"
                ],
                "firefox": [
                    f"{home}/.mozilla/firefox/*/places.sqlite"
                ],
                "brave": [
                    f"{home}/.config/BraveSoftware/Brave-Browser/Default/History",
                    f"{home}/snap/brave/current/.config/BraveSoftware/Brave-Browser/Default/History"
                ],
                "edge": []  # Not common on Linux
            }
        elif self.is_windows:
            appdata_local = os.getenv('LOCALAPPDATA', f"{home}\\AppData\\Local")
            appdata_roaming = os.getenv('APPDATA', f"{home}\\AppData\\Roaming")
            
            return {
                "chrome": [
                    f"{appdata_local}\\Google\\Chrome\\User Data\\Default\\History",
                    f"{appdata_local}\\Google\\Chrome\\User Data\\Profile *\\History"
                ],
                "firefox": [
                    f"{appdata_roaming}\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite"
                ],
                "brave": [
                    f"{appdata_local}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History",
                    f"{appdata_local}\\BraveSoftware\\Brave-Browser\\User Data\\Profile *\\History"
                ],
                "edge": [
                    f"{appdata_local}\\Microsoft\\Edge\\User Data\\Default\\History",
                    f"{appdata_local}\\Microsoft\\Edge\\User Data\\Profile *\\History"
                ]
            }
        return {}
    
    def get_shell_config_paths(self) -> List[str]:
        """Get shell configuration file paths"""
        home = str(Path.home())
        
        if self.is_linux:
            return [
                f"{home}/.bashrc",
                f"{home}/.bash_profile",
                f"{home}/.zshrc",
                f"{home}/.profile"
            ]
        elif self.is_windows:
            documents = os.getenv('USERPROFILE', home)
            return [
                f"{documents}\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
                f"{documents}\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1"
            ]
        return []
    
    def get_shell_history_paths(self) -> List[str]:
        """Get shell command history file paths"""
        home = str(Path.home())
        
        if self.is_linux:
            return [
                f"{home}/.bash_history",
                f"{home}/.zsh_history"
            ]
        elif self.is_windows:
            appdata_roaming = os.getenv('APPDATA', f"{home}\\AppData\\Roaming")
            return [
                f"{appdata_roaming}\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
            ]
        return []
    
    def get_temp_dir(self) -> str:
        """Get temporary directory path"""
        if self.is_linux:
            return "/tmp"
        elif self.is_windows:
            return os.getenv('TEMP', r"C:\Windows\Temp")
        return "/tmp"
    
    def get_startup_paths(self) -> List[str]:
        """Get autostart/startup folder paths"""
        if self.is_linux:
            home = str(Path.home())
            return [
                f"{home}/.config/autostart",
                "/etc/xdg/autostart"
            ]
        elif self.is_windows:
            appdata_roaming = os.getenv('APPDATA', f"{str(Path.home())}\\AppData\\Roaming")
            return [
                f"{appdata_roaming}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            ]
        return []
    
    def normalize_path(self, path: str) -> str:
        """Convert path to OS-appropriate format"""
        if self.is_windows:
            # Convert forward slashes to backslashes
            return path.replace('/', '\\')
        else:
            # Convert backslashes to forward slashes
            return path.replace('\\', '/')
    
    def get_db_path(self, relative_path: str = "soc_platform.db") -> str:
        """Get platform-appropriate database path"""
        # Use absolute path to avoid issues with working directory
        base_dir = Path(__file__).parent.parent
        return str(base_dir / relative_path)
    
    def is_admin(self) -> bool:
        """Check if running with administrator/root privileges"""
        if self.is_linux:
            return os.geteuid() == 0
        elif self.is_windows:
            import ctypes
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        return False
    
    def get_username(self) -> str:
        """Get current username"""
        return os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    
    def get_hostname(self) -> str:
        """Get system hostname"""
        return platform.node() or 'unknown'

# Global instance
os_abstraction = OSAbstraction()

def get_os() -> OSAbstraction:
    """Get OS abstraction instance"""
    return os_abstraction
