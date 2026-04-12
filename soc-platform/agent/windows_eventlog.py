"""
Windows Event Log Monitor
Collects events from Windows Event Logs (Security, System, Application)
Requires: pywin32 (Windows only)
"""

import sys
import time
from datetime import datetime
from typing import List, Dict, Optional

# Windows-only imports
if sys.platform == 'win32':
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
    import pywintypes

class WindowsEventLogMonitor:
    """Monitor Windows Event Logs"""
    
    def __init__(self, log_names: List[str] = None):
        """
        Initialize Windows Event Log monitor
        
        Args:
            log_names: List of log names to monitor (default: System, Security, Application)
        """
        if sys.platform != 'win32':
            raise RuntimeError("WindowsEventLogMonitor only works on Windows")
        
        self.log_names = log_names or ["System", "Security", "Application"]
        self.enabled_logs = []
        self.last_record_numbers = {}
        self._initialize_bookmarks()
    
    def _initialize_bookmarks(self):
        """Initialize bookmarks to track last read event for each log"""
        for log_name in self.log_names:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                # Read backwards to get the absolutely newest event immediately
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    # Get the record number of the newest event (which is the first one backwards)
                    self.last_record_numbers[log_name] = events[0].RecordNumber
                else:
                    self.last_record_numbers[log_name] = 0
                
                win32evtlog.CloseEventLog(hand)
                self.enabled_logs.append(log_name)
            except Exception as e:
                print(f"[WindowsEventLog] Failed to initialize {log_name}: {e}")
                self.last_record_numbers[log_name] = 0
    
    def collect_new_events(self) -> List[Dict]:
        """
        Collect new events from all monitored logs
        
        Returns:
            List of event dictionaries
        """
        all_events = []
        
        for log_name in self.enabled_logs:
            try:
                events = self._read_log(log_name)
                all_events.extend(events)
            except Exception as e:
                print(f"[WindowsEventLog] Error reading {log_name}: {e}")
        
        return all_events
    
    def _read_log(self, log_name: str) -> List[Dict]:
        """Read new events from specific log"""
        events = []
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Read events backwards until we hit our bookmark
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            new_bookmark = self.last_record_numbers[log_name]
            
            for event in raw_events:
                # Stop reading once we reach our already processed bookmark
                if event.RecordNumber <= self.last_record_numbers[log_name]:
                    break
                
                # Update our newest bookmark on the very first event seen
                if event.RecordNumber > new_bookmark:
                    new_bookmark = event.RecordNumber
                
                # Parse event
                parsed = self._parse_event(event, log_name)
                events.append(parsed)
            
            # Save the new highest bookmark
            self.last_record_numbers[log_name] = new_bookmark
            
            # Reverse events to be chronological
            events.reverse()
            
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            print(f"[WindowsEventLog] Error in _read_log for {log_name}: {e}")
        
        return events
    
    def _parse_event(self, event, log_name: str) -> Dict:
        """Parse Windows event into standardized format"""
        try:
            # Get event type string
            event_type = {
                win32con.EVENTLOG_ERROR_TYPE: "ERROR",
                win32con.EVENTLOG_WARNING_TYPE: "WARNING",
                win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
                win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
                win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE"
            }.get(event.EventType, "UNKNOWN")
            
            # Get event message (may be None)
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except:
                message = "(Unable to format message)"
            
            # Get username (SID to name)
            username = "N/A"
            if event.Sid:
                try:
                    domain, user, typ = win32security.LookupAccountSid(None, event.Sid)
                    username = f"{domain}\\{user}"
                except:
                    username = str(event.Sid)
            
            # Build structured event
            return {
                "timestamp": event.TimeGenerated.isoformat(),
                "log_name": log_name,
                "event_id": event.EventID & 0xFFFF,  # Mask to get actual ID
                "event_type": event_type,
                "source": event.SourceName,
                "category": event.EventCategory,
                "username": username,
                "computer": event.ComputerName,
                "message": message,
                "record_number": event.RecordNumber
            }
        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "log_name": log_name,
                "event_id": 0,
                "event_type": "ERROR",
                "source": "EventLogParser",
                "message": f"Failed to parse event: {e}",
                "record_number": event.RecordNumber if hasattr(event, 'RecordNumber') else 0
            }
    
    def get_critical_events(self, events: List[Dict]) -> List[Dict]:
        """
        Filter for security-critical events
        
        Important Event IDs:
        - 4624: Successful logon
        - 4625: Failed logon
        - 4648: Logon with explicit credentials
        - 4672: Special privileges assigned
        - 4720: User account created
        - 4732: Member added to security-enabled group
        - 7045: Service installed (System log)
        - 4697: Service installed (Security log)
        """
        critical_event_ids = {
            4624, 4625, 4648, 4672, 4720, 4732, 4697,  # Security
            7045, 7036, 7040,  # System - Services
            1000, 1001, 1002,  # Application errors
        }
        
        return [e for e in events if e.get("event_id") in critical_event_ids]

def format_for_soc(event: Dict) -> str:
    """Format Windows event for SOC platform ingestion"""
    return (
        f"[{event['timestamp']}] "
        f"EventID={event['event_id']} "
        f"Type={event['event_type']} "
        f"Source={event['source']} "
        f"User={event.get('username', 'N/A')} "
        f"Computer={event.get('computer', 'N/A')} "
        f"Message: {event['message']}"
    )

# Test function
if __name__ == "__main__":
    if sys.platform != 'win32':
        print("This module only works on Windows")
        sys.exit(1)
    
    print("[WindowsEventLog] Starting monitor test...")
    monitor = WindowsEventLogMonitor(["System", "Security"])
    
    print("[WindowsEventLog] Reading current events...")
    events = monitor.collect_new_events()
    print(f"[WindowsEventLog] Found {len(events)} new events")
    
    # Show last 5 events
    for event in events[-5:]:
        print(format_for_soc(event))
    
    print("\n[WindowsEventLog] Monitoring for new events (Ctrl+C to stop)...")
    try:
        while True:
            time.sleep(5)
            new_events = monitor.collect_new_events()
            if new_events:
                print(f"\n[WindowsEventLog] {len(new_events)} new events:")
                for event in new_events:
                    print(format_for_soc(event))
    except KeyboardInterrupt:
        print("\n[WindowsEventLog] Stopped")
