import re
import json
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.logger import get_logger
logger = get_logger("RuleEngine")
from shared.models import Alert, LogEvent

class RuleLoader:
    def __init__(self, rules_file="rules.json"):
        self.rules_file = os.path.join(os.path.dirname(__file__), rules_file)
        self.rules = []
        self.reload()
        
    def reload(self):
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                self.rules = json.load(f)
            # Precompile regex for performance
            for r in self.rules:
                if 'pattern' in r and getattr(r, 'pattern', None):
                    pass
                if isinstance(r.get('pattern'), str):
                    r['_compiled'] = re.compile(r['pattern'], re.IGNORECASE)
            logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
        except Exception as e:
            logger.info(f"Error loading rules: {e}")

class RuleEngine:
    def __init__(self):
        self.loader = RuleLoader()
        self._last_hit = {}
        
    def reload_rules(self):
        self.loader.reload()
        
    def _is_duplicate(self, rule_id, agent_id, raw_log, dedup_seconds=300):
        """Check if we already alerted on this recently."""
        now = time.time()
        # Strip out the leading timestamp (e.g., [2026-04-09T...]) so identical payloads with different times are truly deduplicated
        pure_log = re.sub(r"^\[.*?\]\s*", "", raw_log)
        key = f"{rule_id}:{agent_id}:{pure_log}"
        last = self._last_hit.get(key, 0)
        if now - last < dedup_seconds:
            return True
        self._last_hit[key] = now
        
        # Cleanup old entries to prevent memory leak
        if len(self._last_hit) > 10000:
            cutoff = now - max(60, dedup_seconds)
            self._last_hit = {k: v for k, v in self._last_hit.items() if v > cutoff}
            
        return False
        
    def evaluate(self, event: LogEvent) -> list[Alert]:
        """Check a single LogEvent against all loaded rules."""
        alerts = []
        for rule in self.loader.rules:
            # Check source filter
            if rule.get('source_filter') is not None and rule['source_filter'] != event.source:
                continue
                
            # Check regex
            if '_compiled' in rule and rule['_compiled'].search(event.raw_log):
                dedup_seconds = int(rule.get("dedup_seconds", 300))
                if not self._is_duplicate(rule['id'], event.agent_id, event.raw_log, dedup_seconds):
                    alert = Alert(
                        rule_id=rule['id'],
                        rule_name=rule['name'],
                        severity=rule['severity'],
                        agent_id=event.agent_id,
                        hostname=event.hostname,
                        matched_log=event.raw_log,
                        timestamp=event.timestamp
                    )
                    alerts.append(alert)
        return alerts
