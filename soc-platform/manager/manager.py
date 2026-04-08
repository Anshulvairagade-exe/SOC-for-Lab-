# ============================================================
#  SOC Platform - Central Manager / Server
#  PRODUCTION — handles 60+ concurrent agent connections
#  Listens for incoming Agent connections.
#  For each log received → runs Rule Engine → saves to DB.
# ============================================================

import socket
import threading
import os
import sys
import queue
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.config import MANAGER_HOST, MANAGER_PORT, MANAGER_BUFFER_SIZE
from shared.models  import LogEvent
from rule_engine.engine import RuleEngine
from database.db import init_db, insert_log, insert_alert, upsert_agent


# ─────────────────────────────────────────────
#  Client Handler — one thread per Agent
# ─────────────────────────────────────────────
class AgentHandler(threading.Thread):
    """
    Spawned for each connected Agent.
    Reads newline-delimited JSON log events and processes them.
    """
    def __init__(self, conn: socket.socket, addr: tuple, engine: RuleEngine):
        super().__init__(daemon=True)
        self.conn   = conn
        self.addr   = addr
        self.engine = engine
        # Set socket options for reliability
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def run(self):
        print(f"[Manager] Agent connected from {self.addr}")
        buffer = ""

        try:
            while True:
                data = self.conn.recv(MANAGER_BUFFER_SIZE)
                if not data:
                    break  # Agent disconnected

                buffer += data.decode("utf-8", errors="ignore")

                # Messages are newline-delimited — process complete ones
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        self._process(line)

        except ConnectionResetError:
            pass
        except Exception as e:
            print(f"[Manager] Error from {self.addr}: {e}")
        finally:
            self.conn.close()
            print(f"[Manager] Agent disconnected: {self.addr}")

    def _process(self, raw: str):
        """Deserialize a JSON log event → rule check → save to DB."""
        try:
            import json
            data = json.loads(raw)

            # ── Heartbeat message — just update agent last_seen, no alert ──
            if data.get("type") == "heartbeat":
                upsert_agent(data["agent_id"], data["hostname"])
                return

            # ── Normal log event ──
            event = LogEvent.from_json(raw)
            upsert_agent(event.agent_id, event.hostname)
            insert_log(event)
            alerts = self.engine.evaluate(event)
            for alert in alerts:
                insert_alert(alert)

        except Exception as e:
            print(f"[Manager] Failed to process event: {e} | raw={raw[:80]}")


# ─────────────────────────────────────────────
#  Manager Server
# ─────────────────────────────────────────────
class Manager:
    def __init__(self):
        self.engine = RuleEngine()
        self.active_connections = 0
        self._lock = threading.Lock()

    def start(self):
        """Start the TCP server and listen for agent connections."""
        init_db()   # Ensure DB tables exist

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        server.bind((MANAGER_HOST, MANAGER_PORT))
        server.listen(100)   # Queue up to 100 pending connections

        print(f"[Manager] ═══════════════════════════════════════════")
        print(f"[Manager] SOC Platform Manager - PRODUCTION MODE")
        print(f"[Manager] Listening on {MANAGER_HOST}:{MANAGER_PORT}")
        print(f"[Manager] Max connections: 100 | Buffer: {MANAGER_BUFFER_SIZE} bytes")
        print(f"[Manager] ═══════════════════════════════════════════")
        print(f"[Manager] Waiting for agents...")

        while True:
            try:
                conn, addr = server.accept()
                handler = AgentHandler(conn, addr, self.engine)
                handler.start()
                with self._lock:
                    self.active_connections += 1
                print(f"[Manager] Active connections: {self.active_connections}")
            except KeyboardInterrupt:
                print("\n[Manager] Shutting down...")
                break
            except Exception as e:
                print(f"[Manager] Accept error: {e}")

        server.close()


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Increase file descriptor limit for many connections
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(4096, hard), hard))
        print(f"[Manager] File descriptor limit: {min(4096, hard)}")
    except:
        pass
    
    mgr = Manager()
    mgr.start()
