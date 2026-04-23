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
import json

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.logger import get_logger
logger = get_logger("Manager")
from shared.config import MANAGER_HOST, MANAGER_PORT, MANAGER_BUFFER_SIZE
from shared.models  import LogEvent
from rule_engine.engine import RuleEngine
from database.db import (
    init_db,
    insert_log,
    insert_alert,
    upsert_agent,
    claim_queued_agent_commands,
    mark_agent_command_sent,
    mark_agent_command_failed,
    complete_agent_command,
)
from shared.security import CertificateManager, SecureSocket
from pathlib import Path


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
        self.agent_id: str | None = None
        self.hostname: str | None = None
        # Set socket options for reliability
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.conn.settimeout(1.0)

    def run(self):
        logger.info(f"Agent connected from {self.addr}")
        buffer = ""

        try:
            while True:
                try:
                    data = self.conn.recv(MANAGER_BUFFER_SIZE)
                except socket.timeout:
                    self._dispatch_pending_commands()
                    continue
                if not data:
                    break  # Agent disconnected

                buffer += data.decode("utf-8", errors="ignore")

                # Messages are newline-delimited — process complete ones
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        # Silently drop HTTP protocol scans or garbage packets
                        if line.startswith("GET ") or line.startswith("POST ") or line.startswith("HTTP/"):
                            break
                        self._process(line)
                self._dispatch_pending_commands()

        except ConnectionResetError:
            pass
        except Exception as e:
            logger.info(f"Error from {self.addr}: {e}")
        finally:
            self.conn.close()
            logger.info(f"Agent disconnected: {self.addr}")

    def _process(self, raw: str):
        """Deserialize a JSON log event → rule check → save to DB."""
        try:
            data = json.loads(raw)

            # ── Heartbeat message — just update agent last_seen, no alert ──
            if data.get("type") == "heartbeat":
                self.agent_id = data["agent_id"]
                self.hostname = data["hostname"]
                upsert_agent(self.agent_id, self.hostname)
                return

            if data.get("type") == "command_result":
                self._process_command_result(data)
                return

            # ── Normal log event ──
            event = LogEvent.from_json(raw)
            self.agent_id = event.agent_id
            self.hostname = event.hostname
            upsert_agent(event.agent_id, event.hostname)
            insert_log(event)
            alerts = self.engine.evaluate(event)
            for alert in alerts:
                insert_alert(alert)

        except Exception as e:
            logger.info(f"Failed to process event: {e} | raw={raw[:80]}")

    def _dispatch_pending_commands(self):
        if not self.agent_id:
            return
        commands = claim_queued_agent_commands(self.agent_id, limit=10)
        for command in commands:
            payload = {
                "type": "command",
                "command_id": command["id"],
                "action": command["action"],
                "payload": command["payload"],
            }
            try:
                self.conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                mark_agent_command_sent(command["id"])
                logger.info(
                    "Sent command_id=%s action=%s to agent_id=%s",
                    command["id"],
                    command["action"],
                    self.agent_id,
                )
            except Exception as e:
                mark_agent_command_failed(command["id"], f"Dispatch failed: {e}")
                raise

    def _process_command_result(self, data: dict):
        command_id = data.get("command_id")
        if not command_id:
            return

        self.agent_id = data.get("agent_id") or self.agent_id
        self.hostname = data.get("hostname") or self.hostname

        success = bool(data.get("success"))
        result_message = str(data.get("result_message") or "")
        action = str(data.get("action") or "unknown")
        complete_agent_command(int(command_id), success=success, result_message=result_message)

        if self.agent_id and self.hostname:
            insert_log(
                LogEvent(
                    self.agent_id,
                    self.hostname,
                    "AGENT_CONTROL",
                    f"COMMAND_RESULT: CommandID={command_id} | Action={action} | Success={success} | Message={result_message}",
                    timestamp=data.get("timestamp"),
                )
            )


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

        # Generate dynamic certificates if they don't exist
        cert_dir = Path(__file__).parent / "certs"
        cert_file = cert_dir / "server.crt"
        key_file = cert_dir / "server.key"
        
        if not cert_file.exists() or not key_file.exists():
            logger.info("Generating Self-Signed Certificates for TLS...")
            CertificateManager.generate_self_signed_cert(cert_dir)
            
        logger.info("Initializing TLS SecureSocket Listener...")
        server = SecureSocket.create_server_socket(MANAGER_HOST, MANAGER_PORT, str(cert_file), str(key_file))

        logger.info(f"═══════════════════════════════════════════")
        logger.info(f"SOC Platform Manager - PRODUCTION MODE")
        logger.info(f"Listening on {MANAGER_HOST}:{MANAGER_PORT}")
        logger.info(f"Max connections: 100 | Buffer: {MANAGER_BUFFER_SIZE} bytes")
        logger.info(f"═══════════════════════════════════════════")
        logger.info(f"Waiting for agents...")

        while True:
            try:
                conn, addr = server.accept()
                handler = AgentHandler(conn, addr, self.engine)
                handler.start()
                with self._lock:
                    self.active_connections += 1
                logger.info(f"Active connections: {self.active_connections}")
            except KeyboardInterrupt:
                logger.info("\n[Manager] Shutting down...")
                break
            except Exception as e:
                logger.info(f"Accept error: {e}")

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
        logger.info(f"File descriptor limit: {min(4096, hard)}")
    except Exception as e:
        pass
    
    mgr = Manager()
    mgr.start()
