# ============================================================
#  SOC Agent Configuration — EDIT THIS FOR EACH MACHINE
#  Copy this file to each student machine and update values
# ============================================================

# ── Manager Server (your laptop/server IP) ──
MANAGER_IP = "192.168.245.129"    # ← Change to your manager's IP
MANAGER_PORT = 9000

# ── This Machine's Identity ──
AGENT_ID = "agent-001"            # ← Change: agent-001, agent-002, ... agent-060
AGENT_HOSTNAME = "lab-machine-1"  # ← Change: lab-machine-1, lab-machine-2, etc.

# ── Intervals (seconds) ──
SEND_INTERVAL = 2                 # How often to send logs (2 = good for 60 machines)
