#!/bin/bash
# ============================================================
#  SOC Platform - Quick Deploy Script for Student Machines
#  Run this on each student machine to install the agent
# ============================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  SOC Platform Agent Installer${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"

# Check arguments
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <MANAGER_IP> <AGENT_NUMBER> <MACHINE_NAME>"
    echo "Example: $0 192.168.1.100 5 lab-machine-5"
    exit 1
fi

MANAGER_IP=$1
AGENT_NUM=$2
MACHINE_NAME=$3

echo -e "${YELLOW}Manager IP:${NC} $MANAGER_IP"
echo -e "${YELLOW}Agent ID:${NC} agent-$(printf '%03d' $AGENT_NUM)"
echo -e "${YELLOW}Hostname:${NC} $MACHINE_NAME"

# Install dependencies
echo -e "\n${GREEN}[1/4] Installing dependencies...${NC}"
pip3 install psutil --quiet 2>/dev/null || pip install psutil --quiet

# Create agent directory
echo -e "${GREEN}[2/4] Setting up agent...${NC}"
AGENT_DIR="$HOME/soc-agent"
mkdir -p "$AGENT_DIR"

# Download or copy agent files (adjust path as needed)
# For local copy:
# cp -r /path/to/soc-platform/agent/* "$AGENT_DIR/"
# cp -r /path/to/soc-platform/shared "$AGENT_DIR/"

# Update config
echo -e "${GREEN}[3/4] Configuring agent...${NC}"
cat > "$AGENT_DIR/local_config.py" << EOF
# Auto-generated config for $MACHINE_NAME
MANAGER_HOST = "$MANAGER_IP"
MANAGER_PORT = 9000
AGENT_ID = "agent-$(printf '%03d' $AGENT_NUM)"
AGENT_HOSTNAME = "$MACHINE_NAME"
AGENT_SEND_INTERVAL = 2
EOF

echo -e "${GREEN}[4/4] Agent configured!${NC}"
echo ""
echo -e "${GREEN}To start the agent:${NC}"
echo "  cd $AGENT_DIR && python3 agent.py"
echo ""
echo -e "${GREEN}To run on startup, add to crontab:${NC}"
echo "  @reboot cd $AGENT_DIR && python3 agent.py &"
