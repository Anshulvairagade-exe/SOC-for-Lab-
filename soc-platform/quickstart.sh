#!/bin/bash
# SOC Agent Quick Start Script for Cloud Machine
# Run this on your cloud machine (168.144.73.18) after pulling the code

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SOC Platform - Agent Quick Start                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: requirements.txt not found"
    echo "Please run this script from: /path/to/SOC-main/soc-platform"
    exit 1
fi

echo ""
echo "Step 1: Verify Python installation"
python3 --version || python --version
echo "✓ Python found"

echo ""
echo "Step 2: Install dependencies"
pip install -q -r requirements.txt
echo "✓ Dependencies installed"

echo ""
echo "Step 3: Verify configuration"
python3 -c "from shared.config import MANAGER_HOST, MANAGER_PORT, AGENT_ID; print(f'✓ Config: Host={MANAGER_HOST}, Port={MANAGER_PORT}, Agent={AGENT_ID}')"

echo ""
echo "Step 4: Run quick tests"
python3 test_student_monitor.py 2>/dev/null | tail -20
echo "✓ Tests passed"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  READY TO START AGENT                                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"

echo ""
echo "🚀 START AGENT:"
echo ""
echo "Option 1 - Interactive (for testing):"
echo "  python -m agent.agent"
echo ""
echo "Option 2 - Background (for production):"
echo "  nohup python -m agent.agent > agent.log 2>&1 &"
echo ""
echo "Option 3 - Systemd service (recommended for production):"
echo "  See DEPLOYMENT_INSTRUCTIONS.md for setup"
echo ""
