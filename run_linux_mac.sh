#!/bin/bash
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)"
echo ""
echo "============================================="
echo "  AgentFirewall v2 - Starting..."
echo "============================================="
echo ""
python3 --version
echo ""
python3 server.py