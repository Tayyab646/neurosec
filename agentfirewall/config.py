# agentfirewall/config.py
import os

# Reads API key from environment variable (set in HF Secrets)
# Falls back to placeholder if not set
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "YOUR_KEY_HERE")

CLAUDE_MODEL = "claude-sonnet-4-20250514"

RISK_ALLOW = 37
RISK_WARN  = 71

MEMORY_WINDOW = 10
TOOLS_REAL = False