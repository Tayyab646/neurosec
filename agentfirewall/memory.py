# agentfirewall/memory.py
# Stores conversation history per user session

from collections import defaultdict, deque
from .config import MEMORY_WINDOW

# In-memory store: { session_id: deque of messages }
_store = defaultdict(lambda: deque(maxlen=MEMORY_WINDOW))


def add_message(session_id: str, role: str, content: str):
    """
    role = 'user' or 'assistant'
    """
    _store[session_id].append({"role": role, "content": content})


def get_history(session_id: str) -> list:
    """Returns list of past messages for this session."""
    return list(_store[session_id])


def get_history_as_text(session_id: str) -> str:
    """Returns conversation as readable text block for prompts."""
    msgs = get_history(session_id)
    if not msgs:
        return "No prior conversation."
    lines = []
    for m in msgs:
        label = "User" if m["role"] == "user" else "Agent"
        lines.append(f"{label}: {m['content']}")
    return "\n".join(lines)


def clear(session_id: str):
    _store[session_id].clear()