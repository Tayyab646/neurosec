# agentfirewall/intent_drift.py
# Intent Drift Score — tracks semantic velocity of conversation intent.
# Detects gradual multi-turn attacks where each message looks safe
# but the trajectory reveals the attack.

from .llm import call_llm_json
from .memory import get_history

DRIFT_SYSTEM = """You are an AI security analyst detecting intent drift in conversations.
Intent drift = when a user's goals gradually escalate toward something harmful across turns.
Normal conversation stays semantically consistent. A drift attack escalates gradually.
Respond ONLY with valid JSON."""

DRIFT_PROMPT = """Analyze this conversation for intent drift.

HISTORY (oldest to newest):
{history}

NEW MESSAGE: {current_prompt}

Drift score 0-100:
  0-20  = normal topic evolution
  21-50 = noticeable shift, monitor
  51-75 = suspicious drift, possible gradual attack
  76-100 = clear escalation, likely multi-turn attack

Respond EXACTLY with this JSON (no other text):
{{"drift_score":0,"trajectory":"how intent evolved across turns","is_suspicious":false,"explanation":"why this score was assigned","attack_pattern":null}}"""


def compute_intent_drift(session_id: str, current_prompt: str) -> dict:
    history = get_history(session_id)
    if len(history) < 2:
        return {
            "drift_score": 0,
            "trajectory": "Insufficient history.",
            "is_suspicious": False,
            "explanation": "Need at least 2 prior messages to detect drift.",
            "attack_pattern": None,
        }
    recent = history[-6:]
    history_text = "\n".join(
        f"{'User' if m['role'] == 'user' else 'Agent'}: {m['content']}"
        for m in recent
    )
    result = call_llm_json(
        DRIFT_PROMPT.format(history=history_text, current_prompt=current_prompt),
        system=DRIFT_SYSTEM,
    )
    if not result:
        return {
            "drift_score": 0,
            "trajectory": "Analysis unavailable.",
            "is_suspicious": False,
            "explanation": "LLM could not be reached.",
            "attack_pattern": None,
        }
    return result