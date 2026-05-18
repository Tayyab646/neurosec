# agentfirewall/llm.py
# ALL LLM calls go through here.
# Switched from Gemini to Claude (Anthropic) — drop-in replacement.
# Both call_llm() and call_llm_json() keep the same signatures so
# every other file works without any changes.

import json
import re
import anthropic
from .config import ANTHROPIC_API_KEY, CLAUDE_MODEL

# One client instance shared across the whole process
_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


def call_llm(prompt: str, system: str = "", temperature: float = 0.2) -> str:
    """
    Basic LLM call. Returns the text response as a plain string.
    Same signature as the old Gemini version — all callers unchanged.
    """
    try:
        kwargs = {
            "model": CLAUDE_MODEL,
            "max_tokens": 1024,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system

        message = _client.messages.create(**kwargs)
        return "".join(
            block.text for block in message.content
            if hasattr(block, "text")
        ).strip()

    except Exception as e:
        print(f"[LLM ERROR] {e}")
        return ""


def call_llm_json(prompt: str, system: str = "") -> dict:
    """
    LLM call that expects a JSON response.
    Used by the firewall judge, red-team, and intent drift modules.
    """
    system_with_json = (
        (system or "") +
        "\nYou MUST respond with valid JSON only. "
        "No explanation. No markdown. No backticks. No preamble. JSON only."
    )

    raw = call_llm(prompt, system=system_with_json, temperature=0.1)

    # Strip any markdown fences Claude might add despite instructions
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract JSON object if wrapped in extra text
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        print(f"[JSON PARSE ERROR] Raw: {raw[:400]}")
        return {}