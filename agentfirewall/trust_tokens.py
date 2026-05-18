# agentfirewall/trust_tokens.py
# Zero-Knowledge style Trust Token System.
# An agent proves it hasn't been tampered with WITHOUT revealing internal state.

import hashlib
import hmac
import time
import secrets
from typing import Dict, Tuple

_SIGNING_KEY: bytes = secrets.token_bytes(32)
_token_store: Dict[str, dict] = {}


def issue_token(agent_id: str, role: str, tool: str, session_id: str) -> dict:
    nonce = secrets.token_hex(16)
    issued_at = time.time()
    expires_at = issued_at + 300  # 5 minutes TTL
    commitment_data = f"{agent_id}:{role}:{tool}:{session_id}:{nonce}:{issued_at}"
    commitment = hmac.new(
        _SIGNING_KEY, commitment_data.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    token_id = f"tok_{nonce[:12]}"
    token = {
        "token_id": token_id,
        "agent_id": agent_id,
        "role": role,
        "tool": tool,
        "session_id": session_id,
        "commitment": commitment,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "verified": False,
        "revoked": False,
        "_nonce": nonce,
    }
    _token_store[token_id] = token
    return {k: v for k, v in token.items() if not k.startswith("_")}


def verify_token(token_id: str, agent_id: str) -> Tuple[bool, str]:
    token = _token_store.get(token_id)
    if not token:
        return False, "Token not found."
    if token.get("revoked"):
        return False, "Token revoked."
    if time.time() > token["expires_at"]:
        return False, "Token expired."
    if token["agent_id"] != agent_id:
        return False, "Agent identity mismatch."
    nonce = token.get("_nonce", "")
    commitment_data = (
        f"{token['agent_id']}:{token['role']}:{token['tool']}:"
        f"{token['session_id']}:{nonce}:{token['issued_at']}"
    )
    expected = hmac.new(
        _SIGNING_KEY, commitment_data.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, token["commitment"]):
        return False, "Commitment verification failed."
    token["verified"] = True
    return True, "Token verified successfully."


def revoke_token(token_id: str) -> bool:
    if token_id in _token_store:
        _token_store[token_id]["revoked"] = True
        return True
    return False


def get_session_trust_status(session_id: str) -> dict:
    now = time.time()
    session_tokens = [
        {k: v for k, v in t.items() if not k.startswith("_")}
        for t in _token_store.values()
        if t["session_id"] == session_id
    ]
    return {
        "session_id": session_id,
        "total_tokens": len(session_tokens),
        "verified": sum(1 for t in session_tokens if t.get("verified")),
        "expired": sum(1 for t in session_tokens if now > t.get("expires_at", 0)),
        "revoked": sum(1 for t in session_tokens if t.get("revoked")),
        "active": sum(
            1 for t in session_tokens
            if not t.get("revoked") and now <= t.get("expires_at", 0)
        ),
        "tokens": session_tokens,
    }