# agentfirewall/blast_radius.py
# Blast Radius Estimator
# Answers: "If this agent is already compromised, how much damage can it do?"

from typing import Dict

_TOOL_BLAST: Dict[str, dict] = {
    "chat_only":        {"score": 5,  "reversible": True,  "label": "Minimal — text response only"},
    "knowledge_search": {"score": 10, "reversible": True,  "label": "Low — read-only knowledge access"},
    "summarize_report": {"score": 15, "reversible": True,  "label": "Low — read-only document access"},
    "send_email":       {"score": 70, "reversible": False, "label": "HIGH — irreversible external communication"},
    "read_database":    {"score": 55, "reversible": True,  "label": "Medium — sensitive data exposure risk"},
    "execute_code":     {"score": 90, "reversible": False, "label": "CRITICAL — arbitrary code execution"},
    "export_logs":      {"score": 45, "reversible": True,  "label": "Medium — audit data exposure"},
    "admin_override":   {"score": 95, "reversible": False, "label": "CRITICAL — full policy bypass"},
}

_ROLE_MULTIPLIER: Dict[str, float] = {
    "guest": 0.5,
    "student": 0.7,
    "employee": 1.0,
    "security_analyst": 1.3,
    "admin": 1.7,
}

_SENSITIVE_KEYWORDS = [
    "production", "customer", "secret", "credential", "admin", "database",
    "medical", "financial", "payroll", "personal", "private", "confidential",
]


def estimate_blast_radius(tool: str, role: str, resource: str) -> dict:
    base = _TOOL_BLAST.get(tool, {"score": 30, "reversible": True, "label": "Unknown tool"})
    multiplier = _ROLE_MULTIPLIER.get(role, 1.0)
    resource_lower = resource.lower()
    matched_keywords = [kw for kw in _SENSITIVE_KEYWORDS if kw in resource_lower]
    resource_boost = len(matched_keywords) * 10
    final_score = min(100, int((base["score"] * multiplier) + resource_boost))
    return {
        "blast_radius_score": final_score,
        "reversible": base["reversible"],
        "label": base["label"],
        "tool": tool,
        "role": role,
        "resource": resource,
        "matched_sensitive_keywords": matched_keywords,
        "containment_recommendation": _containment_advice(final_score, base["reversible"]),
        "factors": {
            "base_tool_score": base["score"],
            "role_multiplier": multiplier,
            "resource_boost": resource_boost,
        },
    }


def _containment_advice(score: int, reversible: bool) -> str:
    if score >= 80:
        return "CRITICAL: Multi-factor approval required. Consider blocking entirely."
    if score >= 60:
        return f"HIGH: Human-in-the-loop approval required.{' Action is IRREVERSIBLE.' if not reversible else ''}"
    if score >= 40:
        return "MEDIUM: Log all parameters, notify security team, monitor output."
    if score >= 20:
        return "LOW: Standard audit logging is sufficient."
    return "MINIMAL: No special containment needed."


def get_all_blast_radii(role: str, resource: str = "general") -> list:
    return [estimate_blast_radius(tool, role, resource) for tool in _TOOL_BLAST]