#!/usr/bin/env python3
"""
AgentFirewall v2 Server — FIXED + New Endpoints
Run:  python server.py
Open: http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import mimetypes
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from agentfirewall.agent import DemoEnterpriseAgent
from agentfirewall.db import AuditStore
from agentfirewall.engine import AgentFirewallEngine
from agentfirewall.policies import (
    DEFAULT_GUARDRAILS, ROLE_LABELS, TOOL_POLICIES, allowed_tools_for_role
)
from agentfirewall.redteam import RED_TEAM_CASES
from agentfirewall.memory import get_history_as_text

ROOT     = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
DATA_DIR = ROOT / "data"
DB_PATH  = DATA_DIR / "agentfirewall.db"

ENGINE = AgentFirewallEngine()
AGENT  = DemoEnterpriseAgent()
STORE  = AuditStore(DB_PATH)


def analyze_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    prompt          = str(payload.get("prompt", ""))
    role            = str(payload.get("role", "guest"))
    tool            = str(payload.get("tool", "chat_only"))
    target_resource = str(payload.get("target_resource", "general"))
    session_id      = str(payload.get("session_id", "default"))

    history = get_history_as_text(session_id)

    # ── Phase 1: Input firewall ────────────────────────────────────
    pre_analysis = ENGINE.analyze_input(
        prompt=prompt, role=role, tool=tool,
        resource=target_resource, history=history,
    )

    from agentfirewall.policies import get_tool_policy
    import time, uuid

    tool_policy = get_tool_policy(tool)
    role_label  = ROLE_LABELS.get(role, role)
    tool_label  = tool_policy.label if tool_policy else tool
    decision_id = str(uuid.uuid4())
    timestamp   = time.time()

    # ── Blast radius ───────────────────────────────────────────────
    blast_radius_score, blast_radius_label = 0, ""
    try:
        from agentfirewall.blast_radius import estimate_blast_radius
        br = estimate_blast_radius(tool, role, target_resource)
        blast_radius_score = br["blast_radius_score"]
        blast_radius_label = br["label"]
    except Exception as e:
        print(f"[BLAST WARN] {e}")

    # ── Drift score from detections ────────────────────────────────
    drift_score, drift_explanation = 0, ""
    for d in pre_analysis.get("detections", []):
        if d.get("category") == "intent_drift":
            drift_score       = d.get("severity", 0)
            drift_explanation = d.get("explanation", "")

    if pre_analysis["decision"] == "BLOCK":
        agent_response     = "Request blocked before agent execution. No tool or model call was performed."
        sanitized_response = agent_response
        output_detections  = []
    else:
        # ── Phase 2: Agent responds ────────────────────────────────
        agent_response = AGENT.respond(
            prompt=pre_analysis["sanitized_prompt"],
            tool=tool,
            session_id=session_id,
            role=role,
            target_resource=target_resource,
        )
        # ── Phase 3: Output firewall ───────────────────────────────
        sanitized_response = ENGINE.sanitize_output(agent_response)
        output_detections  = []

    data = {
        "decision_id":        decision_id,
        "timestamp":          timestamp,
        "decision":           pre_analysis["decision"],
        "risk_score":         pre_analysis["risk_score"],
        "detections":         pre_analysis.get("detections", []),
        "output_detections":  output_detections,
        "sanitized_prompt":   pre_analysis["sanitized_prompt"],
        "sanitized_response": sanitized_response,
        "agent_response":     agent_response,
        "decision_reason":    _make_reason(pre_analysis),
        "rbac_ok":            pre_analysis.get("rbac_ok", True),
        "rbac_message":       pre_analysis.get("rbac_message", ""),
        "latency_ms":         pre_analysis.get("latency_ms", 0),
        "role":               role,
        "tool":               tool,
        "target_resource":    target_resource,
        "prompt":             prompt,
        "role_label":         role_label,
        "tool_label":         tool_label,
        "blast_radius_score": blast_radius_score,
        "blast_radius_label": blast_radius_label,
        "drift_score":        drift_score,
        "drift_explanation":  drift_explanation,
    }

    # ── Causal graph ───────────────────────────────────────────────
    try:
        from agentfirewall.causal_graph import add_event
        add_event(session_id, data)
    except Exception as e:
        print(f"[CAUSAL WARN] {e}")

    # ── Trust token ────────────────────────────────────────────────
    try:
        from agentfirewall.trust_tokens import issue_token
        data["trust_token"] = issue_token(
            "enterprise_agent_v1", role, tool, session_id
        )
    except Exception as e:
        print(f"[TOKEN WARN] {e}")

    STORE.save(data)
    return data


def _make_reason(analysis: dict) -> str:
    detections = [
        d for d in analysis.get("detections", [])
        if d.get("category") != "safe"
    ]
    if not detections:
        return "No threats detected. Request is within policy bounds."
    labels = [d.get("label", d.get("category", "unknown")) for d in detections[:2]]
    return f"Detected: {', '.join(labels)}."


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentFirewall/2.0"

    def log_message(self, format: str, *args: Any) -> None:
        if os.getenv("AGENTFIREWALL_DEBUG") == "1":
            super().log_message(format, *args)

    def do_OPTIONS(self) -> None:
        self._send_empty(204)

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path   = parsed.path
            query  = parse_qs(parsed.query)

            if path == "/api/health":
                return self._send_json({"status": "ok", "service": "AgentFirewall v2"})

            if path == "/api/policies":
                tools = []
                for name, policy in TOOL_POLICIES.items():
                    tools.append({
                        "name":         policy.name,
                        "label":        policy.label,
                        "description":  policy.description,
                        "minimum_role": policy.minimum_role,
                        "base_risk":    policy.base_risk,
                        "sensitive":    policy.sensitive,
                        "allowed_roles": [
                            r for r in ROLE_LABELS
                            if name in allowed_tools_for_role(r)
                        ],
                    })
                return self._send_json({
                    "roles":      ROLE_LABELS,
                    "tools":      tools,
                    "guardrails": DEFAULT_GUARDRAILS,
                })

            if path == "/api/logs":
                limit = int(query.get("limit", [100])[0])
                return self._send_json({"events": STORE.list_events(limit)})

            if path == "/api/stats":
                return self._send_json(STORE.stats())

            if path == "/api/redteam/cases":
                return self._send_json({"cases": RED_TEAM_CASES})

            # ── NEW endpoints ──────────────────────────────────────
            if path == "/api/blast_radius":
                from agentfirewall.blast_radius import get_all_blast_radii
                role     = query.get("role",     ["employee"])[0]
                resource = query.get("resource", ["general"])[0]
                return self._send_json({
                    "role": role, "resource": resource,
                    "estimates": get_all_blast_radii(role, resource),
                })

            if path == "/api/causal_graph":
                from agentfirewall.causal_graph import get_graph
                return self._send_json(
                    get_graph(query.get("session_id", ["default"])[0])
                )

            if path == "/api/trust_status":
                from agentfirewall.trust_tokens import get_session_trust_status
                return self._send_json(
                    get_session_trust_status(query.get("session_id", ["default"])[0])
                )

            return self._serve_static(path)

        except Exception as exc:
            return self._send_error(exc)

    def do_POST(self) -> None:
        try:
            path    = urlparse(self.path).path
            payload = self._read_json()

            if path == "/api/analyze":
                if not str(payload.get("prompt", "")).strip():
                    return self._send_json({"error": "Prompt is required."}, status=400)
                return self._send_json(analyze_request(payload))

            if path == "/api/redteam/run":
                results = []
                for case in RED_TEAM_CASES:
                    result = analyze_request(case)
                    result["case_name"] = case["name"]
                    results.append(result)
                return self._send_json({"results": results, "count": len(results)})

            if path == "/api/redteam/auto":
                from agentfirewall.redteam_auto import run_adversarial_cycle
                return self._send_json(run_adversarial_cycle(
                    role=payload.get("role", "employee"),
                    tool=payload.get("tool", "read_database"),
                    resource=payload.get("resource", "production database"),
                    rounds=min(int(payload.get("rounds", 3)), 5),
                ))

            return self._send_json({"error": "Unknown endpoint."}, status=404)

        except Exception as exc:
            return self._send_error(exc)

    def do_DELETE(self) -> None:
        try:
            if urlparse(self.path).path == "/api/logs":
                STORE.clear()
                return self._send_json({"status": "cleared"})
            return self._send_json({"error": "Unknown endpoint."}, status=404)
        except Exception as exc:
            return self._send_error(exc)

    def _serve_static(self, path: str) -> None:
        if path == "/":
            path = "/index.html"
        file_path = (WEB_ROOT / path.lstrip("/")).resolve()
        if not str(file_path).startswith(str(WEB_ROOT.resolve())):
            return self._send_json({"error": "Forbidden"}, status=403)
        if not file_path.exists() or not file_path.is_file():
            return self._send_json({"error": "Not found"}, status=404)
        content_type, _ = mimetypes.guess_type(str(file_path))
        data = file_path.read_bytes()
        self.send_response(200)
        self._send_headers(content_type=content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_headers(content_type="application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int = 204) -> None:
        self.send_response(status)
        self._send_headers()
        self.end_headers()

    def _send_headers(self, *, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_error(self, exc: Exception) -> None:
        payload = {"error": str(exc)}
        if os.getenv("AGENTFIREWALL_DEBUG") == "1":
            payload["traceback"] = traceback.format_exc()
        return self._send_json(payload, status=500)



def main() -> int:
    port = int(os.getenv("PORT", "7860"))      # HuggingFace uses 7860
    host = os.getenv("HOST", "0.0.0.0")        # 0.0.0.0 = accessible from internet
    server = ThreadingHTTPServer((host, port), Handler)
    print("\n" + "=" * 60)
    print("  NeuroSec — Multi-Agent Trust Network")
    print("=" * 60)
    print(f"  Dashboard   : http://{host}:{port}")
    print(f"  Health      : http://{host}:{port}/api/health")
    print("  Running on Hugging Face Spaces")
    print("  CTRL+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NeuroSec...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())