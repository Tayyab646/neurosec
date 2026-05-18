# agentfirewall/causal_graph.py
# Causal Attack Graph — builds a session-level DAG of firewall decisions.
# Shows counterfactual blame: "blocking step 2 prevented steps 3-5."

import time
from collections import defaultdict
from typing import Dict, List

_graphs: Dict[str, List[dict]] = defaultdict(list)


def add_event(session_id: str, event: dict) -> None:
    nodes = _graphs[session_id]
    parent_id = nodes[-1]["node_id"] if nodes else None
    node = {
        "node_id":           event.get("decision_id", f"node_{int(time.time()*1000)}"),
        "step":              len(nodes) + 1,
        "timestamp":         event.get("timestamp", time.time()),
        "prompt_snippet":    (event.get("prompt", ""))[:120],
        "decision":          event.get("decision", "UNKNOWN"),
        "risk_score":        event.get("risk_score", 0),
        "tool":              event.get("tool", "chat_only"),
        "role":              event.get("role", "unknown"),
        "detections":        [
            d.get("category") for d in event.get("detections", [])
            if d.get("category") != "safe"
        ],
        "blast_radius_score": event.get("blast_radius_score", 0),
        "drift_score":        event.get("drift_score", 0),
        "parent_id":          parent_id,
    }
    _graphs[session_id].append(node)


def get_graph(session_id: str) -> dict:
    nodes = _graphs.get(session_id, [])

    # Build edges
    edges = []
    for i in range(1, len(nodes)):
        risk_delta = nodes[i]["risk_score"] - nodes[i - 1]["risk_score"]
        edges.append({
            "from_id":   nodes[i - 1]["node_id"],
            "to_id":     nodes[i]["node_id"],
            "from_step": nodes[i - 1]["step"],
            "to_step":   nodes[i]["step"],
            "risk_delta": risk_delta,
            "escalation": risk_delta > 15,
        })

    # Counterfactual blame attribution
    counterfactuals = []
    for i, node in enumerate(nodes):
        if node["decision"] == "BLOCK":
            subsequent = nodes[i + 1:]
            if subsequent:
                counterfactuals.append({
                    "blocked_node_id": node["node_id"],
                    "blocked_at_step": node["step"],
                    "prevented_steps": len(subsequent),
                    "prevented_tools": list({n["tool"] for n in subsequent}),
                    "message": (
                        f"Block at step {node['step']} prevented "
                        f"{len(subsequent)} subsequent action(s)."
                    ),
                })

    # Detect escalation chains
    escalation_chains, chain = [], []
    for edge in edges:
        if edge["escalation"]:
            chain.append(edge)
        else:
            if len(chain) >= 2:
                escalation_chains.append(chain)
            chain = []
    if len(chain) >= 2:
        escalation_chains.append(chain)

    attack_chain_detected = len(escalation_chains) > 0

    # Forward risk projection
    next_predicted_risk = None
    if len(nodes) >= 2:
        last_delta = nodes[-1]["risk_score"] - nodes[-2]["risk_score"]
        next_predicted_risk = min(100, nodes[-1]["risk_score"] + max(0, last_delta))

    return {
        "session_id":              session_id,
        "total_steps":             len(nodes),
        "nodes":                   nodes,
        "edges":                   edges,
        "counterfactuals":         counterfactuals,
        "escalation_chains":       escalation_chains,
        "attack_chain_detected":   attack_chain_detected,
        "total_risk_accumulated":  sum(n["risk_score"] for n in nodes),
        "avg_risk":                round(
            sum(n["risk_score"] for n in nodes) / len(nodes), 1
        ) if nodes else 0,
        "next_predicted_risk":     next_predicted_risk,
        "summary":                 _summarize(nodes, attack_chain_detected),
    }


def clear_graph(session_id: str) -> None:
    _graphs[session_id].clear()


def _summarize(nodes: list, attack_chain: bool) -> str:
    if not nodes:
        return "No events recorded for this session."
    blocked = [n["decision"] for n in nodes].count("BLOCK")
    total = len(nodes)
    if attack_chain:
        return (
            f"Attack escalation chain detected across {total} steps. "
            f"{blocked} blocked."
        )
    if blocked > 0:
        return f"{blocked} of {total} requests blocked. No escalation chain."
    return f"{total} events recorded. All within normal risk bounds."