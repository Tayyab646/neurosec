"""SQLite persistence for AgentFirewall audit events."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional


class AuditStore:
    def __init__(self, db_path: str | os.PathLike[str]):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    decision_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    role TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target_resource TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events(risk_score)")

    def save(self, decision_payload: Dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_events
                (decision_id, created_at, role, tool, target_resource, decision, risk_score, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_payload["decision_id"],
                    decision_payload["timestamp"],
                    decision_payload["role"],
                    decision_payload["tool"],
                    decision_payload["target_resource"],
                    decision_payload["decision"],
                    int(decision_payload["risk_score"]),
                    json.dumps(decision_payload, ensure_ascii=False),
                ),
            )

    def list_events(self, limit: int = 100) -> List[Dict]:
        limit = max(1, min(500, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM audit_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def stats(self) -> Dict:
        events = self.list_events(500)
        total = len(events)
        if total == 0:
            return {
                "total": 0,
                "allowed": 0,
                "warned": 0,
                "blocked": 0,
                "avg_risk": 0,
                "top_categories": [],
                "recent": [],
            }
        allowed = sum(1 for e in events if e["decision"] == "ALLOW")
        warned = sum(1 for e in events if e["decision"] == "WARN")
        blocked = sum(1 for e in events if e["decision"] == "BLOCK")
        avg_risk = round(sum(int(e["risk_score"]) for e in events) / total, 1)
        categories: Dict[str, int] = {}
        for e in events:
            for d in e.get("detections", []) + e.get("output_detections", []):
                categories[d.get("category", "unknown")] = categories.get(d.get("category", "unknown"), 0) + 1
        top_categories = sorted(categories.items(), key=lambda item: item[1], reverse=True)[:6]
        return {
            "total": total,
            "allowed": allowed,
            "warned": warned,
            "blocked": blocked,
            "avg_risk": avg_risk,
            "top_categories": [{"category": k, "count": v} for k, v in top_categories],
            "recent": events[:12],
        }

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM audit_events")
