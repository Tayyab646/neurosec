# AgentFirewall AI Coding Instructions

## Project Overview

**AgentFirewall** is an enterprise AI security firewall that intercepts, analyzes, and controls LLM agent requests using three-phase decision logic:
1. **Input Firewall** — Detects prompt injection, jailbreaks, and malicious intent via LLM-as-judge
2. **Agent Execution** — Sandboxed agent responds within approved tool boundaries
3. **Output Firewall** — Sanitizes responses to remove leaked credentials/PII

The system guards against 9 attack categories: prompt injection, jailbreak, credential theft, data exfiltration, indirect injection, social engineering, intent drift, malware, and safe queries.

## Architecture & Key Components

### Three-Phase Request Pipeline

```
analyze_request()
├─ Phase 1: INPUT FIREWALL
│  ├─ Engine.analyze_input() [engine.py]
│  ├─ LLM-as-judge detects threats (JUDGE_SYSTEM + JUDGE_PROMPT)
│  ├─ Checks RBAC via role/tool policy matrix [policies.py]
│  ├─ Returns: decision (ALLOW/BLOCK), risk_score, detections, sanitized_prompt
│  └─ Supplementary: blast_radius, intent_drift, causal_graph
│
├─ Phase 2: AGENT EXECUTION [agent.py]
│  └─ DemoEnterpriseAgent.respond() runs ONLY if Phase 1 = ALLOW
│
└─ Phase 3: OUTPUT FIREWALL
   └─ Engine.sanitize_output() redacts credentials/PII
```

**Entry point:** `server.py::analyze_request()` is called by HTTP POST `/api/analyze`.

### Module Responsibilities

| Module | Purpose | Key Pattern |
|--------|---------|------------|
| `engine.py` | LLM judge, RBAC, output sanitization | Two `call_llm_json()` prompts (judge + redactor) |
| `policies.py` | Zero-dependency policy definitions | Frozen dataclass `ToolPolicy`, ROLE_ORDER dict |
| `agent.py` | Sandboxed agent with tool responses | `respond()` takes role/tool/session_id params |
| `config.py` | Centralized env-based config | ANTHROPIC_API_KEY, CLAUDE_MODEL, thresholds (RISK_ALLOW=37, RISK_WARN=71) |
| `memory.py` | Per-session conversation history | In-memory defaultdict deque; window size = MEMORY_WINDOW (10) |
| `llm.py` | Unified Claude API wrapper | Both `call_llm()` (string) and `call_llm_json()` handle model switching transparently |
| `blast_radius.py` | Damage estimation if agent compromised | Tool base score × role multiplier + resource keyword boost |
| `intent_drift.py` | Multi-turn attack detection | Tracks semantic velocity; needs ≥2 prior messages |
| `db.py` | SQLite audit persistence | AuditStore saves decision_payload with indexes on created_at, decision, risk_score |
| `redteam.py` | Built-in test cases | RED_TEAM_CASES list for demo/validation |

## Critical Developer Workflows

### Running the Server

```bash
# Windows
run_windows.bat

# Linux/Mac
bash run_linux_mac.sh

# Or directly (sets PYTHONPATH)
python server.py
```

Server starts on `http://127.0.0.1:8000`. Web UI loads from `web/index.html`.

### Testing & Validation

```bash
# Module dependency check (all imports load cleanly)
python test_modules.py

# Manual testing via web UI or curl
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"prompt":"...", "role":"employee", "tool":"chat_only"}'

# Red-team demo cases
curl http://127.0.0.1:8000/api/redteam/cases
```

### Key API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/analyze` | POST | Submit request for firewall decision |
| `/api/health` | GET | Service status |
| `/api/policies` | GET | Tool, role, and guardrail definitions |
| `/api/logs` | GET | Audit event history (limit param) |
| `/api/stats` | GET | Decision stats (total, allowed, blocked, avg_risk) |
| `/api/redteam/cases` | GET | Built-in attack cases for testing |

## Project-Specific Patterns & Conventions

### 1. LLM Calls: Universal Claude Adapter

All LLM calls route through `llm.py` using identical function signatures—enables model switching without touching business logic:

```python
# Deterministic (temperature=0.1 for JSON, 0.2 for text)
result = call_llm_json(prompt, system=JUDGE_SYSTEM)  # Returns dict
text = call_llm(prompt, system=AGENT_SYSTEM)         # Returns str

# JSON parsing handles Claude's markdown-fence escaping:
# call_llm_json() strips ```json``` and uses regex fallback for wrapped JSON
```

**When adding LLM-powered features:** Always use these two functions; never import anthropic directly.

### 2. Policy-Driven RBAC

Policies are **pure data structures** (no dependencies) in `policies.py`:

- **Role hierarchy:** guest(0) → student(1) → employee(2) → security_analyst(3) → admin(4)
- **Tool policy attributes:** name, label, minimum_role (gates who can use it), base_risk (0–95), sensitive (bool)
- **Usage check:** `allowed_tools_for_role(role)` returns set of permitted tools

```python
# From policies.py
TOOL_POLICIES["send_email"].minimum_role == "employee"  # Only employee+ can send_email
TOOL_POLICIES["admin_override"].base_risk == 70         # High-risk tool
```

### 3. Risk Score & Decision Logic

**Risk calculation:**
- Base: tool's `base_risk` + RBAC penalty if role insufficient
- Detections add severity points
- **Decision threshold:** risk_score ≤ RISK_ALLOW (37) → ALLOW; ≥ RISK_WARN (71) → BLOCK; else WARN

**Configuration constants** live in `config.py` and are centralized (RISK_ALLOW, RISK_WARN, MEMORY_WINDOW, CLAUDE_MODEL).

### 4. Session-Based Conversation Memory

Each user session maintains sliding-window history (max 10 messages):

```python
# In agent/engine code:
history = get_history_as_text(session_id)  # Returns readable text block for prompts
add_message(session_id, "user", content)   # After request
add_message(session_id, "assistant", response)  # After response
```

**Critical:** Intent drift detection requires ≥2 prior messages; pass `session_id` consistently.

### 5. Audit Event Persistence

Every decision is logged to SQLite with full payload:

```python
STORE = AuditStore(DB_PATH)
data = {
    "decision_id": uuid,
    "timestamp": time.time(),
    "decision": "ALLOW|BLOCK|WARN",
    "risk_score": int,
    "role", "tool", "target_resource", "detections": [...],
    # ... 30+ fields
}
STORE.save(data)  # Persists with indexes
```

**When debugging decisions:** Query SQLite: `SELECT payload FROM audit_events ORDER BY created_at DESC LIMIT 10`.

### 6. Error Handling: Graceful Degradation

Non-critical subsystems (blast_radius, drift, causal_graph, trust_tokens) wrap in try-except:

```python
try:
    br = estimate_blast_radius(tool, role, target_resource)
    blast_radius_score = br["blast_radius_score"]
except Exception as e:
    print(f"[BLAST WARN] {e}")
    blast_radius_score = 0
```

This ensures one failed module doesn't block the entire request—firewall remains operational.

### 7. JSON Extraction & Robustness

LLM responses are fragile. `call_llm_json()` in `llm.py` includes:
- Markdown fence stripping (Claude adds ````json```despite instructions)
- Regex fallback to extract `{...}` if wrapped in explanation text
- Empty dict fallback on parse failure

## Integration Points & Dependencies

### External: Anthropic Claude API

- **Config:** `ANTHROPIC_API_KEY` (env var) + `CLAUDE_MODEL` in `config.py`
- **Model:** claude-sonnet-4-20250514
- **Used by:** All threat detection, redaction, drift analysis
- **Fallback:** Functions return empty strings/dicts if API fails; request still processes

### Internal: Multi-Module Data Flow

```
Request → analyze_request()
  ├→ Engine.analyze_input()
  │  └→ LLM judge (JUDGE_PROMPT) → detections + risk_score
  ├→ check_rbac() [policies.py] → rbac_ok boolean
  ├→ estimate_blast_radius() [blast_radius.py] → blast_radius_score, label, advice
  ├→ compute_intent_drift() [intent_drift.py] → drift_score (if history ≥ 2 msgs)
  ├→ add_event() [causal_graph.py] → graph mutation (optional)
  ├→ issue_token() [trust_tokens.py] → JWT-like token (optional)
  └→ STORE.save() [db.py] → audit event persisted
```

## Common Customization Points

- **Add detection category:** Extend JUDGE_SYSTEM prompt + red-team test case in `redteam.py`
- **Adjust tool policies:** Modify `TOOL_POLICIES` dict in `policies.py`
- **Change thresholds:** Update `RISK_ALLOW`, `RISK_WARN` in `config.py`
- **Tune memory window:** Adjust `MEMORY_WINDOW` in `config.py`
- **Add approval workflows:** Hook into `server.py::analyze_request()` before STORE.save()
