# test_modules.py
# Place this in ROOT folder: D:\AgentFirewall\AgentFirewall\
# Run: python test_modules.py

import sys
import os

# Force Python to find the agentfirewall package
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

print("=" * 55)
print("  AgentFirewall — Module Check")
print("=" * 55)
print(f"  Root folder: {ROOT}")
print(f"  Looking for: {os.path.join(ROOT, 'agentfirewall')}")
print()

# Check agentfirewall folder exists
af_path = os.path.join(ROOT, 'agentfirewall')
if not os.path.isdir(af_path):
    print("  CRITICAL: agentfirewall\\ folder NOT FOUND in", ROOT)
    print("  Create it and put all .py files inside it.")
    sys.exit(1)
else:
    print(f"  agentfirewall\\ folder found OK")

# Check __init__.py exists
init_path = os.path.join(af_path, '__init__.py')
if not os.path.isfile(init_path):
    print("  CRITICAL: agentfirewall\\__init__.py NOT FOUND")
    print("  Create an empty file called __init__.py inside agentfirewall\\")
    sys.exit(1)
else:
    print(f"  __init__.py found OK")

print()

ok_count   = 0
fail_count = 0

def check(label, fn):
    global ok_count, fail_count
    try:
        result = fn()
        print(f"  OK    {label:<30} {result}")
        ok_count += 1
    except Exception as e:
        print(f"  FAIL  {label:<30} {e}")
        fail_count += 1

# Check each file exists first
files = [
    'agent.py', 'blast_radius.py', 'causal_graph.py',
    'config.py', 'db.py', 'engine.py', 'intent_drift.py',
    'llm.py', 'memory.py', 'policies.py', 'redteam.py',
    'redteam_auto.py', 'tools.py', 'trust_tokens.py',
]
missing = []
for f in files:
    fp = os.path.join(af_path, f)
    if not os.path.isfile(fp):
        missing.append(f)

if missing:
    print("  MISSING FILES inside agentfirewall\\:")
    for f in missing:
        print(f"    - {f}")
    print()

print("  Checking imports:")
print()

# config
def chk_config():
    from agentfirewall.config import ANTHROPIC_API_KEY, CLAUDE_MODEL
    if "YOUR" in ANTHROPIC_API_KEY:
        return f"model={CLAUDE_MODEL} | WARNING: API key not set yet"
    return f"model={CLAUDE_MODEL} | API key is set"
check("config.py", chk_config)

# policies
def chk_policies():
    from agentfirewall.policies import TOOLS, get_tool_policy, check_rbac
    ok, _ = check_rbac('guest', 'admin_override')
    return f"tools={len(TOOLS)} | guest_blocked={not ok}"
check("policies.py", chk_policies)

# llm
check("llm.py", lambda: (
    __import__('agentfirewall.llm', fromlist=['call_llm'])
    and "Claude SDK loaded"
))

# engine
def chk_engine():
    from agentfirewall.engine import AgentFirewallEngine
    e = AgentFirewallEngine()
    if not hasattr(e, 'sanitize_output'):
        raise Exception("sanitize_output missing — replace engine.py")
    if not hasattr(e, 'analyze_input'):
        raise Exception("analyze_input missing — replace engine.py")
    return "sanitize_output=True | analyze_input=True"
check("engine.py", chk_engine)

# agent
def chk_agent():
    from agentfirewall.agent import DemoEnterpriseAgent
    return "DemoEnterpriseAgent loaded"
check("agent.py", chk_agent)

# memory
def chk_memory():
    from agentfirewall.memory import add_message, get_history
    add_message('__test__', 'user', 'hello')
    h = get_history('__test__')
    return f"history_length={len(h)}"
check("memory.py", chk_memory)

# db
def chk_db():
    from agentfirewall.db import AuditStore
    from pathlib import Path
    Path('data').mkdir(exist_ok=True)
    AuditStore(Path('data/test_check.db'))
    return "AuditStore loaded"
check("db.py", chk_db)

# blast_radius
def chk_blast():
    from agentfirewall.blast_radius import estimate_blast_radius
    br = estimate_blast_radius('execute_code', 'admin', 'production')
    return f"score={br['blast_radius_score']} | reversible={br['reversible']}"
check("blast_radius.py", chk_blast)

# causal_graph
def chk_causal():
    from agentfirewall.causal_graph import add_event, get_graph, clear_graph
    add_event('__test__', {
        'decision_id': 'x1', 'timestamp': 1000.0,
        'decision': 'BLOCK', 'risk_score': 85,
        'prompt': 'test', 'tool': 'execute_code',
        'role': 'employee', 'detections': [],
        'blast_radius_score': 90, 'drift_score': 60,
    })
    g = get_graph('__test__')
    clear_graph('__test__')
    return f"nodes={g['total_steps']}"
check("causal_graph.py", chk_causal)

# trust_tokens
def chk_trust():
    from agentfirewall.trust_tokens import issue_token, verify_token
    tok = issue_token('agent_v1', 'employee', 'read_database', 'sess_test')
    valid, _ = verify_token(tok['token_id'], 'agent_v1')
    return f"valid={valid} | id={tok['token_id']}"
check("trust_tokens.py", chk_trust)

# intent_drift
check("intent_drift.py", lambda: (
    __import__('agentfirewall.intent_drift', fromlist=['compute_intent_drift'])
    and "loaded"
))

# redteam
def chk_redteam():
    from agentfirewall.redteam import RED_TEAM_CASES
    return f"cases={len(RED_TEAM_CASES)}"
check("redteam.py", chk_redteam)

# redteam_auto
check("redteam_auto.py", lambda: (
    __import__('agentfirewall.redteam_auto', fromlist=['run_adversarial_cycle'])
    and "loaded"
))

# server.py
def chk_server():
    server_path = os.path.join(ROOT, 'server.py')
    if not os.path.isfile(server_path):
        raise Exception("server.py NOT FOUND in root folder — create it")
    import importlib.util
    spec = importlib.util.spec_from_file_location("server", server_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return "all imports resolved"
check("server.py", chk_server)

# Summary
print()
print("=" * 55)
print(f"  PASSED: {ok_count}   FAILED: {fail_count}")
print("=" * 55)

if fail_count == 0:
    print()
    print("  All modules OK!")
    print("  Run:  python server.py")
    print("  Or double-click run_windows.bat")
else:
    print()
    print("  Fix the FAIL lines, then re-run this script.")