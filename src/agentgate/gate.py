"""The provenance-aware policy gate.

Every tool call an agent proposes is evaluated against the policy *and* against where the
content in the agent's context came from. Rules R0-R6; the most severe decision wins and
every rule that fires is recorded, so each verdict explains itself.

    R0  tool not declared in policy                      -> BLOCK (default deny)
    R1  secret material in the arguments                 -> BLOCK
    R2  private/metadata destination, or egress to a
        host / email domain not on the allowlist         -> BLOCK
    R3  injection markers in untrusted input
          + side-effecting tool                          -> BLOCK
          + read-only tool                               -> ALLOW, SOC alerted
    R4  any untrusted content + side-effecting tool      -> REQUIRE_APPROVAL
    R5  high / destructive / persistence tier            -> REQUIRE_APPROVAL
    R6  trusted context, nothing flagged                 -> ALLOW
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum

from . import detectors as det
from .policy import Policy

IMPACT_ATLAS = {
    "write": ["AML.T0053"],
    "egress": ["AML.T0086"],
    "high": ["AML.T0086"],
    "destructive": ["AML.T0101"],
    "persistence": ["AML.T0080"],
}


class Action(IntEnum):
    """Ordered by severity so max() picks the most restrictive decision."""

    ALLOW = 0
    REQUIRE_APPROVAL = 1
    BLOCK = 2


@dataclass(frozen=True)
class Segment:
    """A piece of agent context, tagged with where it came from."""

    text: str
    source: str
    trusted: bool

    @classmethod
    def trusted_(cls, text: str, source: str = "operator") -> Segment:
        return cls(text, source, True)

    @classmethod
    def untrusted(cls, text: str, source: str = "external") -> Segment:
        return cls(text, source, False)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: str = ""


@dataclass
class RuleHit:
    rule_id: str
    detail: str


@dataclass
class Decision:
    action: Action
    tool: str
    tainted: bool
    rules: list[RuleHit] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    soc_alert: bool = False

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def explain(self) -> str:
        lines = [f"{self.action.name}  tool={self.tool}  context={'untrusted' if self.tainted else 'trusted'}"]
        lines += [f"  {r.rule_id}: {r.detail}" for r in self.rules]
        tags = self.atlas + self.attack + self.owasp + self.mitigations
        if tags:
            lines.append("  maps to: " + ", ".join(tags))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "action": self.action.name,
            "tool": self.tool,
            "tainted": self.tainted,
            "rules": [{"id": r.rule_id, "detail": r.detail} for r in self.rules],
            "atlas": self.atlas,
            "attack": self.attack,
            "owasp": self.owasp,
            "mitigations": self.mitigations,
            "soc_alert": self.soc_alert,
        }


class _Builder:
    def __init__(self, tool: str, tainted: bool) -> None:
        self.d = Decision(action=Action.ALLOW, tool=tool, tainted=tainted)

    def escalate(self, action: Action) -> None:
        self.d.action = max(self.d.action, action)

    def hit(self, rule_id: str, detail: str, *, atlas=(), attack=(), owasp=(), mit=()) -> None:
        self.d.rules.append(RuleHit(rule_id, detail))
        for bucket, items in ((self.d.atlas, atlas), (self.d.attack, attack),
                              (self.d.owasp, owasp), (self.d.mitigations, mit)):
            for item in items:
                if item not in bucket:
                    bucket.append(item)


class Gate:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(self, context: Iterable[Segment], call: ToolCall) -> Decision:
        context = list(context)
        untrusted_text = "\n".join(s.text for s in context if not s.trusted)
        tainted = any(not s.trusted for s in context)
        b = _Builder(call.tool, tainted)
        spec = self.policy.tools.get(call.tool)

        # R0 — default deny
        if spec is None:
            b.escalate(Action.BLOCK)
            b.hit("R0-UNKNOWN-TOOL", "tool is not declared in policy — default deny",
                  atlas=["AML.T0053"], owasp=["LLM06"], mit=["AML.M0028"])
            return b.d
        risk = spec.risk
        arg_blob = f"{call.tool} {call.args}"

        # R1 — secrets leaving through arguments
        leaked = det.secrets_in(call.args)
        if leaked:
            b.escalate(Action.BLOCK)
            b.hit("R1-SECRET-IN-ARGS", "secret material in arguments: " + ", ".join(leaked),
                  atlas=["AML.T0086"], attack=["T1552"], owasp=["LLM02"], mit=["AML.M0024"])

        # R2 — destinations
        for url in det.urls_in(arg_blob):
            host = det.host_of(url)
            if det.is_private_or_metadata(host):
                b.escalate(Action.BLOCK)
                b.hit("R2-PRIVATE-DEST", f"private / cloud-metadata address requested: {host}",
                      atlas=["AML.T0053"], attack=["T1552.005"], owasp=["LLM06"], mit=["AML.M0032"])
            elif risk == "egress" and not det.domain_allowed(host, self.policy.egress_hosts):
                b.escalate(Action.BLOCK)
                b.hit("R2-EGRESS-HOST", f"destination host not allowlisted: {host}",
                      atlas=["AML.T0086"], attack=["T1567"], owasp=["LLM02", "LLM06"], mit=["AML.M0028"])
        if call.tool == "send_email":
            for dom in det.email_domains_in(call.args):
                if not det.domain_allowed(dom, self.policy.email_domains):
                    b.escalate(Action.BLOCK)
                    b.hit("R2-EGRESS-EMAIL", f"recipient domain not allowlisted: {dom}",
                          atlas=["AML.T0086"], attack=["T1048"], owasp=["LLM02", "LLM06"], mit=["AML.M0028"])

        # R3 — injection detected in untrusted input
        markers = det.injection_markers(untrusted_text) if tainted else []
        if markers:
            if risk == "read":
                b.d.soc_alert = True
                b.hit("R3-INJECTION-OBSERVED",
                      f"injection markers in untrusted input ({', '.join(markers)}); read-only call allowed, SOC alerted",
                      atlas=["AML.T0051.001"], owasp=["LLM01"], mit=["AML.M0024"])
            else:
                b.escalate(Action.BLOCK)
                b.hit("R3-INJECTION-TO-ACTION", f"injection markers ({', '.join(markers)}) with a '{risk}' tool requested",
                      atlas=["AML.T0051.001", *IMPACT_ATLAS.get(risk, [])], owasp=["LLM01", "LLM06"], mit=["AML.M0030"])

        # R4 — provenance: untrusted content may not drive side effects without a human
        if tainted and risk != "read":
            b.escalate(Action.REQUIRE_APPROVAL)
            b.hit("R4-TAINTED-CONTEXT", f"untrusted content in context and a '{risk}' tool requested",
                  atlas=IMPACT_ATLAS.get(risk, []), owasp=["LLM06"], mit=["AML.M0030", "AML.M0029"])

        # R5 — blast radius
        if risk in self.policy.always_approve:
            b.escalate(Action.REQUIRE_APPROVAL)
            b.hit("R5-HIGH-IMPACT", f"'{risk}' tier always requires human approval",
                  owasp=["LLM06"], mit=["AML.M0029"])

        # R6 — clean
        if not b.d.rules:
            b.hit("R6-ALLOW", f"'{risk}' tool, trusted context, nothing flagged")
        return b.d
