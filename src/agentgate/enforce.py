"""Enforcement point: the only path from an agent's proposed call to a real tool.

    guard = Guard(gate, tools={"search_kb": search_kb, ...}, approver=pager_approver, audit=log)
    result = guard.call(context, ToolCall("search_kb", "q=vpn reset"))

BLOCK raises ToolBlocked. REQUIRE_APPROVAL asks the approver; no approver, or a refusal,
raises ApprovalDenied. Fails closed: if anything in the gate errors, the call does not run.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .audit import AuditLog
from .gate import Action, Decision, Gate, Segment, ToolCall

# An approver sees the decision and returns the approver's identity, or None to refuse.
Approver = Callable[[ToolCall, Decision], str | None]


class GateError(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explain())
        self.decision = decision


class ToolBlocked(GateError):
    pass


class ApprovalDenied(GateError):
    pass


def deny_all(call: ToolCall, decision: Decision) -> str | None:
    return None


class Guard:
    def __init__(
        self,
        gate: Gate,
        tools: Mapping[str, Callable[[str], Any]],
        approver: Approver = deny_all,
        audit: AuditLog | None = None,
        on_alert: Callable[[Decision], None] | None = None,
    ) -> None:
        self.gate, self.tools, self.approver, self.audit, self.on_alert = gate, tools, approver, audit, on_alert

    def call(self, context: Iterable[Segment], call: ToolCall) -> Any:
        try:
            decision = self.gate.evaluate(context, call)
        except Exception as exc:  # fail closed
            raise RuntimeError(f"gate error, call refused: {exc}") from exc

        if decision.soc_alert and self.on_alert:
            self.on_alert(decision)

        approved_by: str | None = None
        if decision.action is Action.BLOCK:
            self._log(call, decision, None)
            if self.on_alert:
                self.on_alert(decision)
            raise ToolBlocked(decision)
        if decision.action is Action.REQUIRE_APPROVAL:
            approved_by = self.approver(call, decision)
            if not approved_by:
                self._log(call, decision, None)
                raise ApprovalDenied(decision)

        self._log(call, decision, approved_by)
        fn = self.tools.get(call.tool)
        if fn is None:  # declared in policy but not wired up: still refuse
            raise ToolBlocked(decision)
        return fn(call.args)

    def _log(self, call: ToolCall, decision: Decision, approved_by: str | None) -> None:
        if self.audit:
            self.audit.record(call, decision, approved_by=approved_by)
