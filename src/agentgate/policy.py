"""Policy loading. The policy is data (YAML), never code, so it can be reviewed in a PR."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RISK_TIERS = ("read", "write", "egress", "high", "destructive", "persistence")


class PolicyError(ValueError):
    """Raised when a policy file is malformed. AgentGate refuses to start on a bad policy."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk: str
    description: str = ""


@dataclass(frozen=True)
class Policy:
    tools: dict[str, ToolSpec]
    egress_hosts: tuple[str, ...] = ()
    email_domains: tuple[str, ...] = ()
    render_hosts: tuple[str, ...] = ()
    always_approve: frozenset[str] = field(default_factory=lambda: frozenset({"high", "destructive", "persistence"}))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, dict) or not isinstance(data.get("tools"), dict) or not data["tools"]:
            raise PolicyError("policy must declare a non-empty 'tools' mapping")
        tools: dict[str, ToolSpec] = {}
        for name, spec in data["tools"].items():
            risk = (spec or {}).get("risk")
            if risk not in RISK_TIERS:
                raise PolicyError(f"tool '{name}' has invalid risk '{risk}'; expected one of {RISK_TIERS}")
            tools[name] = ToolSpec(name=name, risk=risk, description=(spec or {}).get("description", ""))
        always = frozenset(data.get("always_approve", ["high", "destructive", "persistence"]))
        unknown = always - set(RISK_TIERS)
        if unknown:
            raise PolicyError(f"always_approve contains unknown tiers: {sorted(unknown)}")
        egress = data.get("egress", {}) or {}
        output = data.get("output", {}) or {}
        low = lambda xs: tuple(str(x).lower() for x in (xs or []))
        return cls(
            tools=tools,
            egress_hosts=low(egress.get("hosts")),
            email_domains=low(egress.get("email_domains")),
            render_hosts=low(output.get("render_hosts")),
            always_approve=always,
        )

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(f"cannot parse policy {path}: {exc}") from exc
        return cls.from_dict(data)


def default_policy_path() -> Path:
    """policy/policy.yaml at the repository root."""
    return Path(__file__).resolve().parents[2] / "policy" / "policy.yaml"
