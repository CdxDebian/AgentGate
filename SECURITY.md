# Security Policy

AgentGate is a security control, so bypasses matter. If you find a way to get a side-effecting
tool call past the gate (a missed rule, a parsing trick, an allowlist bypass), please report it
privately via GitHub's **Report a vulnerability** (Security → Advisories) rather than opening a
public issue.

Useful reports include the context segments, the proposed tool call, the decision AgentGate
returned and the decision you expected. Confirmed bypasses are added to
`redteam/scenarios.yaml` so CI guards against them permanently.
