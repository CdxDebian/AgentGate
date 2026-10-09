"""AgentGate — a provenance-aware policy gate for AI-agent tool calls."""
from .audit import AuditLog
from .enforce import ApprovalDenied, Guard, ToolBlocked
from .gate import Action, Decision, Gate, Segment, ToolCall
from .policy import Policy, PolicyError
from .sanitizer import sanitize_output

__version__ = "1.0.0"
__all__ = ["Action", "ApprovalDenied", "AuditLog", "Decision", "Gate", "Guard", "Policy",
           "PolicyError", "Segment", "ToolBlocked", "ToolCall", "sanitize_output"]
