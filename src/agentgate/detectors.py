"""Cheap, explainable detectors.

These are heuristics and they WILL miss paraphrased attacks (see AG-03 and AG-09 in the
red-team suite). That is by design: detection is the first layer, the provenance rules
in gate.py are the control.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Zero-width and bidi-control characters used to hide instructions from human reviewers.
HIDDEN = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")

INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bignore (all |any )?(previous|prior|above) (instructions|prompts?)\b", re.IGNORECASE), "role-override"),
    (re.compile(r"\b(you are now|act as|switch to) (in )?(maintenance|developer|admin|god) mode\b", re.IGNORECASE), "mode-switch"),
    (re.compile(r"\bdisregard (your|the) (system prompt|instructions|rules)\b", re.IGNORECASE), "role-override"),
    (re.compile(r"\b(reveal|print|repeat) (your|the) (system prompt|instructions)\b", re.IGNORECASE), "prompt-extraction"),
    (re.compile(r"\bremember (this )?for (all )?future (sessions|conversations)\b", re.IGNORECASE), "memory-persistence"),
    (re.compile(r"\b(export|dump|download) (the )?(full|entire|all)\b", re.IGNORECASE), "bulk-export-request"),
    (re.compile(r"\b(forward|send|email|post) (it|this|them|the [a-z ]+) to\b", re.IGNORECASE), "exfil-instruction"),
    (re.compile(r"!\[[^\]]*\]\(https?://", re.IGNORECASE), "markdown-image-in-input"),
]

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key-id"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github-token"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key"),
    (re.compile(r"\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}", re.IGNORECASE), "generic-secret"),
]

URL_RE = re.compile(r"https?://[^\s)\"'>]+", re.IGNORECASE)
EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
METADATA_HOSTS = {"localhost", "metadata.google.internal", "metadata", "instance-data"}


def injection_markers(text: str) -> list[str]:
    """Return labels of injection markers found, checking both raw and hidden-char-stripped text."""
    found: list[str] = []
    candidates = [text]
    if HIDDEN.search(text):
        found.append("hidden-unicode")
        candidates.append(HIDDEN.sub("", text))
    for candidate in candidates:
        for pattern, label in INJECTION_PATTERNS:
            if pattern.search(candidate) and label not in found:
                found.append(label)
    return found


def secrets_in(text: str) -> list[str]:
    return [label for pattern, label in SECRET_PATTERNS if pattern.search(text)]


def redact_secrets(text: str) -> str:
    for pattern, label in SECRET_PATTERNS:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text


def urls_in(text: str) -> list[str]:
    return URL_RE.findall(text)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def email_domains_in(text: str) -> list[str]:
    return [d.lower() for d in EMAIL_DOMAIN_RE.findall(text)]


def is_private_or_metadata(host: str) -> bool:
    """Loopback, RFC1918, link-local (169.254.0.0/16 cloud metadata) and well-known metadata names."""
    if host in METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def domain_allowed(host: str, allowlist: tuple[str, ...] | list[str]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allowlist)
