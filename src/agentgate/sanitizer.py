"""Output handling (OWASP LLM05).

A model reply rendered as markdown can leak data with zero clicks: an image whose URL
carries the conversation in its query string is fetched the moment the reply is shown.
Strip images and links that point anywhere outside the render allowlist.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors import domain_allowed, host_of

_IMAGE = re.compile(r"!\[([^\]]*)\]\((https?://[^)\s]+)[^)]*\)")
_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\((https?://[^)\s]+)[^)]*\)")


@dataclass
class SanitizeResult:
    text: str
    findings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.findings)


def sanitize_output(text: str, render_hosts: tuple[str, ...] | list[str]) -> SanitizeResult:
    findings: list[str] = []

    def _image(m: re.Match[str]) -> str:
        host = host_of(m.group(2))
        if domain_allowed(host, render_hosts):
            return m.group(0)
        findings.append(f"image to non-allowlisted host removed: {host}")
        return "[image removed by the sanitiser]"

    def _link(m: re.Match[str]) -> str:
        host = host_of(m.group(2))
        if domain_allowed(host, render_hosts):
            return m.group(0)
        findings.append(f"link de-linked: {host}")
        return f"{m.group(1)} (external link removed: {host})"

    out = _IMAGE.sub(_image, text)
    out = _LINK.sub(_link, out)
    return SanitizeResult(out, findings)
