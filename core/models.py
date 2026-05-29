from dataclasses import dataclass, field
from typing import list, dict, Any

@dataclass
class Finding:
    title: str
    severity: str
    url: str
    evidence: str
    recommendation: str
    source: str

@dataclass
class ScanContext:
    target: str
    headers: dict = field(default_factory=dict)
    technologies: str = ""
    ports: str = ""
    ffuf_findings: list = field(default_factory=list)
    robots_entries: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    params: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)