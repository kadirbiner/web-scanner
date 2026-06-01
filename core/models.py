from dataclasses import dataclass, field
from typing import Any


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

    headers: dict[str, str] = field(default_factory=dict)

    technologies: str = ""
    ports: str = ""

    ffuf_findings: list[dict] = field(default_factory=list)
    robots_entries: list[dict] = field(default_factory=list)

    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)

    crawled_pages: list[dict] = field(default_factory=list)

    findings: list[Finding] = field(default_factory=list)

    raw: dict[str, Any] = field(default_factory=dict)