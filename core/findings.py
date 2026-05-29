from core.models import Finding

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}

def add_finding(context, title, severity, url, evidence, recommendation, source):
    finding = Finding(
        title=title,
        severity=severity,
        url=url,
        evidence=evidence,
        recommendation=recommendation,
        source=source
    )

    context.findings.append(finding)

def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True
    )