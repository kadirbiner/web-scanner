from urllib.parse import urlparse, parse_qs
from core.findings import add_finding


PARAMETER_RULES = {
    "SQLI_CANDIDATE": [
        "id", "uid", "user", "product", "item", "cat", "category",
        "page_id", "post", "article", "news", "pid"
    ],
    "LFI_CANDIDATE": [
        "file", "path", "page", "template", "include", "view",
        "doc", "document", "folder", "dir"
    ],
    "XSS_CANDIDATE": [
        "q", "query", "search", "s", "keyword", "term",
        "name", "message", "comment", "text"
    ],
    "REDIRECT_CANDIDATE": [
        "url", "next", "redirect", "redirect_url", "return",
        "return_url", "continue", "callback"
    ],
    "AUTH_CANDIDATE": [
        "username", "user", "email", "password", "pass",
        "token", "session", "jwt", "key", "api_key"
    ]
}


def classify_parameter(param_name: str):
    param = param_name.lower()
    matches = []

    for category, keywords in PARAMETER_RULES.items():
        if param in keywords or any(keyword in param for keyword in keywords):
            matches.append(category)

    return matches


def collect_parameters_from_links(context):
    parameter_map = {}

    for link in context.links:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        for param in query.keys():
            if param not in parameter_map:
                parameter_map[param] = set()

            parameter_map[param].add(link)

    for form in context.forms:
        action = form.get("action", "")
        inputs = form.get("inputs", [])

        for param in inputs:
            if param not in parameter_map:
                parameter_map[param] = set()

            parameter_map[param].add(action)

    return parameter_map


def run_parameter_analysis(context):
    parameter_map = collect_parameters_from_links(context)

    context.raw["parameter_analysis"] = {}

    for param, urls in parameter_map.items():
        categories = classify_parameter(param)

        context.raw["parameter_analysis"][param] = {
            "categories": categories,
            "urls": list(urls)
        }

        if not categories:
            add_finding(
                context=context,
                title="Parameter Detected",
                severity="INFO",
                url=list(urls)[0],
                evidence=f"Parameter: {param}",
                recommendation="Parametre input validation ve output encoding açısından incelenmeli.",
                source="Parameter Analyzer"
            )
            continue

        severity = "INFO"

        if "SQLI_CANDIDATE" in categories:
            severity = "MEDIUM"

        if "LFI_CANDIDATE" in categories:
            severity = "MEDIUM"

        if "REDIRECT_CANDIDATE" in categories:
            severity = "MEDIUM"

        if "AUTH_CANDIDATE" in categories:
            severity = "MEDIUM"

        add_finding(
            context=context,
            title="Interesting Parameter Candidate",
            severity=severity,
            url=list(urls)[0],
            evidence=f"Parameter: {param}, Categories: {', '.join(categories)}",
            recommendation="Bu parametre güvenli test modülleriyle ayrıca doğrulanmalı.",
            source="Parameter Analyzer"
        )

    return context