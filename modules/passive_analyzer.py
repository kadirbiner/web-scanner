from config import SECURITY_HEADERS, INTERESTING_KEYWORDS
from core.findings import add_finding
from parsers.ffuf_parser import parse_ffuf_output
from parsers.html_parser import parse_links_forms_params


def analyze_security_headers(context):
    for header in SECURITY_HEADERS:
        if header not in context.headers:
            add_finding(
                context=context,
                title=f"Missing Security Header: {header}",
                severity="LOW",
                url=context.target,
                evidence=f"{header} header bulunamadı.",
                recommendation=f"{header} güvenlik başlığını yapılandır.",
                source="Passive Analysis"
            )


def analyze_ffuf(context):
    raw = context.raw.get("ffuf", {}).get("stdout", "")
    findings = parse_ffuf_output(raw)
    context.ffuf_findings = findings

    for item in findings:
        url = item.get("url", "").lower()
        status = str(item.get("status", ""))

        if any(keyword in url for keyword in INTERESTING_KEYWORDS):
            severity = "MEDIUM"
            title = "Interesting Endpoint Found"
            recommendation = "Endpoint erişimi ve içerik sızıntısı kontrol edilmeli."

            if any(x in url for x in [".git", ".env", "backup", "db.sql", "dump", "config", "server-status", "phpinfo"]):
                severity = "HIGH"
                title = "Potential Sensitive Endpoint or File Exposure"
                recommendation = "Hassas endpoint/dosyalar web root dışına alınmalı veya erişim engellenmeli."

            add_finding(
                context=context,
                title=title,
                severity=severity,
                url=item.get("url", ""),
                evidence=f"Status: {status}, Length: {item.get('length')}",
                recommendation=recommendation,
                source="Discovery / FFUF"
            )

        elif status == "403":
            add_finding(
                context=context,
                title="Forbidden Endpoint Exists",
                severity="INFO",
                url=item.get("url", ""),
                evidence="HTTP 403 döndü. Endpoint mevcut olabilir.",
                recommendation="Gereksiz endpointler kaldırılmalı veya erişim politikası kontrol edilmeli.",
                source="Discovery / FFUF"
            )


def analyze_html(context):
    html = context.raw.get("homepage_body", "")

    if not html:
        return

    parsed = parse_links_forms_params(context.target, html)

    # Önemli: Crawler verilerini ezme, birleştir.
    context.links = list(set(context.links + parsed["links"]))
    context.forms = context.forms + parsed["forms"]
    context.params = list(set(context.params + parsed["params"]))

    for form in parsed["forms"]:
        add_finding(
            context=context,
            title="Form Detected",
            severity="INFO",
            url=form["action"],
            evidence=f"Method: {form['method']}, Inputs: {', '.join(form['inputs'])}",
            recommendation="Form inputları validasyon, CSRF ve rate-limit açısından incelenmeli.",
            source="Passive Analysis"
        )

    for param in parsed["params"]:
        add_finding(
            context=context,
            title="URL/Form Parameter Detected",
            severity="INFO",
            url=context.target,
            evidence=f"Parameter: {param}",
            recommendation="Parametreler güvenli doğrulama ve encoding ile işlenmeli.",
            source="Passive Analysis"
        )


def analyze_robots(context):
    for item in context.robots_entries:
        add_finding(
            context=context,
            title="Robots/Sitemap File Found",
            severity="INFO",
            url=item["url"],
            evidence="robots.txt veya sitemap.xml bulundu.",
            recommendation="Hassas yollar robots.txt içinde ifşa edilmemeli.",
            source="Passive Analysis"
        )


def run_passive_analysis(context):
    analyze_security_headers(context)
    analyze_ffuf(context)
    analyze_html(context)
    analyze_robots(context)

    return context