import requests
from config import SQL_ERROR_SIGNATURES, DEBUG_ERROR_SIGNATURES
from core.findings import add_finding
from utils.url_utils import replace_query_param

def check_debug_errors(context):
    body = context.raw.get("homepage_body", "")

    for signature in DEBUG_ERROR_SIGNATURES:
        if signature.lower() in body.lower():
            add_finding(
                context=context,
                title="Debug/Error Disclosure Signal",
                severity="MEDIUM",
                url=context.target,
                evidence=f"Error signature detected: {signature}",
                recommendation="Production ortamında hata detayları kapatılmalı.",
                source="Safe Vuln Signal"
            )

def check_sql_error_signals(context):
    test_urls = []

    for link in context.links:
        if "?" in link:
            test_urls.append(link)

    for url in test_urls[:10]:
        try:
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params.keys():
                test_url = replace_query_param(url, param, "'")

                response = requests.get(
                    test_url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                body = response.text

                for signature in SQL_ERROR_SIGNATURES:
                    if signature.lower() in body.lower():
                        add_finding(
                            context=context,
                            title="Possible SQL Error-Based Injection Signal",
                            severity="HIGH",
                            url=test_url,
                            evidence=f"SQL error signature detected: {signature}",
                            recommendation="Parametreli sorgular/prepared statements kullanılmalı.",
                            source="Safe Vuln Signal"
                        )
                        break

        except Exception:
            continue

def check_xss_reflection_signals(context):
    marker = "SCANNER_REFLECTION_TEST_12345"

    for link in context.links[:20]:
        if "?" not in link:
            continue

        try:
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(link)
            params = parse_qs(parsed.query)

            for param in params.keys():
                test_url = replace_query_param(link, param, marker)

                response = requests.get(
                    test_url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                if marker in response.text:
                    add_finding(
                        context=context,
                        title="Reflected Input Signal",
                        severity="MEDIUM",
                        url=test_url,
                        evidence=f"Marker reflected in response: {marker}",
                        recommendation="Kullanıcı girdileri HTML context'e uygun encode edilmeli.",
                        source="Safe Vuln Signal"
                    )

        except Exception:
            continue

def check_lfi_risk_signals(context):
    risky_names = [
        "file",
        "path",
        "page",
        "template",
        "include",
        "view",
        "document"
    ]

    for param in context.params:
        if param.lower() in risky_names:
            add_finding(
                context=context,
                title="Potential File Include Parameter",
                severity="MEDIUM",
                url=context.target,
                evidence=f"Risky parameter name detected: {param}",
                recommendation="Dosya yolu alan parametrelerde allowlist kullanılmalı.",
                source="Safe Vuln Signal"
            )

def run_safe_signals(context):
    check_debug_errors(context)
    check_sql_error_signals(context)
    check_xss_reflection_signals(context)
    check_lfi_risk_signals(context)

    return context