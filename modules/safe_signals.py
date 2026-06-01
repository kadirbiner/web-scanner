import requests

from config import SQL_ERROR_SIGNATURES, DEBUG_ERROR_SIGNATURES
from core.findings import add_finding
from utils.url_utils import replace_query_param


MAX_TEST_URLS_PER_PARAM = 5

SQL_TEST_VALUE = "'"
XSS_MARKER = "SCANNER_REFLECTION_TEST_12345"
LFI_TEST_VALUE = "../scanner_lfi_test"
REDIRECT_TEST_VALUE = "https://example.com/scanner_redirect_test"


def get_parameter_analysis(context):
    return context.raw.get("parameter_analysis", {})


def safe_get(url: str):
    try:
        return requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
    except Exception:
        return None


def check_debug_errors(context):
    pages_to_check = []

    homepage_body = context.raw.get("homepage_body", "")
    if homepage_body:
        pages_to_check.append({
            "url": context.target,
            "body": homepage_body
        })

    for page in context.crawled_pages:
        url = page.get("url")
        if not url:
            continue

        response = safe_get(url)
        if response is None:
            continue

        pages_to_check.append({
            "url": url,
            "body": response.text[:50000]
        })

    checked = set()

    for page in pages_to_check:
        url = page["url"]

        if url in checked:
            continue

        checked.add(url)
        body = page["body"]

        for signature in DEBUG_ERROR_SIGNATURES:
            if signature.lower() in body.lower():
                add_finding(
                    context=context,
                    title="Debug/Error Disclosure Signal",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"Error signature detected: {signature}",
                    recommendation="Production ortamında hata detayları kapatılmalı.",
                    source="Safe Vuln Signal"
                )
                break


def check_sql_error_signals(context):
    analysis = get_parameter_analysis(context)

    for param, data in analysis.items():
        categories = data.get("categories", [])
        urls = data.get("urls", [])

        if "SQLI_CANDIDATE" not in categories:
            continue

        for url in urls[:MAX_TEST_URLS_PER_PARAM]:
            if "?" not in url:
                continue

            test_url = replace_query_param(url, param, SQL_TEST_VALUE)
            response = safe_get(test_url)

            if response is None:
                continue

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
                        source="Safe Vuln Signal / Parameter Analyzer"
                    )
                    break


def check_xss_reflection_signals(context):
    analysis = get_parameter_analysis(context)

    for param, data in analysis.items():
        categories = data.get("categories", [])
        urls = data.get("urls", [])

        if "XSS_CANDIDATE" not in categories:
            continue

        for url in urls[:MAX_TEST_URLS_PER_PARAM]:
            if "?" not in url:
                continue

            test_url = replace_query_param(url, param, XSS_MARKER)
            response = safe_get(test_url)

            if response is None:
                continue

            if XSS_MARKER in response.text:
                add_finding(
                    context=context,
                    title="Reflected Input Signal",
                    severity="MEDIUM",
                    url=test_url,
                    evidence=f"Marker reflected in response: {XSS_MARKER}",
                    recommendation="Kullanıcı girdileri HTML context'e uygun encode edilmeli.",
                    source="Safe Vuln Signal / Parameter Analyzer"
                )


def check_lfi_risk_signals(context):
    analysis = get_parameter_analysis(context)

    for param, data in analysis.items():
        categories = data.get("categories", [])
        urls = data.get("urls", [])

        if "LFI_CANDIDATE" not in categories:
            continue

        for url in urls[:MAX_TEST_URLS_PER_PARAM]:
            if "?" not in url:
                continue

            test_url = replace_query_param(url, param, LFI_TEST_VALUE)
            response = safe_get(test_url)

            if response is None:
                continue

            lower_body = response.text.lower()

            lfi_indicators = [
                "failed to open stream",
                "no such file",
                "include_path",
                "warning",
                "open_basedir",
                "permission denied"
            ]

            for indicator in lfi_indicators:
                if indicator in lower_body:
                    add_finding(
                        context=context,
                        title="Possible LFI/Error Disclosure Signal",
                        severity="MEDIUM",
                        url=test_url,
                        evidence=f"LFI-related error indicator detected: {indicator}",
                        recommendation="Dosya yolu alan parametrelerde allowlist kullanılmalı.",
                        source="Safe Vuln Signal / Parameter Analyzer"
                    )
                    break


def check_redirect_signals(context):
    analysis = get_parameter_analysis(context)

    for param, data in analysis.items():
        categories = data.get("categories", [])
        urls = data.get("urls", [])

        if "REDIRECT_CANDIDATE" not in categories:
            continue

        for url in urls[:MAX_TEST_URLS_PER_PARAM]:
            if "?" not in url:
                continue

            test_url = replace_query_param(url, param, REDIRECT_TEST_VALUE)
            response = safe_get(test_url)

            if response is None:
                continue

            location = response.headers.get("Location", "")

            if REDIRECT_TEST_VALUE in location:
                add_finding(
                    context=context,
                    title="Possible Open Redirect Signal",
                    severity="MEDIUM",
                    url=test_url,
                    evidence=f"Redirect Location: {location}",
                    recommendation="Redirect parametrelerinde allowlist kullanılmalı.",
                    source="Safe Vuln Signal / Parameter Analyzer"
                )


def check_auth_parameter_signals(context):
    analysis = get_parameter_analysis(context)

    for param, data in analysis.items():
        categories = data.get("categories", [])
        urls = data.get("urls", [])

        if "AUTH_CANDIDATE" not in categories:
            continue

        add_finding(
            context=context,
            title="Authentication/Sensitive Parameter Detected",
            severity="LOW",
            url=urls[0] if urls else context.target,
            evidence=f"Parameter: {param}, URLs: {len(urls)}",
            recommendation="Auth parametreleri rate-limit, CSRF, session güvenliği ve brute-force koruması açısından incelenmeli.",
            source="Safe Vuln Signal / Parameter Analyzer"
        )


def run_safe_signals(context):
    check_debug_errors(context)
    check_sql_error_signals(context)
    check_xss_reflection_signals(context)
    check_lfi_risk_signals(context)
    check_redirect_signals(context)
    check_auth_parameter_signals(context)

    return context