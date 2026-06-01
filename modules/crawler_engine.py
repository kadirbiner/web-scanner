import requests
from collections import deque
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from config import (
    CRAWLER_MAX_PAGES,
    CRAWLER_MAX_DEPTH,
    CRAWLER_TIMEOUT,
    CRAWLER_ALLOWED_CONTENT_TYPES
)


def is_same_domain(base_url: str, candidate_url: str) -> bool:
    base_host = urlparse(base_url).netloc
    candidate_host = urlparse(candidate_url).netloc
    return base_host == candidate_host


def normalize_url(url: str) -> str:
    parsed = urlparse(url)

    clean = parsed._replace(fragment="")
    normalized = clean.geturl()

    if normalized.endswith("/") and parsed.path != "/":
        normalized = normalized.rstrip("/")

    return normalized


def should_skip_url(url: str) -> bool:
    blocked_extensions = [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
        ".css", ".js", ".ico", ".woff", ".woff2", ".ttf",
        ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
        ".mp4", ".mp3", ".avi", ".mov"
    ]

    lower_url = url.lower()

    return any(lower_url.endswith(ext) for ext in blocked_extensions)


def extract_links_forms_params(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")

    links = set()
    forms = []
    params = set()

    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()

        if not href:
            continue

        full_url = normalize_url(urljoin(base_url, href))
        parsed = urlparse(full_url)

        for key in parsed.query.split("&"):
            if "=" in key:
                params.add(key.split("=")[0])

        links.add(full_url)

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()

        form_url = normalize_url(urljoin(base_url, action))

        inputs = []

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")

            if name:
                inputs.append(name)
                params.add(name)

        forms.append({
            "action": form_url,
            "method": method,
            "inputs": inputs
        })

    return {
        "links": list(links),
        "forms": forms,
        "params": list(params)
    }


def crawl_page(url: str):
    try:
        response = requests.get(
            url,
            timeout=CRAWLER_TIMEOUT,
            allow_redirects=True,
            verify=False
        )

        content_type = response.headers.get("Content-Type", "")

        if not any(ct in content_type for ct in CRAWLER_ALLOWED_CONTENT_TYPES):
            return None

        return {
            "url": response.url,
            "status": response.status_code,
            "content_type": content_type,
            "body": response.text[:100000]
        }

    except Exception:
        return None


def run_crawler(context):
    base_url = context.target.rstrip("/")

    queue = deque()
    visited = set()

    queue.append((base_url, 0))

    crawled_pages = []
    all_links = set(context.links)
    all_forms = list(context.forms)
    all_params = set(context.params)

    while queue and len(visited) < CRAWLER_MAX_PAGES:
        current_url, depth = queue.popleft()
        current_url = normalize_url(current_url)

        if current_url in visited:
            continue

        if depth > CRAWLER_MAX_DEPTH:
            continue

        if should_skip_url(current_url):
            continue

        if not is_same_domain(base_url, current_url):
            continue

        visited.add(current_url)

        page = crawl_page(current_url)

        if not page:
            continue

        parsed = extract_links_forms_params(page["url"], page["body"])

        page_record = {
            "url": page["url"],
            "status": page["status"],
            "content_type": page["content_type"],
            "depth": depth,
            "links_found": len(parsed["links"]),
            "forms_found": len(parsed["forms"]),
            "params_found": len(parsed["params"])
        }

        crawled_pages.append(page_record)

        for link in parsed["links"]:
            if is_same_domain(base_url, link) and not should_skip_url(link):
                all_links.add(link)

                if link not in visited:
                    queue.append((link, depth + 1))

        for form in parsed["forms"]:
            all_forms.append(form)

        for param in parsed["params"]:
            all_params.add(param)

    context.crawled_pages = crawled_pages
    context.links = list(all_links)
    context.forms = all_forms
    context.params = list(all_params)

    return context