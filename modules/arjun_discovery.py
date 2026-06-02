import json
from urllib.parse import urlparse

from core.runner import run_command
from config import ARJUN_MAX_URLS, ARJUN_TIMEOUT


def is_interesting_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()

    if not path:
        return False

    ignored_extensions = [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf",
        ".zip", ".rar", ".7z"
    ]

    if any(path.endswith(ext) for ext in ignored_extensions):
        return False

    interesting_extensions = [
        ".php", ".asp", ".aspx", ".jsp", ".do", ".action"
    ]

    if any(path.endswith(ext) for ext in interesting_extensions):
        return True

    return False


def build_arjun_targets(context):
    targets = set()

    for link in context.links:
        if is_interesting_url(link):
            targets.add(link.split("?")[0])

    for form in context.forms:
        action = form.get("action", "")
        if action and is_interesting_url(action):
            targets.add(action.split("?")[0])

    return list(targets)[:ARJUN_MAX_URLS]


def parse_arjun_output(raw_output: str):
    discovered = {}

    try:
        data = json.loads(raw_output)

        for url, value in data.items():
            params = []

            if isinstance(value, dict):
                params = value.get("params", [])

            elif isinstance(value, list):
                params = value

            discovered[url] = params

    except Exception:
        for line in raw_output.splitlines():
            line = line.strip()

            if not line:
                continue

            if "Parameters found:" in line:
                continue

            if line.startswith("[") or line.startswith("{"):
                continue

    return discovered


async def run_arjun_discovery(context):
    targets = build_arjun_targets(context)

    context.raw["arjun_targets"] = targets
    context.raw["arjun"] = {}

    for target in targets:
        command = [
            "arjun",
            "-u", target,
            "-oJ", "-"
        ]

        result = await run_command(command, timeout=ARJUN_TIMEOUT)

        context.raw["arjun"][target] = result

    return context