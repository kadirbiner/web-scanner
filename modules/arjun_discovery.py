import json
from urllib.parse import urlparse

from core.runner import run_command
from config import ARJUN_MAX_URLS, ARJUN_TIMEOUT
from parsers.arjun_parser import parse_arjun_json


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

    return any(path.endswith(ext) for ext in interesting_extensions)


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


def extract_discovered_parameters(context):
    discovered = {}

    arjun_results = context.raw.get("arjun", {})

    for target_url, result in arjun_results.items():
        raw_output = result.get("stdout", "")
        parsed = parse_arjun_json(raw_output)

        params = []

        for _, found_params in parsed.items():
            params.extend(found_params)

        discovered[target_url] = sorted(list(set(params)))

    context.raw["arjun_discovered"] = discovered
    return context


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

    context = extract_discovered_parameters(context)

    return context