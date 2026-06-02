import json


def parse_arjun_json(raw_output: str):
    if not raw_output:
        return {}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return {}

    discovered = {}

    for url, value in data.items():
        params = []

        if isinstance(value, dict):
            raw_params = value.get("params", [])

            if isinstance(raw_params, list):
                params = raw_params

        elif isinstance(value, list):
            params = value

        if params:
            discovered[url] = params

    return discovered