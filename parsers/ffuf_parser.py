import json

def parse_ffuf_output(raw_output: str):
    findings = []

    for line in raw_output.splitlines():
        try:
            item = json.loads(line)

            findings.append({
                "url": item.get("url", ""),
                "status": item.get("status", ""),
                "length": item.get("length", ""),
                "words": item.get("words", ""),
                "redirect": item.get("redirectlocation", "")
            })

        except json.JSONDecodeError:
            continue

    return findings