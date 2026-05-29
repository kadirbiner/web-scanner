import requests
from utils.url_utils import join_url

def run_robots_discovery(context):
    robots_url = join_url(context.target, "/robots.txt")
    sitemap_url = join_url(context.target, "/sitemap.xml")

    entries = []

    for url in [robots_url, sitemap_url]:
        try:
            response = requests.get(url, timeout=10, verify=False)

            if response.status_code == 200:
                entries.append({
                    "url": url,
                    "status": response.status_code,
                    "body": response.text[:5000]
                })

        except Exception:
            continue

    context.robots_entries = entries

    return context