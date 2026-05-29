import requests
from config import DEFAULT_TIMEOUT

def run_header_recon(context):
    try:
        response = requests.get(
            context.target,
            timeout=10,
            allow_redirects=True,
            verify=False
        )

        context.headers = dict(response.headers)
        context.raw["homepage_status"] = response.status_code
        context.raw["homepage_body"] = response.text[:50000]

    except Exception as e:
        context.raw["homepage_error"] = str(e)

    return context