from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

def parse_links_forms_params(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")

    links = []
    forms = []
    params = set()

    for a in soup.find_all("a", href=True):
        full_url = urljoin(base_url, a["href"])
        links.append(full_url)

        parsed = urlparse(full_url)
        query = parse_qs(parsed.query)

        for key in query.keys():
            params.add(key)

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        full_action = urljoin(base_url, action)

        inputs = []

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append(name)
                params.add(name)

        forms.append({
            "action": full_action,
            "method": method,
            "inputs": inputs
        })

    return {
        "links": list(set(links)),
        "forms": forms,
        "params": list(params)
    }