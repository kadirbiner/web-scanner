from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

def normalize_base_url(target: str) -> str:
    return target.rstrip("/")

def get_hostname(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc or parsed.path.split("/")[0]

def join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

def extract_query_params(url: str) -> dict:
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]

    new_query = urlencode(query, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))