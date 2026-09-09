from urllib.parse import urlparse, parse_qs

def extract_url_params(url):
    return sorted(parse_qs(urlparse(url).query).keys())
