from urllib.parse import urlparse

class Scope:
    def __init__(self, patterns):
        self.patterns = [p.strip().lower() for p in patterns if p.strip() and not p.lstrip().startswith('#')]

    @classmethod
    def from_file(cls, path):
        with open(path, encoding='utf-8') as f:
            return cls(f.readlines())

    def allows_host(self, host):
        host = (host or '').lower().rstrip('.')
        for p in self.patterns:
            p = p.rstrip('.').lower()
            if p.startswith('*.'):
                base = p[2:]
                if host == base or host.endswith('.' + base):
                    return True
            elif host == p:
                return True
        return False

    def allows_url(self, url):
        return self.allows_host(urlparse(url).hostname)
