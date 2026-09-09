import re, yaml
from urllib.parse import urljoin
import aiohttp

DEFAULT_PATHS=['/.env','/.git/config','/config.json']

def load_patterns(path):
    with open(path,encoding='utf-8') as f: return yaml.safe_load(f) or []

def scan_text(text, patterns):
    findings=[]
    for rule in patterns:
        try:
            rx=re.compile(rule['regex'])
        except re.error:
            continue
        for m in rx.finditer(text):
            raw=m.group(0)
            masked=raw[:4]+'*'*max(0,len(raw)-8)+raw[-4:] if len(raw)>8 else '*'*len(raw)
            findings.append({'id':rule['id'],'name':rule.get('name',rule['id']),'severity':rule.get('severity','medium'),'match':masked,'offset':m.start()})
    return findings

async def scan_url(base_url, patterns, max_bytes=2_000_000):
    urls={base_url}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15),headers={'User-Agent':'SiteSweep/2.0'}) as s:
        for p in DEFAULT_PATHS: urls.add(urljoin(base_url,p))
        results=[]
        for url in urls:
            try:
                async with s.get(url,allow_redirects=True) as r:
                    body=await r.content.read(max_bytes+1)
                    text=body[:max_bytes].decode('utf-8','ignore')
                    hits=scan_text(text,patterns)
                    if hits: results.append({'url':str(r.url),'status':r.status,'findings':hits})
            except Exception: pass
    return results
