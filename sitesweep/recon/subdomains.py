import asyncio, re
import aiohttp
import dns.asyncresolver

async def crtsh(domain):
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(url, headers={'User-Agent':'SiteSweep/2.0'}) as r:
                if r.status != 200: return set()
                data = await r.json(content_type=None)
        out=set()
        for row in data:
            for name in row.get('name_value','').splitlines():
                name=name.strip().lower()
                if name.startswith('*.'): name=name[2:]
                if name == domain or name.endswith('.'+domain): out.add(name)
        return out
    except Exception:
        return set()

async def resolve(host, resolver):
    try:
        ans = await resolver.resolve(host, 'A')
        return [a.to_text() for a in ans]
    except Exception:
        return []

async def probe(session, host):
    for scheme in ('https','http'):
        url=f'{scheme}://{host}/'
        try:
            async with session.get(url, allow_redirects=True, max_redirects=3) as r:
                text=await r.text(errors='ignore')
                m=re.search(r'<title[^>]*>(.*?)</title>', text, re.I|re.S)
                return {'url':str(r.url),'status':r.status,'title':re.sub(r'\s+',' ',m.group(1)).strip()[:200] if m else '', 'content_type':r.headers.get('content-type','')}
        except Exception:
            continue
    return None

async def enumerate_subdomains(domain, wordlist=None, scope=None, concurrency=30):
    domain=domain.strip().lower().rstrip('.')
    found=await crtsh(domain)
    if wordlist:
        with open(wordlist, encoding='utf-8', errors='ignore') as f:
            candidates={f'{x.strip().lower()}.{domain}' for x in f if x.strip() and not x.startswith('#')}
        found |= candidates
    if scope:
        found={h for h in found if scope.allows_host(h)}
    resolver=dns.asyncresolver.Resolver()
    sem=asyncio.Semaphore(concurrency)
    async def one(h):
        async with sem:
            ips=await resolve(h,resolver)
            return h,ips
    resolved=dict(await asyncio.gather(*(one(h) for h in sorted(found))))
    timeout=aiohttp.ClientTimeout(total=10)
    connector=aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(timeout=timeout,connector=connector,headers={'User-Agent':'SiteSweep/2.0'}) as session:
        async def p(h):
            if not resolved[h]: return {'hostname':h,'ips':[],'alive':False}
            result=await probe(session,h)
            return {'hostname':h,'ips':resolved[h],'alive':bool(result),'http':result}
        return await asyncio.gather(*(p(h) for h in sorted(found)))
