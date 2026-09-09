import argparse, asyncio
from .scope import Scope
from .recon.subdomains import enumerate_subdomains
from .checks.secrets import load_patterns, scan_url
from .report.json_report import write as json_write
from .report.html_report import write as html_write

def main():
    p=argparse.ArgumentParser(prog='sitesweep')
    sub=p.add_subparsers(dest='cmd',required=True)
    r=sub.add_parser('recon'); r.add_argument('domain'); r.add_argument('--subdomains',action='store_true'); r.add_argument('--wordlist'); r.add_argument('--scope'); r.add_argument('--output',default='subs.json')
    s=sub.add_parser('secrets'); s.add_argument('url'); s.add_argument('--patterns',default='data/secret_patterns.yaml'); s.add_argument('--scope'); s.add_argument('--output',default='secrets.json')
    a=sub.add_parser('scan'); a.add_argument('url'); a.add_argument('--checks',default='headers,secrets'); a.add_argument('--scope'); a.add_argument('--patterns',default='data/secret_patterns.yaml'); a.add_argument('--output',default='report.html')
    args=p.parse_args()
    scope=Scope.from_file(args.scope) if getattr(args,'scope',None) else None
    if scope and not scope.allows_url(args.url if hasattr(args,'url') else 'https://'+args.domain): p.error('Target is outside supplied scope')
    if args.cmd=='recon':
        data={'subdomains':asyncio.run(enumerate_subdomains(args.domain,args.wordlist,scope))}
    elif args.cmd=='secrets':
        data={'secrets':asyncio.run(scan_url(args.url,load_patterns(args.patterns)))}
    else:
        data={}
        checks=set(args.checks.split(','))
        if 'secrets' in checks: data['secrets']=asyncio.run(scan_url(args.url,load_patterns(args.patterns)))
    (html_write if args.output.endswith('.html') else json_write)(data,args.output)
    print(f'Wrote {args.output}')

if __name__=='__main__': main()
