import html

def write(data,path):
    findings=[]
    for x in data.get('secrets',[]):
        for f in x.get('findings',[]): findings.append(f"<li><b>{html.escape(f['severity'])}</b> — {html.escape(f['name'])} — {html.escape(x['url'])} — {html.escape(f['match'])}</li>")
    subs=data.get('subdomains',[])
    rows=''.join(f"<tr><td>{html.escape(s['hostname'])}</td><td>{s.get('http',{}).get('status','')}</td><td>{html.escape(s.get('http',{}).get('title',''))}</td></tr>" for s in subs if s.get('alive'))
    doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>SiteSweep Report</title><style>body{{font:15px system-ui;margin:40px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left}}</style></head><body><h1>SiteSweep Report</h1><h2>Live Subdomains</h2><table><tr><th>Host</th><th>Status</th><th>Title</th></tr>{rows}</table><h2>Secret Findings</h2><ul>{''.join(findings) or '<li>None detected</li>'}</ul></body></html>'''
    with open(path,'w',encoding='utf-8') as f:f.write(doc)
