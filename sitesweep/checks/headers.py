SECURITY_HEADERS={'strict-transport-security':'high','content-security-policy':'high','x-content-type-options':'medium','referrer-policy':'low','permissions-policy':'low','x-frame-options':'medium'}

def check_headers(headers):
    lower={k.lower():v for k,v in headers.items()}
    return [{'header':h,'severity':sev,'issue':f'Missing {h}'} for h,sev in SECURITY_HEADERS.items() if h not in lower]
