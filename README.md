# SiteSweep v2

A scoped web reconnaissance and defensive vulnerability-scanning toolkit for authorized security testing and bug-bounty targets.

## Features
- crt.sh passive subdomain enumeration
- Optional DNS brute-force wordlist
- Async DNS resolution and HTTP/HTTPS alive checks
- Optional scope-file enforcement for active targets
- Regex-based secret scanning with masked evidence
- Basic exposed-file checks (`.env`, `.git/config`, `config.json`)
- URL query-parameter extraction helper
- Security-header checker module
- JSON and HTML reports

## Install
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
pip install -e .
```

## Examples
```bash
sitesweep recon example.com --subdomains --output subs.json
sitesweep recon example.com --subdomains --wordlist data/subdomains.txt --scope scope.txt --output subs.json
sitesweep secrets https://example.com --scope scope.txt --output secrets.json
sitesweep scan https://example.com --scope scope.txt --checks secrets --output report.html
```

Only test assets you are explicitly authorized to assess. Use a scope file for bug-bounty programs and keep concurrency/rate limits conservative.
