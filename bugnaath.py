import requests, argparse, re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from pyfiglet import Figlet

# ========== Banner ==========
def print_banner():
    figlet = Figlet(font='slant')
    print("\033[1;92m" + figlet.renderText("BUGNAATH") + "\033[0m")
    print("\033[1;96mSearch Hunter | by Virendra Leelawat\033[0m\n")

# ========== Argument Parser ==========
def get_args():
    parser = argparse.ArgumentParser(description="BugNaath - P4/P5 level vulnerability scanner")
    parser.add_argument('-u', '--url', help='Target URL', required=False)
    parser.add_argument('--list', help='List of URLs (txt file)', required=False)
    parser.add_argument('--deep', help='Enable deep vulnerability scan', action='store_true')
    parser.add_argument('-t', '--timeout', help='Request timeout', type=int, default=10)
    parser.add_argument('--threads', help='Number of threads', type=int, default=5)
    parser.add_argument('-o', '--output', help='Save output to file', required=False)
    return parser.parse_args()

# ========== Header Check ==========
def check_missing_headers(url):
    issues = []
    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        if 'X-Frame-Options' not in headers:
            issues.append(f"Missing Header: X-Frame-Options => {url}")
        if 'X-Content-Type-Options' not in headers:
            issues.append(f"Missing Header: X-Content-Type-Options => {url}")
        if 'Strict-Transport-Security' not in headers:
            issues.append(f"Missing Header: Strict-Transport-Security => {url}")
        if 'Content-Security-Policy' not in headers:
            issues.append(f"Missing Header: Content-Security-Policy => {url}")
    except:
        issues.append(f"Request failed or timed out => {url}")
    return issues

# ========== SQLi ==========
def check_sqli(url):
    payloads = ["'", "'--", "\"", "`", "' OR 1=1--", "\" OR 1=1--"]
    vulnerable = []
    for p in payloads:
        test_url = inject_payload(url, p)
        try:
            r = requests.get(test_url, timeout=8)
            if re.search(r"SQL|syntax|mysqli?|error in your", r.text, re.I):
                vulnerable.append(f"Possible SQLi: {test_url}")
        except: pass
    return vulnerable

# ========== XSS ==========
def check_xss(url):
    payload = "<script>alert(1)</script>"
    test_url = inject_payload(url, payload)
    try:
        r = requests.get(test_url, timeout=8)
        if payload in r.text:
            return [f"Possible XSS: {test_url}"]
    except: pass
    return []

# ========== Parameter Injection Helper ==========
def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        return url
    injected = "&".join([f"{k}={payload}" for k in query])
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{injected}"

# ========== Sensitive Files ==========
def check_sensitive_files(base_url):
    paths = ['.env', 'phpinfo.php', '.git/config', 'config.php', 'backup.zip']
    found = []
    for path in paths:
        full_url = f"{base_url.rstrip('/')}/{path}"
        try:
            r = requests.get(full_url, timeout=6)
            if r.status_code == 200 and ("DB_" in r.text or "phpinfo" in r.text or "root" in r.text):
                found.append(f"Sensitive file exposed: {full_url}")
        except: pass
    return found

# ========== Deep Scan ==========
def deep_scan(url):
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    findings += check_missing_headers(url)
    findings += check_sqli(url)
    findings += check_xss(url)
    findings += check_sensitive_files(base)

    # Heuristic Warnings (attach URL to each)
    warnings = [
        "Possible IDOR (check for user-id or resource access)",
        "Potential CSRF (no CSRF tokens detected)",
        "RCE/SSRF/SSTI/XXE: Manual review suggested",
        "Subdomain takeover: Check DNS + 404 response patterns",
        "Rate Limiting: Try multiple fast requests",
        "Origin IP Exposure: Look for IP in response headers",
    ]
    for w in warnings:
        findings.append(f"{w} => {url}")

    return findings

# ========== Scan Dispatcher ==========
def scan_target(url, deep=False):
    print(f"\n[*] Scanning: {url}")
    results = deep_scan(url) if deep else check_missing_headers(url)
    for issue in results:
        print("\033[93m- " + issue + "\033[0m")
    return results

# ========== Main ==========
def main():
    args = get_args()
    print_banner()
    targets = []

    if args.url:
        targets.append(args.url)
    elif args.list:
        with open(args.list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_target, url, args.deep) for url in targets]
        for f in futures:
            result = f.result()
            all_results.extend(result)

    if args.output:
        with open(args.output, 'w') as f:
            for line in all_results:
                f.write(line + '\n')

if __name__ == "__main__":
    main()
