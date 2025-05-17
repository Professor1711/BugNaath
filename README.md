# 🛡️ BugNaath - Search Hunter | by Virendra Leelawat

BugNaath is a powerful, real-world P4/P5-level vulnerability scanner built for ethical hackers and bug bounty hunters. It performs deep scanning to detect common low to medium severity issues that are often overlooked — like XSS, SQLi, IDOR, CSRF, Sensitive Files, Rate Limiting, Subdomain Takeover, and more.

---

## 🔍 Features

- ✅ Smart Payload Injection (SQLi, XSS, etc.)
- ✅ Deep Vulnerability Scanning (`--deep` flag)
- ✅ Sensitive File Detection (`.env`, `phpinfo.php`, `config.php`, etc.)
- ✅ Security Misconfiguration Detection (Missing Headers, Open Directories)
- ✅ Rate Limiting & Origin IP Exposure Detection
- ✅ Subdomain Takeover Heuristic Warnings
- ✅ RCE, SSRF, SSTI, XXE - Warning-based Deep Tests
- ✅ Auto URL Parameter Extraction
- ✅ Multithreaded Scanning Support
- ✅ Clean CLI Output + Optional File Output
- ✅ Single URL or Bulk URL Scanning from File

---

## 🚀 Usage

### 🔗 Scan a Single URL
```bash
python3 bugnaath.py -u https://target.com/page.php?id=123
🧠 Deep Scan for All Vulnerabilities
python3 bugnaath.py -u https://target.com/page.php?id=123 --deep
📁 Scan URLs in Bulk
python3 bugnaath.py --list targets.txt --deep
💾 Save Output to File
python3 bugnaath.py -u https://target.com --deep -o report.txt
⚙️ Command-Line Options
Flag	Description
-u / --url	Target URL to scan
--list	    Path to file with list of target URLs
--deep	    Enable deep scan (includes IDOR, SSRF, etc.)
-o	        Save results to file
-t	        Request timeout in seconds (default: 10)
--threads	  Number of concurrent threads (default: 5)

🧪 Sample Output
[*] Scanning: https://target.com/page.php?id=2
- Missing Header: Content-Security-Policy
- Missing Header: X-Frame-Options
- Possible SQLi: https://target.com/page.php?id='
- Possible XSS: https://target.com/page.php?id=<script>alert(1)</script>
- Possible IDOR: https://target.com/page.php?id=2
- Sensitive File Found: https://target.com/.env
- Potential Subdomain Takeover: unresolvable.test.target.com
- Rate Limiting Possible: Try flooding same endpoint
- Origin IP Exposure: Server leaked internal IP 10.0.0.1

⚠️ Legal Disclaimer
This tool is intended only for educational purposes and for use in authorized environments.
Do NOT scan any website without proper legal permission. Unauthorized use may be illegal.

👨‍💻 Author
Virendra Leelawat
Tagline: Search Hunter | BugNaath
Tool written in Python 3.9+ with ❤️
