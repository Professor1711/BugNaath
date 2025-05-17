# 🛡️ BugNaath - Search Hunter | by Virendra Leelawat

BugNaath is a powerful, real-world P4/P5-level vulnerability scanner built for ethical hackers and bug bounty hunters. It performs deep scanning to detect common low to medium severity issues that are often overlooked — like XSS, SQLi, IDOR, CSRF, Sensitive Files, Rate Limiting, Subdomain Takeover, and more.

---

## ⚠️ Disclaimer :

This tool is for educational and authorized testing purposes only. Do not use it against any target without proper permission. The author is not responsible for any misuse or damage caused.


## 🔗 GitHub Repository :
```bash
git clone https://github.com/Professor1711/BugNaath.git
cd BugNaath
```
## ⚙️ Installation :
Make sure you have Python 3.9+ installed.
Install all dependencies using:
```
pip install -r requirements.txt
```
## 🚀 Usage :
▶️ Scan a Single URL
```
python3 bugnaath.py -u "https://example.com/page.php?id=123" --deep
```
▶️ Scan Multiple URLs from a File
```
python3 bugnaath.py --list targets.txt --deep
```
▶️ Save Results to a File
```
python3 bugnaath.py -u "https://example.com" --deep -o results.txt
```
▶️ Set Timeout and Threads
```
python3 bugnaath.py --list targets.txt --deep -t 10 --threads 10

```
📥 Output Sample
```
[*] Scanning: https://example.com/page.php?id=123
- Missing Header: X-Frame-Options
- Possible SQLi: https://example.com/page.php?id='
- Possible XSS: https://example.com/page.php?id=<script>alert(1)</script>
- Sensitive file exposed: https://example.com/.env
- Potential CSRF (no CSRF tokens detected)
- Subdomain takeover: Check DNS + 404 response patterns
```
## 🧠 Features :

🔍 Deep vulnerability scanning with real payload injection

🧬 SQLi detection (error-based, reflected payloads)

✳️ XSS detection

🛑 Missing Security Headers detection

🔓 Sensitive file exposure detection (.env, phpinfo.php, etc.)

🔐 IDOR, CSRF, SSRF, XXE, SSTI (warning-based)

🌐 Subdomain Takeover detection (warning-based)

📊 CLI-based real-time results and optional file output

🧠 Smart parameter parsing and payload mapping


📁 Folder Structure
```
BugNaath/
├── bugnaath.py          # Main scanner file
├── requirements.txt     # Required Python packages
├── README.md            # This file
└── targets.txt          # Optional - list of URLs to scan
```
## 💬 Created with 💻 

by Virendra Kumar Leelawat

Tool name: BugNaath – “Search Hunter”
