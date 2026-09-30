# Web Vulnerability Scanner

A desktop GUI tool (PyQt6) for running basic, automated security checks against a web application and exporting the results as an HTML or text report.

> ⚠️ **Legal notice:** Only scan websites you own or have explicit written permission to test. Unauthorized scanning may be illegal. The author is not responsible for misuse.

## Features

- **Information gathering** – server header, `X-Powered-By`, generator meta tag, HTML comments
- **Security headers** – checks for missing/weak headers (e.g. `X-Frame-Options`, `X-Content-Type-Options`)
- **SSL/TLS** – basic configuration check for HTTPS targets
- **XSS** – basic reflected XSS testing
- **SQL injection** – basic error-based testing
- **Directory traversal** – path traversal checks
- **Open redirect** – redirect parameter testing
- **CSRF** – form token checks
- **Misconfigurations** – common exposed files/paths
- Non-blocking scans (runs in a background thread) with a progress bar
- Enable/disable each check with checkboxes
- Export reports as **HTML** (with severity summary) or **TXT**

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`

## Installation

```bash
git clone https://github.com/xPh4nt0m-Byte/Web-Scanner.git
cd Web-Scanner

python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
python web_scanner.py
```

1. Enter the target URL (e.g. `https://example.com`).
2. Select the checks you want to run.
3. Click **Start Scan** and follow the progress.
4. Review the findings in the result tabs.
5. Click **Save Report** to export as `.html` or `.txt`.

## Severity Levels

| Level  | Meaning                                   |
|--------|-------------------------------------------|
| High   | Likely exploitable or critical issue      |
| Medium | Weak configuration or partial protection  |
| Low    | Information disclosure                    |
| Info   | Informational finding                     |

## Limitations

- This is a **lightweight scanner**, not a replacement for tools like Burp Suite, OWASP ZAP, or a professional penetration test.
- Results may include **false positives** and **false negatives**.
- SSL certificate verification is disabled during scans (`verify=False`) so that targets with invalid certificates can be tested.

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. You are solely responsible for how you use it.

## License

Released under the [MIT License](LICENSE).
