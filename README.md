# Crypt7air Vulnerability Scanner

## 🚀 Overview
Crypt7air is a lightweight and customizable vulnerability scanner designed for:
- Scanning for **XSS vulnerabilities** using customizable payloads.
- Checking for common **HTTP security header misconfigurations** like:
  - Missing `Content-Security-Policy`
  - Missing `Strict-Transport-Security`
  - Missing `X-Frame-Options`

### 🔍 Features
- **XSS Payload Testing**: Dynamically test multiple URLs for reflected XSS vulnerabilities.
- **HTTP Header Analysis**: Detect missing HTTP headers critical for securing web applications.
- **Multithreaded Scanning**: Faster results through parallel processing.
- **Custom Payloads**: Add your own payloads for specific use cases.
- **JSON Output**: Save scan results in a structured format for easy analysis.

---

## 🛠️ Usage
### Requirements:
- Python 3.7+
- Required libraries: `requests`, `bs4`

Install the dependencies using:
```bash
pip install -r requirements.txt
