import time
import threading
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from os import system, name
import json

def clear_screen():
    """Clears the terminal screen."""
    if name == "nt":  # Windows
        system("cls")
    else:  # macOS/Linux
        system("clear")

def display_animation():
    """Displays a cool animation with the name Crypt7air."""
    art_frames = [
        r"""
   ______     _           
  / ___\ \   / (_) ___ ___
 | |    \ \ / / |/ __/ _ \
 | |___  \ V /| | (_|  __/
  \____|  \_/ |_|\___\___|
        """,
        r"""
   ______   _             
  / ___\ \ / / ___   ___  
 | |     \ V / / _ \ / _ \
 | |___   | | | (_) |  __/
  \____|  |_|  \___/ \___|
        """,
    ]

    for frame in art_frames:
        clear_screen()
        print(frame)
        time.sleep(0.5)
    clear_screen()
    print(r"""
   ______     _           
  / ___\ \   / (_) ___ ___
 | |    \ \ / / |/ __/ _ \
 | |___  \ V /| | (_|  __/
  \____|  \_/ |_|\___\___|

[INFO] Welcome to the Crypt7air XSS and HTTP Vulnerability Scanner!
""")
    time.sleep(2)

class Crypt7airVulnerabilityScanner:
    def __init__(self, base_url, threads=5):
        self.base_url = base_url
        self.payloads = [
            "<script>alert('crypt7air')</script>",
            "<img src=x onerror=alert('crypt7air')>",
            "'\"><script>alert('crypt7air')</script>",
            "<svg/onload=alert('crypt7air')>",
            "`\"><img src=x onerror=alert('crypt7air')>",
        ]
        self.found_vulnerabilities = []
        self.http_issues = []
        self.session = requests.Session()
        self.log_file = "crypt7air_scan.log"
        self.result_file = "crypt7air_results.json"
        self.threads = threads

    def log(self, message):
        with open(self.log_file, "a") as log:
            log.write(message + "\n")
        print(message)

    def authenticate(self, login_url, credentials):
        """Logs in to the website if authentication is required."""
        self.log("[INFO] Authenticating...")
        response = self.session.post(login_url, data=credentials)
        if response.status_code == 200:
            self.log("[INFO] Authentication successful.")
        else:
            self.log("[ERROR] Authentication failed. Check your credentials.")
            exit(1)

    def add_payload(self, payload):
        """Allows adding custom payloads dynamically."""
        self.payloads.append(payload)
        self.log(f"[INFO] Custom payload added: {payload}")

    def scan_http_headers(self, url):
        """Checks for common HTTP header vulnerabilities."""
        try:
            response = self.session.head(url, timeout=10)
            headers = response.headers

            if "X-Content-Type-Options" not in headers:
                self.http_issues.append({"url": url, "issue": "Missing X-Content-Type-Options header."})
                self.log(f"[WARNING] Missing X-Content-Type-Options header on {url}")

            if "X-Frame-Options" not in headers:
                self.http_issues.append({"url": url, "issue": "Missing X-Frame-Options header."})
                self.log(f"[WARNING] Missing X-Frame-Options header on {url}")

            if "Content-Security-Policy" not in headers:
                self.http_issues.append({"url": url, "issue": "Missing Content-Security-Policy header."})
                self.log(f"[WARNING] Missing Content-Security-Policy header on {url}")

            if "Strict-Transport-Security" not in headers:
                self.http_issues.append({"url": url, "issue": "Missing Strict-Transport-Security header."})
                self.log(f"[WARNING] Missing Strict-Transport-Security header on {url}")

        except requests.RequestException as e:
            self.log(f"[ERROR] Failed to fetch headers from {url}: {e}")

    def scan_http_methods(self, url):
        """Checks for insecure HTTP methods enabled on the server."""
        try:
            response = self.session.options(url, timeout=10)
            if "Allow" in response.headers:
                allowed_methods = response.headers["Allow"]
                self.log(f"[INFO] Allowed HTTP methods on {url}: {allowed_methods}")
                if any(method in allowed_methods for method in ["PUT", "DELETE", "TRACE", "CONNECT"]):
                    self.http_issues.append({"url": url, "issue": f"Insecure HTTP methods enabled: {allowed_methods}"})
                    self.log(f"[WARNING] Insecure HTTP methods enabled on {url}: {allowed_methods}")

        except requests.RequestException as e:
            self.log(f"[ERROR] Failed to fetch HTTP methods from {url}: {e}")

    def scan_url(self, url):
        """Scans a URL for vulnerabilities."""
        self.scan_http_headers(url)
        self.scan_http_methods(url)

        for payload in self.payloads:
            try:
                test_url = url + payload
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    self.found_vulnerabilities.append({
                        "url": url,
                        "payload": payload,
                    })
                    self.log(f"[VULNERABILITY FOUND] XSS Payload: {payload} on {test_url}")
            except requests.RequestException as e:
                self.log(f"[ERROR] Failed to scan {url}: {e}")

    def scan_links(self, links):
        """Scans multiple links in parallel using threading."""
        def worker(link):
            absolute_url = urljoin(self.base_url, link)
            self.scan_url(absolute_url)

        self.log("[INFO] Scanning links with multithreading...")
        threads = []
        for link in links:
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
            t = threading.Thread(target=worker, args=(link,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def extract_links(self):
        """Extracts all links from the base URL using BeautifulSoup."""
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [a['href'] for a in soup.find_all('a', href=True)]
            self.log(f"[INFO] Extracted {len(links)} links from {self.base_url}.")
            return links
        except requests.RequestException as e:
            self.log(f"[ERROR] Failed to fetch links from {self.base_url}: {e}")
            return []

    def save_results(self):
        """Saves scan results to a JSON file."""
        with open(self.result_file, "w") as result_file:
            json.dump({
                "vulnerabilities": self.found_vulnerabilities,
                "http_issues": self.http_issues,
            }, result_file, indent=4)
        self.log(f"[INFO] Results saved to {self.result_file}")

    def run(self):
        """Runs the vulnerability scanner."""
        self.log(f"[INFO] Starting vulnerability scan on: {self.base_url}")
        links = self.extract_links()
        self.scan_links(links)
        self.save_results()
        self.log("[INFO] Scan completed.")
        if self.found_vulnerabilities or self.http_issues:
            self.log("[RESULTS] Issues Found:")
            for vuln in self.found_vulnerabilities:
                self.log(f"XSS - URL: {vuln['url']} | Payload: {vuln['payload']}")
            for issue in self.http_issues:
                self.log(f"HTTP - URL: {issue['url']} | Issue: {issue['issue']}")
        else:
            self.log("[RESULTS] No vulnerabilities found.")

if __name__ == "__main__":
    display_animation()
    print("=== Crypt7air Vulnerability Scanner ===")
    target_url = input("Enter the target URL (e.g., https://example.com): ")
    threads = int(input("Enter the number of threads to use (default: 5): ") or 5)
    scanner = Crypt7airVulnerabilityScanner(target_url, threads)

    auth_required = input("Does the site require authentication? (yes/no): ").strip().lower()
    if auth_required == "yes":
        login_url = input("Enter the login URL (e.g., https://example.com/login): ")
        username = input("Enter username: ")
        password = input("Enter password: ")
        scanner.authenticate(login_url, {"username": username, "password": password})

    custom_payload = input("Would you like to add a custom payload? (yes/no): ").strip().lower()
    if custom_payload == "yes":
        new_payload = input("Enter the custom XSS payload: ")
        scanner.add_payload(new_payload)

    scanner.run()
