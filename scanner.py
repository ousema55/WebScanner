"""
Scanner Simple avec BeautifulSoup
==================================
Code clair et efficace pour tester les sites web
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures
from payloads import (
    XSS_PAYLOADS, SQLI_PAYLOADS, SQL_ERROR_PATTERNS,
    ADVANCED_XSS_PAYLOADS, ADVANCED_SQLI_PAYLOADS, USER_AGENTS
)

# Disable warnings is good practice for scanners that might hit self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Scanner:
    def __init__(self, target_url, cookie=None):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.verify = False
        
        # Increase pool size to handle concurrent requests
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Initial user agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        })

        # Set manual cookie if provided
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        self.vulnerabilities = {
            "Xss": [],
            "sqli": []
        }
        self.vuln_hashes = set()
        self.logs = []
        self.visited_urls = set()
        self.urls_to_scan = [target_url]
        self.max_pages = 10
        self.forms_found = []
        self.stop_scan_flag = False

    def stop(self):
        """Signals the scanner to stop."""
        self.stop_scan_flag = True
        self.log("[!] Stopping scan at user request...")

    def get_results(self):
        """Returns current scan results."""
        all_vulnerabilities = []
        for v_type, v_list in self.vulnerabilities.items():
            all_vulnerabilities.extend(v_list)
            
        return {
            "vulnerabilities": all_vulnerabilities,
            "scanned_count": len(self.visited_urls),
            "forms_found": self.forms_found,
            "logs": self.logs,
            "is_stopped": self.stop_scan_flag
        }

    def log(self, message):
        print(message)
        self.logs.append(message)

    def run_scan(self):
        self.log(f"[*] Starting scan on {self.target_url}")
        
        # 1. Scan the base URL's parameters first (Virtual Form)
        # This fixes the issue where ?cat=1 wasn't being scanned if no form existed
        parsed_target = urlparse(self.target_url)
        if parsed_target.query:
            self.log(f"[*] Detected URL parameters. Creating virtual form for: {self.target_url}")
            from urllib.parse import parse_qs
            query_params = parse_qs(parsed_target.query)
            
            virtual_inputs = []
            for param_name, values in query_params.items():
                virtual_inputs.append({
                    "name": param_name,
                    "type": "text",
                    "value": values[0] if values else ""
                })
            
            virtual_form = {
                "action": self.target_url.split('?')[0], # Base URL without query
                "method": "get",
                "inputs": virtual_inputs
            }
            
            # Add to forms list so it shows in UI and gets scanned
            self.forms_found.append(virtual_form)

        while self.urls_to_scan and len(self.visited_urls) < self.max_pages:
            if self.stop_scan_flag:
                break
            url = self.urls_to_scan.pop(0)
            if url in self.visited_urls:
                continue
            
            self.log(f"[*] Parsing: {url}")
            try:
                response = self.session.get(url, timeout=5) # Reduced timeout for crawling
                status_code = response.status_code
                self.log(f"[*] Parsed: {url} [{status_code}]")
                
                # Check for WAF/Blocking
                if status_code in [403, 406, 429]:
                    self.log(f"[!] Warning: Received {status_code}. The scanner might be blocked by a WAF.")
                
                self.visited_urls.add(url)
                
                soup = BeautifulSoup(response.content, "html.parser")
                
                # Crawl
                self.extract_links(url, soup)
                
                # Extract forms
                forms = self.extract_forms(url, soup)
                self.forms_found.extend(forms)
                
                self.log(f"[+] Found {len(forms)} forms on {url}")
                
                # Scan forms in parallel using a single ThreadPool for this page
                # We handle payloads inside the test functions, but limiting max_workers here to prevent explosion
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    # Also scan the virtual form if we just added it and this is the first iteration
                    # (Actually self.forms_found grows, but we only want to scan new forms. 
                    # Simpler approach: gather all forms to scan for THIS page)
                    
                    forms_to_scan = forms.copy()
                    if url == self.target_url and 'virtual_form' in locals():
                        forms_to_scan.append(virtual_form)

                    for form in forms_to_scan:
                        futures.append(executor.submit(self.test_xss, form))
                        futures.append(executor.submit(self.test_sqli, form))
                    
                    concurrent.futures.wait(futures)

            except Exception as e:
                self.log(f"[!] Error scanning {url}: {e}")

        self.log(f"[*] Scan Terminé. {len(self.visited_urls)} pages scannées.")

        # Flatten vulnerabilities for the report
        all_vulnerabilities = []
        for v_type, v_list in self.vulnerabilities.items():
            all_vulnerabilities.extend(v_list)

        return {
            "vulnerabilities": all_vulnerabilities,
            "scanned_count": len(self.visited_urls),
            "forms_found": self.forms_found,
            "logs": self.logs
        }

    def extract_links(self, url, soup):
        for link in soup.find_all("a"):
            href = link.get("href")
            if not href:
                continue
                
            # Resolve relative URLs
            full_url = urljoin(url, href)
            parsed_url = urlparse(full_url)
            
            # Normalize domains for comparison (remove www.)
            scan_domain = self.domain.replace("www.", "")
            link_domain = parsed_url.netloc.replace("www.", "")
            
            # Only scan internal links and avoid duplicates
            # Allow matching if the link domain ends with the scan domain (subdomain support)
            domain_match = link_domain == scan_domain or link_domain.endswith("." + scan_domain)
            
            if domain_match and full_url not in self.visited_urls and full_url not in self.urls_to_scan:
                # Basic filter to avoid logout or other destructive actions if possible
                if "logout" not in full_url.lower():
                    self.urls_to_scan.append(full_url)
            elif not domain_match and parsed_url.netloc:
                 # Optional: log external links for debug?
                 pass

    def extract_forms(self, url, soup):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            
            # Resolve action URL
            if action:
                action_url = urljoin(url, action)
            else:
                action_url = url
                
            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name")
                
                # We need the name to exploit it
                if input_name:
                    inputs.append({
                        "name": input_name,
                        "type": input_type,
                        "tag": input_tag.name
                    })
            
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
        return forms

    def test_xss(self, form):
        submit_url = form['action']
        method = form['method']
        inputs = form['inputs']
        
        scan_payloads = XSS_PAYLOADS + ADVANCED_XSS_PAYLOADS
            
        self.log(f"[*] Testing XSS on {submit_url}")
        
        def check_payload(payload, input_name):
            # Deduplication check
            vuln_id = f"{submit_url}:{method}:{input_name}:XSS"
            if vuln_id in self.vuln_hashes:
                return False

            data = {}
            # Preserve other inputs with default values if needed, but for now simple injection
            for input_tag in inputs:
                if input_tag['name'] == input_name:
                    data[input_tag['name']] = payload
                else:
                    data[input_tag['name']] = "test" 
            
            try:
                if method == 'post':
                    res = self.session.post(submit_url, data=data, timeout=5)
                else:
                    res = self.session.get(submit_url, params=data, timeout=5)
                
                if payload in res.text:
                    # Context Extraction
                    try:
                        idx = res.text.index(payload)
                        start = max(0, idx - 50)
                        end = min(len(res.text), idx + len(payload) + 50)
                        context = res.text[start:end]
                        # Escape context for HTML safe display
                        import html
                        context_safe = html.escape(context)
                    except:
                        context_safe = "Context unavailable"

                    self.log(f"[!] XSS Found: {submit_url} (Param: {input_name})")
                    
                    self.vulnerabilities["Xss"].append({
                        "type": "Cross-Site Scripting (XSS)",
                        "url": submit_url,
                        "payload": payload,
                        "method": method,
                        "severity": "High",
                        "context": context_safe,
                        "parameter": input_name
                    })
                    self.vuln_hashes.add(vuln_id)
                    return True
            except Exception:
                pass
            return False

        # Iterate over inputs, then payloads. Stop if input is vulnerable.
        # We don't use ThreadPool here for simplicity and to correctly implement the "stop on first valid payload per input" logic without complex synchronization
        for input_tag in inputs:
            if self.stop_scan_flag:
                return

            input_name = input_tag['name']
            for payload in scan_payloads:
                if self.stop_scan_flag:
                    return

                if check_payload(payload, input_name):
                    # Vulnerability found for this input, move to next input
                    break

    def test_sqli(self, form):
        submit_url = form['action']
        method = form['method']
        inputs = form['inputs']
        
        scan_payloads = SQLI_PAYLOADS + ADVANCED_SQLI_PAYLOADS
            
        self.log(f"[*] Testing SQLi on {submit_url}")

        def check_payload(payload, input_name):
            # Deduplication check
            vuln_id = f"{submit_url}:{method}:{input_name}:SQLi"
            if vuln_id in self.vuln_hashes:
                return False

            data = {}
            for input_tag in inputs:
                if input_tag['name'] == input_name:
                    data[input_tag['name']] = payload
                else:
                    data[input_tag['name']] = "test"
            
            try:
                if method == 'post':
                    res = self.session.post(submit_url, data=data, timeout=5)
                else:
                    res = self.session.get(submit_url, params=data, timeout=5)
                
                for error in SQL_ERROR_PATTERNS:
                    if error in res.text:
                        self.log(f"[!] SQLi Found: {submit_url} (Param: {input_name})")
                        
                        self.vulnerabilities["sqli"].append({
                            "type": "SQL Injection",
                            "url": submit_url,
                            "payload": payload,
                            "error": error,
                            "method": method,
                            "severity": "Critical",
                            "parameter": input_name,
                            "context": f"DB Error triggered: {error}"
                        })
                        self.vuln_hashes.add(vuln_id)
                        return True
            except Exception:
                pass
            return False
            
        # Iterate over inputs, then payloads. Stop if input is vulnerable.
        for input_tag in inputs:
            if self.stop_scan_flag:
                return

            input_name = input_tag['name']
            for payload in scan_payloads:
                if self.stop_scan_flag:
                    return

                if check_payload(payload, input_name):
                    break
