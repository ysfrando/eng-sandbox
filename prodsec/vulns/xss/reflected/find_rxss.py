import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Optional
import logging


class ReflectedXSScanner:
    """Scanner for detecting reflected XSS vulns in web applications"""
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None, 
                 cookies: Optional[Dict[str, str]] = None, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.cookies = cookies
        self.timeout = timeout
        self.log = self._setup_logger()
        
        self.payloads = [
            '<script>alert(1)</script>',
            '><svg>/onload=alert(1)>',
            '\'"<img src=x onerror=alert(1)>',
            '"><iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>',
            '\'onmouseover=alert(1)//'
        ]
        
        # Encode payloads for various contexts
        self.encoded_payloads = {
            'url': [urllib.parse.quote(p) for p in self.payloads],
            'double_encoded': [urllib.parse.quote(urllib.parse.quote(p)) for p in self.payloads]
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for the XSS scanner"""
        logger = logging.getLogger('xss_scanner')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    def discover_input(self, url: str) -> List[str]:
        """Find all input parameters in a page"""
        try:
            # GET request to target and parse HTML
            response = requests.get(url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Store params and input fields. Set O(1) lookup and duplicate checking
            params = []
            
            # Find all input fields
            for form in soup.find_all('form'):
                for input_field in form.findall(['input', 'textarea']):
                    name = input_field.get('name')
                    if name:
                        params.append(name)
                        
            # Look for URL parameters in links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    query_p = href.split('?')[1]
                    for param_pair in query_p.split('&'):
                        if '=' in param_pair:
                            param = param_pair.split('=')[0]
                            if param not in params:
                                params.append(param)
                            
            return params
        
        except Exception as e:
            self.log.error(f"Error discovering inputs on {url}: {str(e)}")
            return set()
        
    def test_parameter(self, url: str, param: str) -> Optional[Dict]:
        """Test a single parameter for reflected XSS"""
        for encoding_type, payloads in self.encoded_payloads.items():
            for payload in payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                
                try:
                    response = requests.get(
                        test_url,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    if response.status_code >= 300 and response.status_code < 400:
                        # Skip redirects
                        continue
                    
                    # Check if the payload is reflected in the response
                    original_payload = self.payloads[payloads.index(payload)]
                    
                    if original_payload in response.text:
                        # Determine if the payload is properly escaped
                        soup = BeautifulSoup(response.text, 'html.parser')
                        scripts = soup.find_all('script')
                    
                        # Check if our payload created a valid script tag or is inside an existing one
                        for script in scripts:
                            if original_payload in str(script):
                                return {
                                    'url': test_url,
                                    'param': param,
                                    'payload': original_payload,
                                    'vulnerable': True,
                                    'context': 'script_tag',
                                    'response_code': response.status_code
                                }
                                
                        # Check if it's in an HTML attribute
                        html_str = response.text
                        attribute_pattern = re.compile(r'="[^"]*' + re.escape(original_payload) + r'[^"]*"')
                        if attribute_pattern.search(html_str):
                            return {
                                'url': test_url,
                                'param': param,
                                'payload': original_payload,
                                'vulnerable': True,
                                'context': 'html_attribute',
                                'response_code': response.status_code
                            }
                            
                        # It's reflected but might be escaped
                        return {
                            'url': test_url,
                            'param': param,
                            'payload': original_payload,
                            'vulnerable': 'potentially',
                            'context': 'html_body',
                            'response_code': response.status_code
                        }
                
                except Exception as e:
                    self.log.error(f"Error testing {test_url}: {str(e)}")
                    
        return None
    
    def scan_url(self, url: str) -> List[Dict]:
        """Scan a single URL for reflected XSS vulnerabilities"""
        self.log.info(f"Scanning {url} for reflected XSS")
        
        # Discover input parameters
        params = self.discover_input(url)
        self.log.info(f"Discovered {len(params)} parameters: {', '.join(params)}")
        
        # Add common params if not found
        common_params = ['q', 'search', 'id', 'page', 'query', 'keyword', 'term']
        for param in common_params:
            if param not in params:
                params.append(param)
                
        vulnerabilities = []
        
        # Test each parameter
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(lambda p: self.test_parameter(url, p), params)
            
            for result in results:
                if result:
                    vulnerabilities.append(result)
                    self.log.warning(f"Found potential XSS in {result['param']} - {result['url']}")
                    
        if not vulnerabilities:
            self.log.info(f"No reflected XSS vulnerabilities found on {url}")
            
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate a report of found vulnerabilities."""
        if not vulnerabilities:
            return "No reflected XSS vulnerabilities were found."
        
        report = "## Reflected XSS Vulnerability Report\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report += f"### {i}. {vuln['url']}\n"
            report += f"- Parameter: `{vuln['param']}`\n"
            report += f"- Payload: `{vuln['payload']}`\n"
            report += f"- Context: {vuln['context']}\n"
            report += f"- Status: {'Vulnerable' if vuln['vulnerable'] == True else 'Potentially Vulnerable'}\n"
            report += f"- Response Code: {vuln['response_code']}\n\n"
            
            # Add remediation advice
            report += "#### Remediation:\n"
            if vuln['context'] == 'script_tag':
                report += "- Implement strict Content Security Policy (CSP) with `script-src` directive\n"
                report += "- Sanitize user input before reflecting it in responses\n"
                report += "- Use context-aware output encoding\n"
            elif vuln['context'] == 'html_attribute':
                report += "- Use HTML attribute encoding\n"
                report += "- Implement Content Security Policy\n"
                report += "- Consider using React or similar frameworks that automatically escape content\n"
            else:
                report += "- Apply context-appropriate encoding\n"
                report += "- Validate input on both client and server side\n"
                report += "- Implement Content Security Policy\n"
            
            report += "\n---\n\n"
        
        return report


# Example usage
if __name__ == "__main__":
    # In a real Stripe context, you might scan internal apps
    scanner = ReflectedXSScanner(
        base_url="https://internal.example-stripe.com",
        headers={
            "User-Agent": "Stripe-Security-Scanner/1.0",
            "Authorization": "Bearer $API_KEY"
        },
        cookies={"session": "authenticated_session_token"}
    )

    # Scan important endpoints
    targets = [
        "/dashboard",
        "/search",
        "/reports",
        "/user/profile",
        "/admin/users"
    ]
    
    all_vulnerabilities = []
    for target in targets:
        url = scanner.base_url + target
        vulnerabilities = scanner.scan_url(url)
        all_vulnerabilities.extend(vulnerabilities)
        
    # Generate and save report
    report = scanner.generate_report(all_vulnerabilities)
    with open("xss_vulnerability_report.md", "w") as f:
        f.write(report)
        
    # This could be integrated into a CI/CD pipeline to fail builds with vulnerabilities
    if any(v['vulnerable'] == True for v in all_vulnerabilities):
        print(f"Critical vulnerabilities found! Detailed report saved.")
        exit(1)
    else:
        print("No critical vulnerabilities found. Report saved.")
