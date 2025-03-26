import requests 
import argparse
import json
from urllib.parse import urlparse

def analyze_csp(url):
    """Analyze a website's CSP and identify potential bypass vectors"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        csp_header = None
        
        # Check for CSP in headers
        if 'Content-Security-Policy' in response.headers:
            csp_header = response.headers['Content-Security-Policy']
            
        # Check for CSP in meta tags
        if not csp_header:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_csp = soup.find('meta', {'http-equiv': 'Content-Security-Policy'})
            if meta_csp:
                csp_header = meta_csp.get('content', '')
                
        if not csp_header:
            print("[!] No CSP found on this page")
            return None
        
        print(f"[+] Found CSP: {csp_header}")
        
        # Parse CSP directives
        directives = {}
        for policy in csp_header.split(';'):
            policy = policy.strip()
            if not policy:
                continue
            
            parts = policy.split()
            if not parts:
                continue
            
            directive = parts[0]
            values = parts[1:] if len(parts) > 1 else []
            directives[directive] = values
            
        return analyze_directives(directives, url)
    
    except requests.exceptions.Timeout as e:
        print(f"[!] Request timed out: {str(e)}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP Error occurred: {str(e)}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] A request error occurred: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return None
    
    
def analyze_directives(directives, url):
    """Analyze individual CSP directives for weaknesses"""
    target_domain = urlparse(url).netloc
    findings = []
    
    # Check default-src
    default_src = directives.get('default-src', [])
    
    # Check script-src (or fall back to default-src)
    script_src = directives.get('script-src', default_src)
    
    # Check for 'unsafe-inline' in script-src
    if 'unsafe-inline' in script_src:
        findings.append({
            'severity': 'High',
            'directive': 'script-src',
            'issue': 'unsafe-inline allowed',
            'impact': 'Allows execution of inline scripts, bypassing CSP protection',
            'exploit': "<script>alert(document.domain)</script>"
        })
        
    # Check for 'unsafe-eval' in script-src
    if 'unsafe-eval' in script_src:
        findings.append({
            'severity': 'Medium',
            'directive': 'script-src',
            'issue': 'unsafe-eval allowed',
            'impact': 'Allows use of eval(), setTimeout(string), setInterval(string), etc.',
            'exploit': "<script>eval('alert(document.domain)')</script>"
        })
        
    if 'data:' in script_src:
        findings.append({
            'severity': 'High',
            'directive': 'script-src',
            'issue': 'data: URIs allowed',
            'impact': 'Allows loading scripts via data: URIs',
            'exploit': "<script src=\"data:text/javascript,alert(document.domain)\"></script>"
        })
        
    # Check for wildcards
    for directive, values in directives.items():
        if "*" in values:
            findings.append({
                'severity': 'Medium',
                'directive': directive,
                'issue': 'Wildcard (*) source',
                'impact': f'Allows loading resources from any domain for {directive}',
                'exploit': f"Depends on {directive} - can load content from any domain"
            })
            
    # Check for known JSONP endpoints from allowed domains
    jsonp_candidates = []
    safe_domains = ['ajax.googleapis.com', 'cdn.jsdelivr.net']
    
    for src in script_src:
        domain = src
        # Remove scheme if present
        if "://" in src:
            domain = src.split("://")[1]
        # Remove path if present
        if "/" in domain:
            domain = domain.split("/")[0]
        
        # Check for JSONP vectors in common domains
        if domain in safe_domains or domain.endswith('google.com') or domain.endswith('googleapis.com'):
            jsonp_candidates.append(domain)
    
    if jsonp_candidates:
        findings.append({
            'severity': 'Medium',
            'directive': 'script-src',
            'issue': 'Potential JSONP endpoints allowed',
            'impact': 'May allow execution of arbitrary code via JSONP callbacks',
            'exploit': f"Look for JSONP endpoints on: {', '.join(jsonp_candidates)}"
        })
    
    # Check object-src (or fall back to default-src)
    object_src = directives.get('object-src', default_src)
    if not object_src or 'none' not in object_src:
        findings.append({
            'severity': 'Medium',
            'directive': 'object-src',
            'issue': 'object-src is missing or not set to none',
            'impact': 'Allows embedding of Flash or other plugin content that could execute code',
            'exploit': "<object data=\"data:text/html,<script>alert(document.domain)</script>\"></object>"
        })
    
    # Check base-uri
    if 'base-uri' not in directives:
        findings.append({
            'severity': 'Low',
            'directive': 'base-uri',
            'issue': 'base-uri directive is missing',
            'impact': 'Allows changing the base URL which can lead to script loading from attacker domains',
            'exploit': "<base href=\"http://attacker.com/\">"
        })
    
    # Check frame-ancestors
    if 'frame-ancestors' not in directives:
        findings.append({
            'severity': 'Low',
            'directive': 'frame-ancestors',
            'issue': 'frame-ancestors directive is missing',
            'impact': 'Site may be vulnerable to clickjacking attacks',
            'exploit': "<iframe src=\"" + url + "\"></iframe>"
        })
    
    return findings

def main():
    parser = argparse.ArgumentParser(description='CSP Analyzer and Bypass Finder')
    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    args = parser.parse_args()
    
    print(f"[+] Analyzing CSP for {args.url}")
    findings = analyze_csp(args.url)
    
    if not findings:
        print("[-] No CSP vulnerabilities found or no CSP present")
        return
    
    print("\n[+] Potential CSP Bypasses:")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding['severity']} - {finding['directive']}: {finding['issue']}")
        print(f"   Impact: {finding['impact']}")
        print(f"   Exploit: {finding['exploit']}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
