import re
import os

def scan_js_files(directory):
    dangerous_patterns = [
        r'\.innerHTML\s*=', 
        r'\.outerHTML\s*=',
        r'document\.write\(',
        r'\.insertAdjacentHTML\(',
        r'eval\(',
        r'setTimeout\([\'"`]',
        r'setInterval\([\'"`]',
        r'new Function\('
    ]
    
    results = []
    
    # Walk through the directory
    for root, _, files in os.walk(directory):
        for file in files:
            # Check for js files 
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                # Open the file
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    try:
                        content = f.read()
                        line_number = 1
                        for line in content.split('\n'):
                            for pattern in dangerous_patterns:
                                if re.search(pattern, line):
                                    results.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'code': line.strip(),
                                        'pattern': pattern  
                                    })
                            
                            line_number += 1
                    except Exception as e:
                        print(f'Error reading {file_path}: {e}')
                        
    return results

if __name__ == "__main__":
    scan_dir = '.'
    findings = scan_js_files(scan_dir)
    
    print(f"Found {len(findings)} potential DOM-based XSS vulnerabilities")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding['file']}:{finding['line']}")
        print(f"    Code: {finding['code']}")
        print(f"    Pattern: {finding['pattern']}")
