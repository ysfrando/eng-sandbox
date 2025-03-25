from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import argparse
import json
import datetime


class SimpleCallbackServer(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        
    def do_GET(self):
        self._handle_request()
        
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._handle_request(post_data)
        
    def _handle_request(self, post_data=None):
        # Log request details
        client_ip = self.client_address[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_data = {
            "timestamp": timestamp,
            "remote_ip": client_ip,
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers)
        }

        if post_data:
            try:
                log_data["post_data"] = post_data.decode('utf-8')
            except:
                log_data["post_data"] = str(post_data)
                
        logging.info(json.dumps(log_data, indent=2))
        
        # Send response
        self._set_response()
        self.wfile.write(f"Request received at {timestamp}\n".encode('utf-8'))
        
        print(f"[+] {timestamp} - Request from {client_ip} to {self.path}")

def run(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleCallbackServer)
    print(f"[+] Callback server running on port {port}")
    print(f"[+] Use this server to detect successful SSRF attempts")
    print(f"Press Ctrl+C to stop")
    httpd.serve_forever()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSRF Callback Server')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port to run the callback server on')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    
    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='ssrf_callback.log'
    )
    
    run(args.port)
