#!/usr/bin/env python3
"""Simple HTTP server for web-config UI."""

import http.server
import socketserver
import os
import sys

PORT = 8000

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def log_message(self, format, *args):
        # Custom log format
        print(f"[{self.log_date_time_string()}] {format % args}")

def main():
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print(f"🌐 BSDM-Proxy Web Configurator")
    print(f"="*50)
    print(f"Server starting on port {PORT}...")
    print(f"")
    print(f"Open your browser and navigate to:")
    print(f"  🔗 http://localhost:{PORT}")
    print(f"")
    print(f"Press Ctrl+C to stop the server")
    print(f"="*50)
    print()
    
    try:
        with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n✅ Server stopped")
        sys.exit(0)
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"\n❌ Error: Port {PORT} is already in use")
            print(f"Try a different port or stop the existing server")
            sys.exit(1)
        else:
            raise

if __name__ == "__main__":
    main()
