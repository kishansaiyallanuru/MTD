#!/usr/bin/env python3
"""
MTD Host Agent - HTTP/HTTPS Server and Client for Inter-Host Communication

This agent runs on each virtual host (h1-h6) to facilitate communication
between hosts in the MTD network.

Usage:
  Server mode: python3 host_agent.py --host h1 --server [--port 8080] [--https]
  Client mode: python3 host_agent.py --host h1 --client --target h2 [--port 8080] [--https]
"""

import argparse
import time
import sys
import json
import requests
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer

# DNS resolution via controller
CONTROLLER_API = "http://127.0.0.1:8000"

# Secret key for HMAC (must match controller)
SECRET = b'supersecret_test_key'  # Must match mtd_controller.py

def log(host, msg, level="INFO"):
    """Log messages with timestamp and host identifier"""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] [{host}] {level}: {msg}", flush=True)

def resolve_hostname(hostname):
    """
    Resolve hostname to public IP via MTD controller DNS
    Returns: IP address string or None
    """
    try:
        response = requests.get(f"{CONTROLLER_API}/dns?q={hostname}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('ip')
        else:
            return None
    except Exception as e:
        print(f"DNS resolution failed: {e}", file=sys.stderr)
        return None

class HostAgentHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for host agent server"""

    def do_GET(self):
        """Handle GET requests"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        response = {
            'status': 'ok',
            'host': self.server.hostname,
            'message': 'Host agent running',
            'timestamp': time.time()
        }
        self.wfile.write(json.dumps(response).encode())
        log(self.server.hostname, f"GET request from {self.client_address[0]}")

    def do_POST(self):
        """Handle POST requests (receive data from other hosts)"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        # Get source information from headers or body
        source_host = "unknown"
        try:
            # Try to parse as JSON
            if body:
                data = json.loads(body.decode('utf-8'))
                source_host = data.get('source', data.get('src', self.client_address[0]))
                payload_preview = str(data.get('payload', data.get('data', '')))[:50]

                print("\n" + "="*70)
                log(self.server.hostname, f"📥 PACKET RECEIVED", "SUCCESS")
                log(self.server.hostname, f"   From: {source_host} ({self.client_address[0]})")
                log(self.server.hostname, f"   Size: {len(body)} bytes")
                if payload_preview:
                    log(self.server.hostname, f"   Data: {payload_preview}...")
                print("="*70 + "\n")
            else:
                data = {}
                log(self.server.hostname, f"Received empty payload from {self.client_address[0]}")
        except Exception:
            data = {'raw': body.decode('utf-8', errors='ignore')}
            source_host = self.client_address[0]
            print("\n" + "="*70)
            log(self.server.hostname, f"📥 PACKET RECEIVED (non-JSON)", "SUCCESS")
            log(self.server.hostname, f"   From: {self.client_address[0]}")
            log(self.server.hostname, f"   Size: {len(body)} bytes")
            print("="*70 + "\n")

        # Compute cryptographic verification fields
        # Hash the received payload for integrity verification
        payload_hash = hashlib.sha256(body).hexdigest()

        # Extract session ID if present
        session_id = data.get('session_id', 'unknown')

        # Send success response with acknowledgment and crypto verification
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        # Build response with all required verification fields
        response = {
            'status': 'ACK',
            'message': 'Packet received and acknowledged',
            'destination': self.server.hostname,  # This host is the destination
            'sender': source_host,
            'bytes_received': len(body),
            'timestamp': time.time(),
            'payload_hash': payload_hash,  # SHA-256 hash for integrity check
            'session_id': session_id  # Session ID echoed back
        }

        # Sign the response with HMAC for authenticity
        response_json = json.dumps(response, sort_keys=True)
        signature = hmac.new(SECRET, response_json.encode(), hashlib.sha256).hexdigest()
        response['signature'] = signature

        self.wfile.write(json.dumps(response).encode())
        log(self.server.hostname, f"✅ ACK sent to {source_host} (signed, hash: {payload_hash[:8]}...)")

class ThreadedHTTPServer(HTTPServer):
    """HTTP server with hostname attribute"""
    def __init__(self, server_address, RequestHandlerClass, hostname):
        super().__init__(server_address, RequestHandlerClass)
        self.hostname = hostname

def run_server(hostname, port=8080, https=False):
    """
    Run HTTP server on specified port

    Args:
        hostname: Host identifier (e.g., 'h1')
        port: Port number to listen on
        https: If True, use HTTPS (not implemented in basic version)
    """
    if https:
        log(hostname, "HTTPS mode requested but not implemented, falling back to HTTP", "WARN")

    server = None
    try:
        server = ThreadedHTTPServer(('0.0.0.0', port), HostAgentHTTPHandler, hostname)
        log(hostname, f"🚀 Server started on 0.0.0.0:{port}")
        log(hostname, f"Listening for connections...")
        server.serve_forever()
    except OSError as e:
        if e.errno == 98:  # Address already in use
            log(hostname, f"❌ Port {port} already in use", "ERROR")
            sys.exit(1)
        else:
            log(hostname, f"❌ Server error: {e}", "ERROR")
            sys.exit(1)
    except KeyboardInterrupt:
        log(hostname, "Server stopped by user")
        if server:
            server.shutdown()

def run_client(hostname, target, port=8080, https=False, count=None, interval=2):
    """
    Run client that sends requests to target host

    Args:
        hostname: Source host identifier (e.g., 'h1')
        target: Target hostname (e.g., 'h2')
        port: Target port number
        https: If True, use HTTPS
        count: Number of messages to send (None = infinite)
        interval: Seconds between messages
    """
    protocol = "https" if https else "http"
    log(hostname, f"🔄 Client mode: sending to {target}")

    message_num = 0
    consecutive_failures = 0
    max_consecutive_failures = 5

    try:
        while count is None or message_num < count:
            message_num += 1

            # Resolve target hostname to IP
            log(hostname, f"🔍 Resolving {target}...")
            target_ip = resolve_hostname(target)

            if not target_ip:
                log(hostname, f"❌ DNS resolution failed for {target}", "ERROR")
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    log(hostname, f"❌ Too many consecutive failures, exiting", "ERROR")
                    sys.exit(1)
                time.sleep(interval)
                continue

            log(hostname, f"✓ Resolved {target} -> {target_ip}")

            # Prepare payload
            payload = {
                'source': hostname,
                'target': target,
                'message_id': message_num,
                'timestamp': time.time(),
                'data': f'Test message #{message_num} from {hostname} to {target}'
            }

            # Send request
            url = f"{protocol}://{target_ip}:{port}"
            try:
                print("\n" + "="*70)
                log(hostname, f"📤 SENDING PACKET", "INFO")
                log(hostname, f"   To: {target} ({target_ip}:{port})")
                log(hostname, f"   Message ID: #{message_num}")
                log(hostname, f"   Payload: {payload['data'][:50]}...")
                print("="*70)

                response = requests.post(
                    url,
                    json=payload,
                    timeout=5,
                    verify=False  # Disable SSL verification for self-signed certs
                )

                if response.status_code == 200:
                    # Parse acknowledgment
                    try:
                        ack_data = response.json()
                        print("\n" + "="*70)
                        log(hostname, f"✅ ACKNOWLEDGMENT RECEIVED", "SUCCESS")
                        log(hostname, f"   From: {target} ({target_ip})")
                        log(hostname, f"   Status: {ack_data.get('status', 'ACK')}")
                        log(hostname, f"   Message: {ack_data.get('message', 'Success')}")
                        log(hostname, f"   Bytes delivered: {ack_data.get('bytes_received', 'N/A')}")
                        print("="*70 + "\n")
                    except:
                        log(hostname, f"✅ PACKET DELIVERED #{message_num} -> {target} ({target_ip})")
                    consecutive_failures = 0
                else:
                    log(hostname, f"⚠️  Response code {response.status_code}", "WARN")
                    consecutive_failures += 1

            except requests.exceptions.Timeout:
                log(hostname, f"⏱️  Timeout connecting to {target_ip}:{port}", "ERROR")
                consecutive_failures += 1
            except requests.exceptions.ConnectionError as e:
                log(hostname, f"❌ Connection refused to {target_ip}:{port} - {e}", "ERROR")
                consecutive_failures += 1
            except Exception as e:
                log(hostname, f"❌ Error: {e}", "ERROR")
                consecutive_failures += 1

            if consecutive_failures >= max_consecutive_failures:
                log(hostname, f"❌ Too many consecutive failures ({consecutive_failures}), exiting", "ERROR")
                sys.exit(1)

            if count is None or message_num < count:
                time.sleep(interval)

    except KeyboardInterrupt:
        log(hostname, f"Client stopped by user after {message_num} messages")

def main():
    parser = argparse.ArgumentParser(description='MTD Host Agent - HTTP Server/Client')
    parser.add_argument('--host', required=True, help='Host identifier (e.g., h1)')
    parser.add_argument('--server', action='store_true', help='Run in server mode')
    parser.add_argument('--client', action='store_true', help='Run in client mode')
    parser.add_argument('--target', help='Target hostname for client mode (e.g., h2)')
    parser.add_argument('--port', type=int, default=8080, help='Port number (default: 8080)')
    parser.add_argument('--https', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('--count', type=int, help='Number of messages to send (client mode)')
    parser.add_argument('--interval', type=float, default=2.0, help='Interval between messages in seconds (default: 2)')

    args = parser.parse_args()

    # Validate arguments
    if not args.server and not args.client:
        parser.error("Must specify either --server or --client mode")

    if args.server and args.client:
        parser.error("Cannot run in both server and client mode simultaneously")

    if args.client and not args.target:
        parser.error("Client mode requires --target argument")

    # Run in appropriate mode
    if args.server:
        log(args.host, f"Starting in SERVER mode on port {args.port}")
        run_server(args.host, args.port, args.https)
    else:
        log(args.host, f"Starting in CLIENT mode targeting {args.target}")
        run_client(args.host, args.target, args.port, args.https, args.count, args.interval)

if __name__ == '__main__':
    main()
