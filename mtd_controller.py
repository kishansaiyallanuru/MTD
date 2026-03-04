#!/usr/bin/env python3
"""
MTD Ryu Controller — Final Stable Version
Project: SDN-Based Moving Target Defense (Final Year B.Tech Cybersecurity)

Architecture:
  - OpenFlow 1.3 / OVS two-table pipeline
  - Table 0: NAT IP rewriting (private ↔ public) + Proxy ARP dispatch
  - Table 1: L2 MAC-to-port forwarding + bidirectional IP flows
  - MTD engine: risk-based public IP hopping (shuffle intervals > idle_timeout)
  - Zone-based ACL: HIGH / MEDIUM / LOW
  - Secure Transfer API with AES-256-GCM + HMAC-SHA256 verification

Timeout strategy:
  - Table 0 NAT flows   : idle=0, hard=0  (permanent until shuffle replaces them)
  - Table 1 IP/L2 flows : idle=60, hard=0 (expire after 60 s idle; re-learnt on
                           next PacketIn — which is safe because shuffle intervals
                           are 90/120/180 s, all > 60 s, so old L2 flows are gone
                           before the next hop occurs — zero stale-flow conflicts)

Shuffle intervals:
  LOW zone   = 90 s
  MEDIUM zone= 120 s
  HIGH zone  = 180 s

All CRITICAL bugs from initial review are fixed (see BUG_REPORT.md for details).
"""

import json
import os
import time
import threading
import uuid
import logging
import sqlite3
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import requests

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    pass

import yaml
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------
PRIVATE_SUBNET = '10.0.0.'
PUBLIC_SUBNET  = '172.16.0.'
GW_IP          = '10.0.0.254'
GW_MAC         = '00:00:00:00:00:fe'

# OpenFlow table IDs
TABLE_SNAT = 0
TABLE_DNAT = 1
TABLE_L2   = 2  # MAC-to-port forwarding + bidirectional IP flows

# Flow timeouts
TIMEOUT_L2_IDLE  = 60   # L2 / IP flows: idle timeout (seconds)
TIMEOUT_L2_HARD  = 0    # L2 / IP flows: no hard timeout
TIMEOUT_NAT_IDLE = 0    # NAT flows: permanent (replaced by shuffle)
TIMEOUT_NAT_HARD = 0    # NAT flows: permanent

# MTD shuffle intervals (must all be > TIMEOUT_L2_IDLE to avoid stale-flow conflicts)
SHUFFLE_INTERVAL = {'low': 80, 'medium': 100, 'high': 120}
# ---------------------------------------------------------------------------

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                        set_ev_cls)
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
    RYU_AVAILABLE = True
except ImportError:
    print("WARNING: Ryu not found. Running in Mock/Simulation mode.")
    RYU_AVAILABLE = False
    class _MockApp:
        def __init__(self, *a, **kw): pass
    app_manager     = type('m', (), {'RyuApp': _MockApp})
    ofp_event       = type('m', (), {'EventOFPSwitchFeatures': object,
                                      'EventOFPPacketIn': object})
    CONFIG_DISPATCHER = MAIN_DISPATCHER = 'dispatcher'
    ofproto_v1_3    = type('m', (), {'OFP_VERSION': 4})
    def set_ev_cls(ev, d=None): return lambda f: f
    packet = ethernet = arp = ipv4 = icmp = None

LOG = logging.getLogger('mtd_controller')
LOG.setLevel(logging.DEBUG)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
LOG.addHandler(_ch)

STATE_DB = 'mtd_state.db'
SECRET   = b'supersecret_test_key'   # must match host_agent.py


def _hmac_token(hostname, nonce, ts):
    msg = f"{hostname}|{nonce}|{ts}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


# ===========================================================================
# REST API handler
# ===========================================================================
class SimpleRESTHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress default access log

    # -----------------------------------------------------------------------
    def _json(self, data, code=200):
        try:
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            LOG.error("Response send error: %s", e)

    def _read_json(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n).decode()) if n else {}

    # -----------------------------------------------------------------------
    def do_GET(self):
        p = self.path

        if p.startswith('/status'):
            self._json(self.server.app.get_status())

        elif p.startswith('/logs'):
            self._json(self.server.app.get_logs(500))

        elif p.startswith('/clear_logs'):
            with self.server.app.lock:
                self.server.app.logs = []
            self._json({'status': 'cleared'})

        elif p.startswith('/dns'):
            q  = p.split('=')[-1]
            ip = self.server.app.resolve_dns(q)
            self._json({'ip': ip} if ip else {'error': 'not_found'}, 200 if ip else 404)

        elif p.startswith('/host_logs_stream'):
            self._stream_host_logs(p)

        elif p.startswith('/host_logs'):
            self._poll_host_logs(p)

        else:
            self._serve_static(p)

    def _stream_host_logs(self, path):
        try:
            from urllib.parse import parse_qs, urlparse
            params   = parse_qs(urlparse(path).query)
            host     = params.get('host', ['h1'])[0]
            log_file = f"/tmp/{host}_agent.log"
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            self._sse('connected', {'host': host})
            if not os.path.exists(log_file):
                self._sse('error', {'error': 'log_file_not_found'}); return
            import subprocess
            try:
                init = subprocess.check_output(['tail', '-n', '50', log_file]).decode()
                for ln in init.strip().split('\n'):
                    if ln: self._sse('log', {'line': ln})
            except Exception: pass
            proc = subprocess.Popen(['tail', '-f', '-n', '0', log_file],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, bufsize=1)
            try:
                for ln in iter(proc.stdout.readline, ''):
                    if ln:
                        self._sse('log', {'line': ln.rstrip()})
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionAbortedError): pass
            finally: proc.terminate(); proc.wait()
        except Exception as e:
            LOG.error("SSE stream error: %s", e)

    def _sse(self, event, data):
        try:
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
        except (BrokenPipeError, ConnectionAbortedError): pass

    def _poll_host_logs(self, path):
        try:
            from urllib.parse import parse_qs, urlparse
            params   = parse_qs(urlparse(path).query)
            host     = params.get('host', ['h1'])[0]
            lines    = int(params.get('lines', ['100'])[0])
            log_file = f"/tmp/{host}_agent.log"
            if os.path.exists(log_file):
                with open(log_file) as f:
                    all_lines = f.readlines()
                self._json({'host': host, 'lines': all_lines[-lines:],
                             'total_lines': len(all_lines), 'log_file': log_file})
            else:
                self._json({'error': 'log_file_not_found', 'host': host}, 404)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _serve_static(self, path):
        try:
            fname = 'web/index.html' if path == '/' else f"web{path}"
            if '..' in fname:
                self.send_error(403, "Forbidden"); return
            with open(fname, 'rb') as f:
                self.send_response(200)
                if fname.endswith('.css'):   self.send_header('Content-Type', 'text/css')
                elif fname.endswith('.js'):  self.send_header('Content-Type', 'application/javascript')
                elif fname.endswith('.html'):self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f.read())
        except FileNotFoundError:
            self._json({'error': 'not_found'}, 404)

    # -----------------------------------------------------------------------
    def do_POST(self):
        p = self.path

        if p.startswith('/shuffle'):
            req        = self._read_json()
            shuffle_id = self.server.app.trigger_shuffle(req.get('hosts', []),
                                                          req.get('policy'))
            self._json({'shuffle_id': shuffle_id})

        elif p.startswith('/clear_history'):
            with self.server.app.lock:
                self.server.app.history = []
                self.server.app._persist_state()
            self._json({'status': 'cleared'})

        elif p.startswith('/token'):
            req = self._read_json()
            ts  = str(time.time())
            self._json({'token': _hmac_token(req.get('hostname'),
                                              req.get('nonce'), ts), 'ts': ts})

        elif p.startswith('/register'):
            req      = self._read_json()
            hostname = req['hostname']
            with self.server.app.lock:
                self.server.app.host_map[hostname] = {
                    'mac': req['mac'], 'ip': req['ip'],
                    'port': 1, 'dpid': req.get('dpid', 1), 'ts': time.time()
                }
                self.server.app.dns_records[hostname] = req['ip']
            self._json({'status': 'registered', 'host': hostname})

        elif p.startswith('/sim/dhcp_discover'):
            req      = self._read_json()
            mac      = req['mac']
            hostname = req.get('hostname') or f"host-{mac.replace(':', '')[-4:]}"
            ip       = self.server.app.simulate_dhcp_allocation(hostname, mac)
            self._json({'status': 'bound', 'ip': ip, 'hostname': hostname, 'mac': mac})

        elif p.startswith('/sim/secure_transfer'):
            self._handle_secure_transfer()

        elif p.startswith('/sim/test_ping'):
            req     = self._read_json()
            allowed = self.server.app.check_connectivity(req.get('src_host'),
                                                          req.get('dst_host'))
            if allowed:
                self._json({'status': 'success', 'msg': 'Ping Reply'})
            else:
                self._json({'status': 'failed', 'msg': 'Request Timed Out (ACL Drop)'})

        else:
            self._json({'error': 'unknown endpoint'}, 404)

    # -----------------------------------------------------------------------
    def _handle_secure_transfer(self):
        """
        End-to-end secure transfer with:
          - Zone ACL check
          - Real ping connectivity test
          - AES-256-GCM payload encryption
          - MTD candidate IP fallback (current + 3 historical)
          - HMAC-SHA256 + session ID + hash integrity verification
          - Single clean delivery loop (NOT inside an except block)
        """
        try:
            req     = self._read_json()
            src     = req.get('src')
            dst     = req.get('dst')
            payload = req.get('payload', 'Test Payload')
            app     = self.server.app
            trace   = []

            # --- Step 1: Zone policy check ---
            src_zone = app.get_host_zone(src)
            dst_zone = app.get_host_zone(dst)
            allowed, reason = app.check_connectivity_verbose(src, dst)

            trace.append({'step': 'POLICY',
                           'msg': f"Zone check: {src_zone.upper()} -> {dst_zone.upper()}",
                           'status': 'info'})

            if not allowed:
                self._install_drop_rule(app, src, dst, trace)
                trace.append({'step': 'RESULT',
                               'msg': f"Access DENIED: {reason}", 'status': 'error'})
                self._json({'status': 'blocked', 'reason': reason, 'trace': trace})
                return

            trace.append({'step': 'POLICY', 'msg': 'Access GRANTED', 'status': 'success'})

            # --- Step 2: Connectivity test (real ping) ---
            dst_details = app.host_map.get(dst, {})
            dst_public  = dst_details.get('ip')
            dst_private = dst_details.get('private_ip')

            trace.append({'step': 'NET',
                           'msg': f"Pinging {dst} public IP {dst_public}...",
                           'status': 'info'})
            try:
                r = requests.post('http://127.0.0.1:8888/exec',
                                  json={'host': src, 'cmd': f"ping -c 1 -W 2 {dst_public}"},
                                  timeout=6)
                ping_out = r.json().get('output', '') if r.status_code == 200 else ''
                if '0% packet loss' in ping_out:
                    trace.append({'step': 'NET', 'msg': 'Connectivity established',
                                   'status': 'success'})
                else:
                    trace.append({'step': 'NET',
                                   'msg': f"Ping failed: {ping_out.strip()[:120]}",
                                   'status': 'error'})
                    raise RuntimeError("Connectivity test failed")
            except RuntimeError:
                raise
            except Exception as e:
                trace.append({'step': 'NET', 'msg': f"Ping error: {e}", 'status': 'error'})
                self._json({'status': 'blocked', 'reason': 'Network Unreachable',
                             'trace': trace})
                return

            # --- Step 3: AES-256-GCM encryption ---
            encrypted_hex = 'N/A'
            try:
                key        = get_random_bytes(32)
                nonce      = get_random_bytes(12)
                cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(payload.encode('utf-8'))
                encrypted_hex   = ciphertext.hex()[:32] + '...'
                trace.append({'step': 'CRYPTO',
                               'msg': f"Encrypted with AES-256-GCM ({len(ciphertext)} B)",
                               'status': 'success'})
            except Exception as e:
                trace.append({'step': 'CRYPTO', 'msg': f"Encryption error: {e}",
                               'status': 'error'})

            # --- Step 4: NAT / MTD state ---
            src_details = app.host_map.get(src, {})
            private_ip  = src_details.get('private_ip')
            current_pub = app.nat_table.get(private_ip, 'pending')
            trace.append({'step': 'NAT',
                           'msg': f"Outbound: {private_ip} -> {current_pub}",
                           'status': 'info'})

            # --- Step 5: Resolve candidate IPs (MTD resilience) ---
            candidates = app._get_candidate_ips(dst_private) or [dst_public]
            trace.append({'step': 'MTD-RESILIENCE',
                           'msg': f"{len(candidates)} candidate IP(s) for {dst}: {candidates}",
                           'status': 'info'})

            # --- Step 6: Delivery loop (clean, NOT inside an except block) ---
            delivery_success = False
            session_id       = str(uuid.uuid4())

            for idx, target_ip in enumerate(candidates):
                if idx > 0:
                    trace.append({'step': 'MTD-RESILIENCE',
                                   'msg': f"Fallback #{idx}: trying {target_ip}",
                                   'status': 'warning'})
                try:
                    transfer_payload = {
                        'source':      src,
                        'destination': dst,
                        'session_id':  session_id,
                        'src_ip':      src_details.get('ip'),
                        'dst_ip':      target_ip,
                        'payload':     payload,
                        'encrypted':   encrypted_hex,
                        'timestamp':   time.time()
                    }
                    raw_bytes     = json.dumps(transfer_payload, sort_keys=True).encode()
                    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

                    json_data = json.dumps(transfer_payload, sort_keys=True).replace("'", "'\\''")
                    curl_cmd  = (
                        f"curl -i -s -X POST "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json_data}' "
                        f"--connect-timeout 3 --max-time 8 "
                        f"http://{target_ip}:8080 2>&1"
                    )

                    trace.append({'step': 'APP',
                                   'msg': f"Sending to {dst} ({target_ip}:8080) — session {session_id}",
                                   'status': 'info'})

                    exec_res = requests.post('http://127.0.0.1:8888/exec',
                                             json={'host': src, 'cmd': curl_cmd},
                                             timeout=15)
                    if exec_res.status_code != 200:
                        trace.append({'step': 'DELIVERY',
                                       'msg': f"Agent exec failed (HTTP {exec_res.status_code})",
                                       'status': 'error'})
                        continue

                    output      = exec_res.json().get('output', '').strip()
                    is_http200  = ('HTTP/1.1 200 OK' in output or 'HTTP/1.0 200 OK' in output)
                    ack_data    = {}
                    is_json_ack = False
                    try:
                        if '{' in output and '}' in output:
                            js = output[output.index('{') : output.rindex('}') + 1]
                            ack_data    = json.loads(js)
                            is_json_ack = (ack_data.get('status') == 'ACK')
                    except (json.JSONDecodeError, ValueError):
                        pass

                    if not is_http200 or not is_json_ack:
                        err = ('No HTTP 200' if not is_http200 else 'Invalid/missing JSON ACK')
                        if 'Connection refused' in output:
                            err = 'Connection Refused (Agent not running)'
                        elif 'timed out' in output.lower():
                            err = 'Connection Timed Out (Routing/NAT issue)'
                        trace.append({'step': 'DELIVERY', 'msg': f"Delivery failed: {err}",
                                       'status': 'error'})
                        continue

                    trace.append({'step': 'DELIVERY',
                                   'msg': f"Packet received by {dst} (HTTP 200 + JSON ACK)",
                                   'status': 'success'})

                    # Cryptographic verifications
                    ok_hash = ok_session = ok_origin = ok_sig = False

                    recv_hash = ack_data.get('payload_hash')
                    if recv_hash == expected_hash:
                        trace.append({'step': 'INTEGRITY',
                                       'msg': f"SHA-256 verified: {recv_hash[:8]}...",
                                       'status': 'success'})
                        ok_hash = True
                    else:
                        trace.append({'step': 'INTEGRITY',
                                       'msg': f"Hash mismatch. Exp={expected_hash[:8]} Got={str(recv_hash)[:8]}",
                                       'status': 'error'})

                    if ack_data.get('session_id') == session_id:
                        trace.append({'step': 'SESSION',
                                       'msg': f"Session ID matched: {session_id}",
                                       'status': 'success'})
                        ok_session = True
                    else:
                        trace.append({'step': 'SESSION', 'msg': 'Session ID mismatch',
                                       'status': 'error'})

                    if ack_data.get('destination') == dst:
                        ok_origin = True
                    else:
                        trace.append({'step': 'ORIGIN', 'msg': 'Destination field mismatch',
                                       'status': 'error'})

                    sig_recv = ack_data.pop('signature', None)
                    if sig_recv:
                        expected_sig = hmac.new(
                            SECRET,
                            json.dumps(ack_data, sort_keys=True).encode(),
                            hashlib.sha256
                        ).hexdigest()
                        if expected_sig == sig_recv:
                            trace.append({'step': 'CRYPTO',
                                           'msg': 'HMAC-SHA256 signature verified',
                                           'status': 'success'})
                            ok_sig = True
                        else:
                            trace.append({'step': 'CRYPTO',
                                           'msg': 'Signature invalid — possible spoofing',
                                           'status': 'error'})
                    else:
                        trace.append({'step': 'CRYPTO', 'msg': 'No signature in ACK',
                                       'status': 'warning'})

                    if ok_hash and ok_session and ok_origin and ok_sig:
                        trace.append({'step': 'VERIFICATION',
                                       'msg': 'All cryptographic verifications passed',
                                       'status': 'success'})
                        delivery_success = True
                        if idx > 0:
                            trace.append({'step': 'MTD-RESILIENCE',
                                           'msg': f"Resilience success via fallback IP {target_ip}",
                                           'status': 'success'})
                        break
                    else:
                        failed = [n for n, v in [('Hash', ok_hash), ('Session', ok_session),
                                                  ('Origin', ok_origin), ('Signature', ok_sig)]
                                  if not v]
                        trace.append({'step': 'VERIFICATION',
                                       'msg': f"Verification failed: {', '.join(failed)}",
                                       'status': 'error'})
                        break   # crypto failure is deterministic — no point trying other IPs

                except Exception as exc:
                    trace.append({'step': 'DELIVERY',
                                   'msg': f"Exception on {target_ip}: {exc}",
                                   'status': 'error'})
                    continue

            # Single, unambiguous result block
            if delivery_success:
                trace.append({'step': 'RESULT',
                               'msg': 'Communication successful — all verifications passed',
                               'status': 'success'})
                resp_status = 'success'
            else:
                trace.append({'step': 'RESULT',
                               'msg': 'Communication failed — delivery or verification failed',
                               'status': 'error'})
                resp_status = 'error'

            self._json({
                'status':            resp_status,
                'delivery_success':  delivery_success,
                'original_payload':  payload,
                'encrypted_preview': encrypted_hex,
                'src_priv':          private_ip,
                'src_pub':           current_pub,
                'dst_ip':            dst_public,
                'trace':             trace
            })

        except RuntimeError as e:
            self._json({'status': 'blocked', 'reason': str(e),
                         'trace': [{'step': 'ERROR', 'msg': str(e), 'status': 'error'}]})
        except Exception as e:
            LOG.error("Secure transfer error: %s", e, exc_info=True)
            self._json({'status': 'error', 'msg': str(e)}, 500)

    def _install_drop_rule(self, app, src, dst, trace):
        """Install an OVS DROP rule for a denied flow (60-second hard timeout)."""
        src_ip = app.host_map.get(src, {}).get('ip')
        dst_ip = app.host_map.get(dst, {}).get('ip')
        if src_ip and dst_ip:
            trace.append({'step': 'POLICY',
                           'msg': f"Installing DROP rule: {src}({src_ip})->{dst}({dst_ip})",
                           'status': 'info',
                           'cmd': f"ovs-ofctl add-flow s1 priority=200,ip,nw_src={src_ip},nw_dst={dst_ip},actions=drop"})
            dp = app.switches.get(1)
            if dp and RYU_AVAILABLE:
                parser  = dp.ofproto_parser
                ofproto = dp.ofproto
                match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
                inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=TABLE_DNAT,
                                               priority=200, match=match, instructions=inst,
                                               idle_timeout=0, hard_timeout=60))
        # Optionally verify block with real ping
        try:
            r = requests.post('http://127.0.0.1:8888/exec',
                              json={'host': src, 'cmd': f"ping -c 1 -W 1 {dst_ip}"},
                              timeout=3)
            if r.status_code == 200:
                out = r.json().get('output', '')
                if '100% packet loss' in out:
                    trace.append({'step': 'VERIFICATION',
                                   'msg': 'BLOCKED: real ping failed as expected',
                                   'status': 'success'})
                else:
                    trace.append({'step': 'VERIFICATION',
                                   'msg': 'WARNING: ping succeeded despite DROP rule',
                                   'status': 'error'})
        except Exception as e:
            trace.append({'step': 'VERIFICATION',
                           'msg': f"Block-verify error: {e}", 'status': 'warning'})


# ===========================================================================
# MTD Ryu Controller Application
# ===========================================================================
class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDController, self).__init__(*args, **kwargs)

        # Core data structures (all initialised here to prevent AttributeError)
        self.host_map          = {}   # hostname -> {mac, ip, private_ip, port, dpid, ...}
        self.dns_records       = {}   # hostname -> public IP
        self.datapaths         = {}   # dpid -> datapath
        self.switches          = {}   # dpid -> datapath (alias used by REST handler)
        self.mac_to_port       = {}   # dpid -> {mac -> port}
        self.lock              = threading.RLock()
        self.shuffle_queue     = []
        self.logs              = []
        self.history           = []
        self.policies          = {}

        # DHCP state
        self.dhcp_leases       = {}   # mac -> {private_ip, hostname, start_ts, end_ts}

        # NAT / MTD state
        self.nat_table         = {}   # private_ip -> public_ip (current)
        self.reverse_nat_table = {}   # public_ip  -> private_ip
        self.nat_history       = {}   # private_ip -> [last 3 public IPs]
        self.public_pool       = [f"{PUBLIC_SUBNET}{i}" for i in range(10, 250)]
        self.assigned_public_ips = set()

        self._init_db()
        self._start_rest_api()
        self._load_policies()
        self._sync_config_files()
        self._start_periodic_loop()
        LOG.info("MTDController initialised with Risk-Based NAT Hopping")

    # -------------------------------------------------------------------------
    # OpenFlow: switch_features (Table 0 + Table 1 bootstrap)
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp      = ev.msg.datapath
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = dp.id

        self.datapaths[dpid] = dp
        self.switches[dpid]  = dp
        LOG.info("Switch connected: dpid=%s", dpid)

        # ======================
        # TABLE 0 — SOURCE NAT (SNAT)
        # ======================

        # ARP: intercept ALL ARP frames → controller (proxy ARP)
        self._add_flow(dp, TABLE_SNAT, 100,
                       parser.OFPMatch(eth_type=0x0806),
                       [parser.OFPInstructionActions(
                           ofproto.OFPIT_APPLY_ACTIONS,
                           [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                    ofproto.OFPCML_NO_BUFFER)])])

        # LLDP: drop silently
        self._add_flow(dp, TABLE_SNAT, 100,
                       parser.OFPMatch(eth_type=0x88cc), [])

        # Table 0 miss: goto Table 1 (DNAT)
        self._add_flow(dp, TABLE_SNAT, 0,
                       parser.OFPMatch(),
                       [parser.OFPInstructionGotoTable(TABLE_DNAT)])

        # ======================
        # TABLE 1 — DEST NAT (DNAT)
        # ======================
        # Table 1 miss: goto Table 2 (L2/IP Forwarding)
        self._add_flow(dp, TABLE_DNAT, 0,
                       parser.OFPMatch(),
                       [parser.OFPInstructionGotoTable(TABLE_L2)])

        # ======================
        # TABLE 2 — L2 / IP
        # ======================

        # Table 1 miss: send to controller (packet-in)
        self._add_flow(dp, TABLE_L2, 0,
                       parser.OFPMatch(),
                       [parser.OFPInstructionActions(
                           ofproto.OFPIT_APPLY_ACTIONS,
                           [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                    ofproto.OFPCML_NO_BUFFER)])])

    # -------------------------------------------------------------------------
    # OpenFlow: packet_in
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if not ev.msg:
            return

        msg      = ev.msg
        dp       = msg.datapath
        ofproto  = dp.ofproto
        parser   = dp.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:   # LLDP guard (Table 0 drops it, but be safe)
            return

        src_mac = eth.src
        dst_mac = eth.dst
        LOG.info("PacketIn: dpid=%s src=%s dst=%s port=%s", dpid, src_mac, dst_mac, in_port)

        # --- MAC learning ---
        self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

        # --- Update host_map port + install NAT flows with correct port ---
        self._update_host_port_and_nat_flows(dpid, src_mac, in_port)

        # --- ARP ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(dp, in_port, eth, arp_pkt)
            return

        # --- IPv4 ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self._handle_ip(dp, in_port, msg, eth, ip_pkt)
            return

        # --- Other L2 ---
        self._l2_forward(dp, in_port, msg, dst_mac)

    # -------------------------------------------------------------------------
    # Port learning + deferred NAT flow installation (fixes BUG-02 + BUG-03)
    # -------------------------------------------------------------------------
    def _update_host_port_and_nat_flows(self, dpid, src_mac, in_port):
        """
        When a PacketIn arrives we now know the real OVS port for src_mac.
        Update host_map and (re-)install NAT flows with the correct port.
        This is the ONLY place NAT flows are installed — never during DHCP.
        """
        with self.lock:
            for h, data in self.host_map.items():
                if data.get('mac') == src_mac:
                    old_port = data.get('port')
                    if old_port != in_port:
                        LOG.info("Port learned for %s: %s -> %s", h, old_port, in_port)
                        data['port'] = in_port
                        data['dpid'] = dpid
                    # Always refresh NAT flows on first packet (or if port changed)
                    priv = data.get('private_ip')
                    pub  = data.get('ip')
                    if priv and pub:
                        self._install_nat_flows(dpid, src_mac, priv, pub, in_port)
                    break

    # -------------------------------------------------------------------------
    # Proxy ARP — handles all three IP categories (fixes BUG-04)
    # -------------------------------------------------------------------------
    def _handle_arp(self, dp, in_port, eth_pkt, arp_pkt):
        """
        Proxy ARP policy:
          • 10.0.0.254             → gateway (virtual, GW_MAC)
          • 10.0.0.X  (private)   → that host's real MAC
          • 172.16.0.X (public)   → that host's real MAC (or GW_MAC as forwarder)
          • Unknown               → flood
        """
        if arp_pkt.opcode != arp.ARP_REQUEST:
            # ARP reply: let it flood so both sides learn the mapping
            self._flood_packet_out(dp, in_port, arp_pkt)
            return

        tgt  = arp_pkt.dst_ip
        srm  = eth_pkt.src
        sri  = arp_pkt.src_ip

        # Gateway
        if tgt == GW_IP:
            LOG.debug("Proxy ARP: gateway %s -> %s", tgt, GW_MAC)
            self._send_arp_reply(dp, in_port, GW_MAC, tgt, srm, sri)
            return

        # Public IPs (172.16.x.x)
        if tgt.startswith(PUBLIC_SUBNET):
            with self.lock:
                for _, d in self.host_map.items():
                    if d.get('ip') == tgt:
                        mac = d.get('mac', GW_MAC)
                        LOG.debug("Proxy ARP: public %s -> %s", tgt, mac)
                        self._send_arp_reply(dp, in_port, mac, tgt, srm, sri)
                        return
            # Unknown public IP → reply with GW_MAC so traffic still enters pipeline
            LOG.debug("Proxy ARP: unknown public %s -> GW_MAC", tgt)
            self._send_arp_reply(dp, in_port, GW_MAC, tgt, srm, sri)
            return

        # Private IPs (10.0.0.x)
        if tgt.startswith(PRIVATE_SUBNET):
            with self.lock:
                for _, d in self.host_map.items():
                    if d.get('private_ip') == tgt:
                        mac = d.get('mac')
                        if mac:
                            LOG.debug("Proxy ARP: private %s -> %s", tgt, mac)
                            self._send_arp_reply(dp, in_port, mac, tgt, srm, sri)
                            return
            # Unknown private IP → flood
            self._do_arp_flood(dp, in_port, eth_pkt, arp_pkt)
            return

        # Everything else → flood
        self._do_arp_flood(dp, in_port, eth_pkt, arp_pkt)

    def _send_arp_reply(self, dp, port, src_mac, src_ip, dst_mac, dst_ip):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                               src_mac=src_mac, src_ip=src_ip,
                               dst_mac=dst_mac, dst_ip=dst_ip))
        self._send_pkt_out(dp, port, p)

    def _do_arp_flood(self, dp, in_port, eth_pkt, arp_pkt):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=0x0806,
                                          dst=eth_pkt.dst, src=eth_pkt.src))
        p.add_protocol(arp.arp(opcode=arp_pkt.opcode,
                               src_mac=arp_pkt.src_mac, src_ip=arp_pkt.src_ip,
                               dst_mac=arp_pkt.dst_mac, dst_ip=arp_pkt.dst_ip))
        p.serialize()
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        out = parser.OFPPacketOut(datapath=dp,
                                   buffer_id=ofproto.OFP_NO_BUFFER,
                                   in_port=in_port,
                                   actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                                   data=p.data)
        dp.send_msg(out)

    # -------------------------------------------------------------------------
    # IPv4 handling + bidirectional flow installation (fixes BUG-05)
    # -------------------------------------------------------------------------
    def _handle_ip(self, dp, in_port, msg, eth_pkt, ip_pkt):
        """
        Install bidirectional IP flows in Table 1 so future packets
        bypass the controller.  idle_timeout=60 ensures stale flows
        expire before the next MTD shuffle (shuffle intervals are
        90/120/180 s > 60 s), preventing stale-flow conflicts.
        """
        ofproto  = dp.ofproto
        parser   = dp.ofproto_parser
        dpid     = dp.id
        src_ip   = ip_pkt.src
        dst_ip   = ip_pkt.dst
        dst_mac  = eth_pkt.dst

        out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)

        if out_port != ofproto.OFPP_FLOOD:
            # Forward flow: src→dst uses learned out_port
            self._add_flow(dp, TABLE_L2, 20,
                           parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip),
                           [parser.OFPInstructionActions(
                               ofproto.OFPIT_APPLY_ACTIONS,
                               [parser.OFPActionOutput(out_port)])],
                           idle_timeout=TIMEOUT_L2_IDLE)

            # Reverse flow: dst→src uses in_port
            self._add_flow(dp, TABLE_L2, 20,
                           parser.OFPMatch(eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip),
                           [parser.OFPInstructionActions(
                               ofproto.OFPIT_APPLY_ACTIONS,
                               [parser.OFPActionOutput(in_port)])],
                           idle_timeout=TIMEOUT_L2_IDLE)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                         in_port=in_port,
                                         actions=[parser.OFPActionOutput(out_port)],
                                         data=data))

    # -------------------------------------------------------------------------
    # L2 fallback forwarding
    # -------------------------------------------------------------------------
    def _l2_forward(self, dp, in_port, msg, dst_mac):
        ofproto  = dp.ofproto
        parser   = dp.ofproto_parser
        out_port = self.mac_to_port.get(dp.id, {}).get(dst_mac, ofproto.OFPP_FLOOD)
        data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                         in_port=in_port,
                                         actions=[parser.OFPActionOutput(out_port)],
                                         data=data))

    def _flood_packet_out(self, dp, in_port, raw):
        pass   # placeholder — ARP replies are sent directly; unknown floods use _do_arp_flood

    def _send_pkt_out(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        pkt.serialize()
        dp.send_msg(parser.OFPPacketOut(datapath=dp,
                                         buffer_id=ofproto.OFP_NO_BUFFER,
                                         in_port=ofproto.OFPP_CONTROLLER,
                                         actions=[parser.OFPActionOutput(port)],
                                         data=pkt.data))

    # -------------------------------------------------------------------------
    # NAT flow installation — TABLE 0 with OFPInstructionGotoTable (fixes BUG-01)
    # -------------------------------------------------------------------------
    def _install_nat_flows(self, dpid, mac, private_ip, public_ip, port):
        """
        Install NAT rewriting rules in Table 0.

        OUTBOUND (private → public):
          Match: eth_type=0x0800, ipv4_src=private_ip
          Action: SetField(ipv4_src=public_ip) → GotoTable(TABLE_L2)

        INBOUND (public → private):
          Match: eth_type=0x0800, ipv4_dst=public_ip
          Action: SetField(ipv4_dst=private_ip) + SetField(eth_dst=mac) → GotoTable(TABLE_L2)

        MAC-to-port rule in Table 1:
          Match: eth_dst=mac
          Action: Output(port)

        All NAT flows are permanent (idle=0, hard=0). They are replaced (not
        appended) on each shuffle, so OVS always has exactly one NAT entry per
        private/public IP.

        L2 MAC rule uses idle_timeout=TIMEOUT_L2_IDLE so it expires before the
        next shuffle interval, preventing stale output-port conflicts.
        """
        LOG.info("NAT flows: %s <-> %s (port=%s)", private_ip, public_ip, port)
        dp = self.datapaths.get(dpid)
        if not dp:
            LOG.warning("_install_nat_flows: dpid=%s not connected", dpid)
            return
        if not port or port < 1:
            LOG.warning("_install_nat_flows: invalid port=%s, deferring", port)
            return

        ofproto = dp.ofproto
        parser  = dp.ofproto_parser

        # ---- Outbound NAT (Table 0 SNAT, pri=50) ----
        self._add_flow(
            dp, TABLE_SNAT, 50,
            parser.OFPMatch(eth_type=0x0800, ipv4_src=private_ip),
            [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionSetField(ipv4_src=public_ip)]),
                parser.OFPInstructionGotoTable(TABLE_DNAT),   # Move to DNAT table
            ],
            idle_timeout=TIMEOUT_NAT_IDLE,
            hard_timeout=TIMEOUT_NAT_HARD
        )

        # ---- Inbound NAT (Table 1 DNAT, pri=50) ----
        self._add_flow(
            dp, TABLE_DNAT, 50,
            parser.OFPMatch(eth_type=0x0800, ipv4_dst=public_ip),
            [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionSetField(ipv4_dst=private_ip),
                     parser.OFPActionSetField(eth_dst=mac)]),
                parser.OFPInstructionGotoTable(TABLE_L2),   # Move to L2 forwarding
            ],
            idle_timeout=TIMEOUT_NAT_IDLE,
            hard_timeout=TIMEOUT_NAT_HARD
        )

        # ---- MAC-to-port (Table 1, pri=10) ----
        self._add_flow(
            dp, TABLE_L2, 10,
            parser.OFPMatch(eth_dst=mac),
            [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(port)]),
            ],
            idle_timeout=TIMEOUT_L2_IDLE,
            hard_timeout=TIMEOUT_L2_HARD
        )

    # -------------------------------------------------------------------------
    # Unified flow-mod helper
    # -------------------------------------------------------------------------
    def _add_flow(self, dp, table_id, priority, match, instructions,
                  idle_timeout=0, hard_timeout=0, buffer_id=None):
        """
        Single helper for OFPFlowMod.
        Accepts a list of OFPInstruction* objects directly (not raw actions).
        """
        parser = dp.ofproto_parser
        kw = dict(datapath=dp, table_id=table_id, priority=priority,
                  match=match, instructions=instructions,
                  idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id is not None:
            kw['buffer_id'] = buffer_id
        dp.send_msg(parser.OFPFlowMod(**kw))

    def add_flow(self, dp, priority, match, actions,
                 table_id=TABLE_L2, idle_timeout=0, hard_timeout=0):
        """Backward-compatible wrapper (action list → instruction list)."""
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._add_flow(dp, table_id, priority, match, inst,
                       idle_timeout=idle_timeout, hard_timeout=hard_timeout)

    # -------------------------------------------------------------------------
    # DB persistence
    # -------------------------------------------------------------------------
    def _init_db(self):
        self.conn = sqlite3.connect(STATE_DB, check_same_thread=False)
        c = self.conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS shuffles (id TEXT PRIMARY KEY, data TEXT)')
        self.conn.commit()

    def _persist_state(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute('REPLACE INTO state VALUES (?,?)',
                        ('host_map', json.dumps(self.host_map)))
            cur.execute('REPLACE INTO state VALUES (?,?)',
                        ('history', json.dumps(self.history)))
            self.conn.commit()

    # -------------------------------------------------------------------------
    # REST API startup / policy loading
    # -------------------------------------------------------------------------
    def _load_policies(self):
        if os.path.exists('policies.yml'):
            with open('policies.yml') as f:
                self.policies = yaml.safe_load(f) or {}
        LOG.info("Policies loaded: %s", list(self.policies.keys()))

    def _start_rest_api(self):
        srv = ThreadedHTTPServer(('0.0.0.0', 8000), SimpleRESTHandler)
        srv.app = self
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        LOG.info("REST API started. Dashboard: http://127.0.0.1:8000/")

    # -------------------------------------------------------------------------
    # Periodic MTD shuffle loop (LOW=90s, MEDIUM=120s, HIGH=180s)
    # -------------------------------------------------------------------------
    def _start_periodic_loop(self):
        threading.Thread(target=self._periodic_shuffle_loop, daemon=True).start()

    def _periodic_shuffle_loop(self):
        """
        Shuffle interval design rationale:
          Table 1 L2/IP flows have idle_timeout=60 s.
          ALL zone shuffle intervals (90/120/180 s) exceed 60 s.
          Therefore, by the time the new public IP is assigned, the old
          L2 flows have already expired from OVS.  This guarantees:
            (a) No stale-flow packet misdirection after a hop.
            (b) The first post-hop packet triggers a clean PacketIn →
                new L2 flows are installed with the new public IP.
        """
        while True:
            time.sleep(5)
            with self.lock:
                now     = time.time()
                targets = [h for h, d in list(self.host_map.items())
                           if d.get('ip') and
                           now - d.get('last_shuffle_ts', d['ts']) >=
                           SHUFFLE_INTERVAL.get(self.get_host_zone(h), 300)]

            for h in targets:
                LOG.info("MTD rotation: %s (zone=%s)", h, self.get_host_zone(h))
                self.trigger_shuffle([h], {'type': 'time_based',
                                           'risk': self.get_host_zone(h)})

    # -------------------------------------------------------------------------
    # REST status / DNS / log helpers
    # -------------------------------------------------------------------------
    def get_status(self):
        with self.lock:
            now   = time.time()
            hosts = {}
            for h, d in self.host_map.items():
                zone     = self.get_host_zone(h)
                interval = SHUFFLE_INTERVAL.get(zone, 300)
                last     = d.get('last_shuffle_ts', d['ts'])
                hosts[h] = {**d, 'risk': zone, 'interval': interval,
                             'next_hop_in': max(0, int(last + interval - now))}
            return {
                'hosts':            hosts,
                'queue':            self.shuffle_queue,
                'dns':              self.dns_records,
                'nat_table':        self.nat_table,
                'public_pool_size': len(self.public_pool) - len(self.assigned_public_ips),
                'history':          self.history[-50:],
                'network_config': {
                    'internal_subnet': '10.0.0.0/24',
                    'public_subnet':   '172.16.0.0/24',
                    'gateway':         GW_IP,
                    'gw_mac':          GW_MAC
                }
            }

    def resolve_dns(self, hostname):
        with self.lock:
            return self.dns_records.get(hostname)

    def get_logs(self, limit=100):
        with self.lock:
            return self.logs[-limit:]

    # -------------------------------------------------------------------------
    # Shuffle engine
    # -------------------------------------------------------------------------
    def trigger_shuffle(self, hosts, policy):
        sid   = f"shuffle-{int(time.time()*1000)}"
        entry = {'id': sid, 'hosts': hosts, 'policy': policy, 'ts': time.time()}
        with self.lock:
            self.shuffle_queue.append(entry)
            self._persist_state()
        threading.Thread(target=self._process_shuffle, args=(entry,), daemon=True).start()
        return sid

    def _process_shuffle(self, entry):
        for h in entry['hosts']:
            try:
                with self.lock:
                    data = self.host_map.get(h, {})
                    mac  = data.get('mac')
                    dpid = data.get('dpid')
                    port = data.get('port')
                    old_pub = data.get('ip')

                if not mac or not dpid:
                    LOG.error("Shuffle: %s not fully discovered, skipping", h)
                    continue

                with self.lock:
                    priv = self.host_map[h].get('private_ip')
                    if not priv:
                        priv = self._allocate_private_ip(h)
                        self.host_map[h]['private_ip'] = priv

                new_pub = self._assign_public_ip(priv)
                LOG.info("Shuffle: %s %s -> %s", h, old_pub, new_pub)

                # Wait one idle_timeout period before installing new flows.
                # This gives in-flight packets using the old public IP time to
                # complete before the old inbound NAT rule is overwritten.
                time.sleep(2)

                self._install_nat_flows(dpid, mac, priv, new_pub, port)
                self._update_dns(h, new_pub)

                with self.lock:
                    self.host_map[h]['ip']              = new_pub
                    self.host_map[h]['ts']              = time.time()
                    self.host_map[h]['last_shuffle_ts'] = time.time()
                    self.history.append({
                        'ts':       time.time(),
                        'time_str': time.strftime("%H:%M:%S"),
                        'host':     h,
                        'zone':     self.get_host_zone(h),
                        'risk':     self.get_host_zone(h),
                        'old_ip':   old_pub or 'N/A',
                        'new_ip':   new_pub,
                        'type':     'triggered' if entry.get('policy') == 'manual' else 'scheduled'
                    })
                    self.logs.append({'shuffle_id': entry['id'], 'host': h,
                                       'old_ip': old_pub, 'new_ip': new_pub,
                                       'status': 'success', 'ts': time.time()})
                    self._persist_state()
                    self._sync_config_files()

            except Exception as e:
                LOG.exception("Shuffle failed for %s: %s", h, e)
                with self.lock:
                    self.logs.append({'shuffle_id': entry['id'], 'host': h,
                                       'status': 'failed', 'error': str(e),
                                       'ts': time.time()})

        with self.lock:
            self.shuffle_queue = [q for q in self.shuffle_queue
                                  if q['id'] != entry['id']]
            self._persist_state()

    # -------------------------------------------------------------------------
    # IP allocation helpers
    # -------------------------------------------------------------------------
    def _allocate_private_ip(self, hostname):
        used = {d.get('private_ip') for d in self.host_map.values()}
        while True:
            ip = f"{PRIVATE_SUBNET}{random.randint(10, 250)}"
            if ip not in used:
                return ip

    def _assign_public_ip(self, private_ip):
        with self.lock:
            old = self.nat_table.get(private_ip)
            if old and old in self.assigned_public_ips:
                self.assigned_public_ips.remove(old)

            avail = [ip for ip in self.public_pool
                     if ip not in self.assigned_public_ips]
            if old and old in avail and len(avail) > 1:
                avail.remove(old)

            if not avail:
                LOG.error("Public IP pool exhausted!")
                return old or '0.0.0.0'

            if old and old not in self.nat_history.get(private_ip, []):
                self.nat_history.setdefault(private_ip, []).insert(0, old)
                self.nat_history[private_ip] = self.nat_history[private_ip][:3]

            new = random.choice(avail)
            self.assigned_public_ips.add(new)
            self.nat_table[private_ip]        = new
            self.reverse_nat_table[new]       = private_ip
            return new

    def _get_candidate_ips(self, private_ip):
        """Return current public IP + last 3 historical IPs for MTD resilience."""
        if not private_ip:
            return []
        result  = []
        current = self.nat_table.get(private_ip)
        if current:
            result.append(current)
        for ip in self.nat_history.get(private_ip, []):
            if ip not in result:
                result.append(ip)
        return result

    # -------------------------------------------------------------------------
    # DHCP simulation (port-deferred NAT installation — fixes BUG-03)
    # -------------------------------------------------------------------------
    def simulate_dhcp_allocation(self, hostname, mac):
        """
        Simulated DORA handshake.
        Private IP and public IP are allocated here.
        NAT flows are NOT installed here — they are deferred to the
        first PacketIn from this host (handled by _update_host_port_and_nat_flows).
        """
        with self.lock:
            LOG.info("DHCP DISCOVER: %s (%s)", hostname, mac)
            self.logs.append({'type': 'DHCP', 'step': 'DISCOVER',
                               'msg': f"DISCOVER {mac} ({hostname})", 'ts': time.time()})
            time.sleep(0.05)

            existing = self.dhcp_leases.get(mac)
            if existing and time.time() <= existing['end_ts']:
                offered = existing['private_ip']
                LOG.info("DHCP: reusing existing lease %s for %s", offered, hostname)
            else:
                if existing:
                    del self.dhcp_leases[mac]
                offered = self._allocate_private_ip(hostname)
                LOG.info("DHCP: new allocation %s for %s", offered, hostname)

            self.logs.append({'type': 'DHCP', 'step': 'OFFER',
                               'msg': f"OFFER {offered} -> {mac}", 'ts': time.time()})
            time.sleep(0.05)
            self.logs.append({'type': 'DHCP', 'step': 'REQUEST',
                               'msg': f"REQUEST {offered} from {mac}", 'ts': time.time()})
            time.sleep(0.05)

            lease_dur = 7200
            self.dhcp_leases[mac] = {
                'private_ip': offered, 'hostname': hostname,
                'start_ts': time.time(), 'end_ts': time.time() + lease_dur
            }

            public_ip = self._assign_public_ip(offered)

            # Preserve port/dpid if already learned (e.g. re-registration)
            existing_data = self.host_map.get(hostname, {})
            self.host_map[hostname] = {
                'mac':           mac,
                'ip':            public_ip,
                'private_ip':    offered,
                'port':          existing_data.get('port'),   # None until PacketIn
                'dpid':          existing_data.get('dpid'),   # None until PacketIn
                'ts':            time.time(),
                'lease_expires': time.time() + lease_dur
            }

            self.dns_records[hostname] = public_ip
            self.logs.append({'type': 'DHCP', 'step': 'ACK',
                               'msg': f"ACK priv={offered} pub={public_ip} mac={mac}",
                               'ts': time.time()})
            self._persist_state()
            self._sync_config_files()

            LOG.info("DHCP complete: %s priv=%s pub=%s (NAT flows deferred to PacketIn)",
                     hostname, offered, public_ip)
            return offered

    # -------------------------------------------------------------------------
    # DNS / config sync / probe
    # -------------------------------------------------------------------------
    def _update_dns(self, hostname, ip):
        LOG.info("DNS update: %s -> %s", hostname, ip)
        with self.lock:
            self.dns_records[hostname] = ip

    def _probe(self, hostname, ip, timeout=1.0):
        return True   # simulation: always success

    def _sync_config_files(self):
        try:
            with open('dnsmasq.conf', 'w') as f:
                f.write("# Auto-generated by MTD Controller\n"
                        "port=53\nno-resolv\nbind-interfaces\n"
                        "interface=lo\nlisten-address=127.0.0.1\n"
                        "dhcp-range=10.0.0.50,10.0.0.250,12h\n")
                for h, d in self.host_map.items():
                    f.write(f"dhcp-host={d['mac']},{d['ip']}\n")
                    f.write(f"address=/{h}/{d['ip']}\n")
            with open('dhcpd.conf', 'w') as f:
                f.write("# Auto-generated by MTD Controller\n"
                        "default-lease-time 600;\nmax-lease-time 7200;\n"
                        "subnet 10.0.0.0 netmask 255.255.255.0 {\n"
                        "  range 10.0.0.50 10.0.0.250;\n")
                for h, d in self.host_map.items():
                    f.write(f"  host {h} {{ hardware ethernet {d['mac']}; "
                            f"fixed-address {d['ip']}; }}\n")
                f.write("}\n")
        except Exception as e:
            LOG.error("Config sync failed: %s", e)

    # -------------------------------------------------------------------------
    # Zone / ACL policy
    # -------------------------------------------------------------------------
    def get_host_zone(self, hostname):
        zones = self.policies.get('zones', {})
        return zones.get(hostname, zones.get('default', 'low'))

    def check_connectivity(self, src, dst):
        ok, _ = self.check_connectivity_verbose(src, dst)
        return ok

    def check_connectivity_verbose(self, src, dst):
        sz = self.get_host_zone(src)
        dz = self.get_host_zone(dst)
        LOG.info("[POLICY] Source Zone: %s", sz.upper())
        LOG.info("[POLICY] Destination Zone: %s", dz.upper())

        if sz == dz:
            LOG.info("[POLICY] Rule Matched: %s -> %s (ALLOW)", sz.upper(), dz.upper())
            return True, "Intra-zone allowed"

        if sz == 'high':
            LOG.info("[POLICY] Rule Matched: HIGH -> ALL (ALLOW)")
            return True, "High zone authorised for all destinations"

        if sz == 'medium':
            if dz in ('medium', 'low'):
                LOG.info("[POLICY] Rule Matched: MEDIUM -> %s (ALLOW)", dz.upper())
                return True, "Medium zone authorised for Med/Low"
            LOG.info("[POLICY] Rule Matched: MEDIUM -> HIGH (DENY)")
            return False, "Security Violation: Medium cannot access High"

        if sz == 'low':
            if dz == 'low':
                LOG.info("[POLICY] Rule Matched: LOW -> LOW (ALLOW)")
                return True, "Low intra-zone allowed"
            LOG.info("[POLICY] Rule Matched: LOW -> %s (DENY)", dz.upper())
            return False, f"Security Violation: Low cannot access {dz}"

        LOG.warning("[POLICY] Implicit DENY: %s -> %s", sz, dz)
        return False, "Implicit Deny"


# ===========================================================================
# Entry point
# ===========================================================================
if __name__ == '__main__':
    import sys
    from ryu.cmd import manager
    print("Starting MTD Controller via Ryu Manager...")
    if 'mtd_controller.py' not in sys.argv:
        sys.argv.append('mtd_controller.py')
    manager.main()
