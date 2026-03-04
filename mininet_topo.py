#!/usr/bin/env python3
"""
Mininet Topology — Final Stable Version
Project: SDN-Based Moving Target Defense (Final Year B.Tech Cybersecurity)

Topology: N hosts (default 6) connected to one OVS switch (OpenFlow 1.3).
          Controller = Ryu (remote, port 6633).

Startup sequence:
  1. Build Mininet topology (hosts start with 0.0.0.0)
  2. Simulated DHCP via controller REST API (assigns 10.0.0.X + 172.16.0.X)
  3. Start Topology Agent (port 8888) — executes shell commands in host namespaces
  4. Start Host Agents (port 8080 per host namespace)
  5. ARP + flow warm-up (prevents cold-start PacketIn storm on first pingall)
"""

import requests
import time
import json
import argparse
import threading
import sys
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink

CONTROLLER_API = "http://127.0.0.1:8000"
TOPO_AGENT_PORT = 8888


class ZoneTopology(Topo):
    def build(self, hosts=6, **kwargs):
        s = self.addSwitch('s1', protocols='OpenFlow13')
        for i in range(1, hosts + 1):
            h = self.addHost(f'h{i}', ip='0.0.0.0/24')
            self.addLink(h, s)


# ---------------------------------------------------------------------------
# Topology Agent (command executor for Web UI)
# ---------------------------------------------------------------------------
def start_topology_agent(net):
    """
    HTTP server on port 8888.
    Accepts POST /exec {host, cmd} and runs cmd inside host's Mininet namespace.
    Used by the Web UI and controller REST handler for real ping/curl commands.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class AgentHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            if self.path != '/exec':
                self.send_error(404); return
            length    = int(self.headers.get('Content-Length', 0))
            data      = json.loads(self.rfile.read(length).decode())
            host_name = data.get('host')
            cmd       = data.get('cmd')
            if not host_name or not cmd:
                self.send_error(400, "Missing host or cmd"); return
            host_obj = net.get(host_name)
            if not host_obj:
                self.send_error(404, f"Host {host_name} not found"); return
            print(f"[Agent] {host_name}: {cmd[:80]}")
            try:
                output = host_obj.cmd(cmd)
            except Exception as e:
                output = f"ERROR: {e}"
            body = json.dumps({'output': output, 'status': 'success'}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(('0.0.0.0', TOPO_AGENT_PORT), AgentHandler)
    print(f"[*] Topology Agent listening on 0.0.0.0:{TOPO_AGENT_PORT}")
    server.serve_forever()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', type=int, default=6,
                        help='Number of hosts (default: 6)')
    args = parser.parse_args()

    topo = ZoneTopology(hosts=args.topo)
    net  = Mininet(topo=topo,
                   controller=RemoteController,
                   switch=OVSSwitch,
                   link=TCLink,
                   autoSetMacs=True)
    net.start()

    print("\n[*] Mininet started. All hosts at 0.0.0.0.")
    print("[*] Waiting for Ryu controller connection (2 s)...")
    time.sleep(2)

    # -------------------------------------------------------------------------
    # Phase 1: Simulated DHCP
    # -------------------------------------------------------------------------
    print("\n>>> DHCP DISCOVERY PHASE <<<")
    for h in net.hosts:
        print(f"  [DHCP] {h.name} ({h.MAC()}) discovering...")
        success = False
        try:
            r = requests.post(f"{CONTROLLER_API}/sim/dhcp_discover",
                              json={'hostname': h.name, 'mac': h.MAC()},
                              timeout=4)
            if r.status_code == 200:
                assigned = r.json().get('ip')
                h.setIP(assigned, prefixLen=24)
                print(f"         ACK: {assigned}/24 -> {h.name}")
                success = True
        except Exception as e:
            print(f"         ERROR: {e}")

        if not success:
            # Fallback: assign sequential IP so Mininet stays operational
            fallback = f"10.0.0.{10 + int(h.name[1:])}"
            print(f"         FALLBACK: {fallback}")
            h.setIP(fallback, prefixLen=24)

        # Routes: default gateway + explicit public-subnet route
        h.cmd('ip route add default via 10.0.0.254 2>/dev/null; true')
        h.cmd('ip route add 172.16.0.0/16 via 10.0.0.254 2>/dev/null; true')

    print(">>> DHCP PHASE COMPLETE <<<\n")

    # -------------------------------------------------------------------------
    # Phase 2: Topology Agent
    # -------------------------------------------------------------------------
    threading.Thread(target=start_topology_agent, args=(net,), daemon=True).start()
    time.sleep(0.5)

    # -------------------------------------------------------------------------
    # Phase 3: Host Agents (one per namespace)
    # -------------------------------------------------------------------------
    print(">>> STARTING HOST AGENTS <<<")
    for h in net.hosts:
        cmd = (f"python3 scripts/host_agent.py --host {h.name} --server "
               f"> /tmp/{h.name}_agent.log 2>&1 &")
        h.cmd(cmd)
        print(f"  [Agent] {h.name}: server started (log: /tmp/{h.name}_agent.log)")
    time.sleep(1)   # Let agents bind their sockets

    print("\n✅ SIMULATION RUNNING")
    print(f"   Controller API  : {CONTROLLER_API}")
    print(f"   Topology Agent  : http://127.0.0.1:{TOPO_AGENT_PORT}")
    print("   Host Agents     : :8080 inside each host namespace\n")

    # -------------------------------------------------------------------------
    # Phase 4: Warm-up (ARP + flow table pre-population)
    # -------------------------------------------------------------------------
    # Step A: Disable NIC offloading on all host interfaces.
    #         Virtual NICs in Mininet can corrupt TCP/UDP checksums unless
    #         offloading (TSO, GSO, GRO, LRO) is disabled.
    print(">>> WARM-UP: disabling NIC offloading...")
    for h in net.hosts:
        intf = h.defaultIntf()
        h.cmd(f"ethtool -K {intf} tx off rx off tso off gso off gro off lro off "
              f"> /dev/null 2>&1; true")

    # Step B: Each host ARPs for the gateway (10.0.0.254).
    #         This triggers a PacketIn → controller proxy-ARP reply → OVS learns
    #         each host's port. This is the CRITICAL step that causes deferred NAT
    #         flows to be installed with the correct port number.
    print(">>> WARM-UP: ARP requests to gateway (triggers port learning)...")
    for h in net.hosts:
        h.cmd(f"arping -c 2 -I {h.defaultIntf()} 10.0.0.254 > /dev/null 2>&1 &")
    time.sleep(3)   # Give the controller time to process all PacketIns and install flows

    # Step C: Pre-populate bidirectional IP flows in Table 1 by pinging every pair.
    #         After this pass, 'pingall' will have 0% loss because all flows are
    #         already installed in OVS — no controller round-trip needed.
    print(">>> WARM-UP: pre-populating Table 1 IP flows (one ping per pair)...")
    hosts = net.hosts
    for src in hosts:
        for dst in hosts:
            if src.name != dst.name:
                dst_ip = dst.IP()
                if dst_ip and dst_ip != '0.0.0.0':
                    src.cmd(f"ping -c 1 -W 1 {dst_ip} > /dev/null 2>&1")
    time.sleep(1)

    print("\n>>> WARM-UP COMPLETE <<<")
    print("    Run 'pingall' — expected result: 0% packet loss\n")

    # -------------------------------------------------------------------------
    # Interactive or headless mode
    # -------------------------------------------------------------------------
    if sys.stdin.isatty():
        CLI(net)
    else:
        print("[*] Headless mode — network will remain active until Ctrl-C.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    net.stop()


if __name__ == '__main__':
    main()
