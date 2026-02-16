# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Moving Target Defense (MTD)** system for hospital networks, implementing dynamic IP rotation to reduce attack surface. The system uses Software-Defined Networking (SDN) with a Ryu controller and Mininet for network simulation.

**Core Concept**: Internal hosts use static private IPs (10.0.0.x) that are never exposed. The MTD controller dynamically rotates their public-facing IPs (172.16.0.x) at different intervals based on risk zones, making reconnaissance difficult while maintaining service continuity.

## Architecture

### Three-Layer Design

1. **Control Plane** (`mtd_controller.py`)
   - Ryu SDN controller (OpenFlow 1.3)
   - Manages DHCP/DNS, NAT mappings, flow tables, and policy enforcement
   - REST API on port 8000 for external control
   - SQLite database (`mtd_state.db`) for state persistence
   - Handles ARP, ICMP, and packet forwarding decisions

2. **Data Plane** (`mininet_topo.py`)
   - Virtual network topology with hosts (h1-h6) and OpenFlow switches
   - Topology agent on port 8888 for executing commands on virtual hosts
   - Hosts boot with 0.0.0.0 and request IPs via simulated DHCP

3. **MTD Engine** (`zone_scheduler.py`)
   - Orchestrates zone-based IP rotation
   - High zone (h1, h2): 40s interval
   - Medium zone (h3, h4): 20s interval
   - Low zone (h5, h6): 10s interval

### Key Architectural Patterns

**NAT Flow Management**: When a host's public IP rotates, the controller:
1. Selects a new IP from the pool (172.16.0.50-99)
2. Updates `nat_table` (private_ip → public_ip mapping)
3. Installs new OpenFlow rules with `OFPActionSetField` for IP rewriting
4. Maintains old rules briefly ("shadow period") to prevent dropped packets
5. Updates DNS records so other hosts resolve to the new IP

**Policy Enforcement** (`policies.yml`):
- Zone assignments determine rotation frequency and access privileges
- ACL rules evaluated sequentially (high→ALL allowed, medium→low allowed, low→ALL denied)
- Policy checks happen before flow installation

**State Persistence**:
- All NAT mappings, DNS records, and shuffle history stored in SQLite
- Controller recovers state after restart
- Logs maintain audit trail of all IP rotations

## Development Commands

### Environment Setup

**Linux (Ubuntu 20.04+) required** - Mininet and Ryu require root privileges:

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3.10-venv dnsmasq isc-dhcp-server nmap

# Install Python dependencies
pip3 install -r requirements.txt

# Note: If Ryu installation fails with setuptools error:
sudo pip3 install "setuptools<70" --break-system-packages
```

### Running the System

The system requires a **two-terminal setup**:

**Terminal 1 - Start Controller (Docker):**
```bash
# Build image
sudo docker build -t mtd-controller .

# Run controller (blocks terminal)
sudo docker run --rm -it --network host --name mtd-controller mtd-controller
```

**Terminal 2 - Start Mininet:**
```bash
# Start network with N hosts (default 6)
sudo python3 mininet_topo.py --topo 6

# In Mininet CLI, verify connectivity:
mininet> pingall

# Access host shell:
mininet> h1 ifconfig

# Execute commands on specific hosts:
mininet> h1 ping -c 1 h2
```

**Terminal 3 (Optional) - Start Zone Scheduler:**
```bash
python3 zone_scheduler.py
```

### API Endpoints

Controller REST API (http://127.0.0.1:8000):

- `GET /status` - View all hosts, NAT mappings, and active flows
- `GET /logs` - Retrieve shuffle history and events
- `GET /dns?q=h2` - Resolve hostname to current public IP
- `POST /shuffle` - Manually trigger IP rotation for specific hosts
- `POST /sim/dhcp_discover` - Simulate DHCP discovery (used by topology script)
- `POST /send` - Simulate secure data transfer between hosts (triggers policy check, encryption, NAT)

Topology Agent API (http://127.0.0.1:8888):

- `POST /exec` - Execute shell commands on virtual hosts: `{"host": "h1", "cmd": "ping -c 1 10.0.0.2"}`

### Testing and Verification

```bash
# Run all verification tests
sudo python3 verify_all.py

# Check zone configurations
python3 verify_zones.py

# Manual connectivity tests (from Mininet CLI):
mininet> h1 ping h2
mininet> h3 curl http://10.0.0.1:8080
```

## Code Structure Guidelines

### When Modifying mtd_controller.py

- **Packet handlers** use `@set_ev_cls` decorators with specific event types
- **OpenFlow actions** must specify `ofproto` and `parser` from datapath
- **Flow modifications** require deleting old flows before installing new ones to avoid conflicts
- **Thread safety**: Use `self.lock` when accessing shared state (`host_map`, `nat_table`)
- **Database operations**: Always commit after INSERT/UPDATE and handle connection in try/finally

### When Modifying Flow Installation

Flow rules have priority hierarchy (higher = more specific):
- Priority 1000: ARP handling
- Priority 500: ICMP (ping) rules
- Priority 100: NAT translation rules (per-host)
- Priority 1: Default drop/forward

Example NAT flow pattern:
```python
# Outbound: Replace private src IP with public IP
match = parser.OFPMatch(eth_type=0x0800, ipv4_src=private_ip)
actions = [parser.OFPActionSetField(ipv4_src=public_ip),
           parser.OFPActionOutput(out_port)]

# Inbound: Replace public dst IP with private IP
match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=public_ip)
actions = [parser.OFPActionSetField(ipv4_dst=private_ip),
           parser.OFPActionOutput(in_port)]
```

### When Adding New Zone Policies

1. Update `policies.yml` with zone assignment and ACL rules
2. Modify `zone_scheduler.py` to add zone with interval timing
3. Controller automatically loads policies on startup via `yaml.safe_load()`
4. ACL rule order matters - first match wins

### Database Schema

The `mtd_state.db` SQLite database contains:

- **hosts**: hostname, mac, private_ip, zone, last_seen
- **nat_mappings**: private_ip, public_ip, timestamp, active (current mappings)
- **shuffle_log**: id, host, old_ip, new_ip, timestamp, shuffle_id (audit trail)
- **dns_records**: hostname, public_ip, ttl, last_updated

Query patterns used frequently:
- Lookup public IP: `SELECT public_ip FROM nat_mappings WHERE private_ip=? AND active=1`
- Get zone: `SELECT zone FROM hosts WHERE hostname=?`
- Check policy: Load ACL from policies.yml and evaluate src_zone→dst_zone

## Common Pitfalls

1. **Forgetting root privileges**: Mininet and Ryu require `sudo`. Commands will fail silently without it.

2. **Port conflicts**: Controller (8000), Topology Agent (8888), and OpenFlow (6653) must be free. Check with `sudo netstat -tuln`.

3. **NetworkManager interference**: On some Linux distros, NetworkManager conflicts with dnsmasq. Disable: `sudo systemctl stop NetworkManager`

4. **Flow table conflicts**: When debugging flows, use `sudo ovs-ofctl dump-flows s1` to inspect. Clear with `sudo ovs-ofctl del-flows s1`.

5. **DHCP timing**: The `mininet_topo.py` script waits 2 seconds for controller connection. If hosts show 0.0.0.0, increase sleep time or manually assign IPs.

6. **Ryu eventlet version**: Ryu requires `eventlet==0.30.2`. Newer versions break. The Dockerfile pins this version.

7. **Mock mode**: If Ryu imports fail, controller runs in mock mode (no actual packet handling). Check logs for "WARNING: Ryu not found."

## Web Dashboard

If present in `web/` directory:
- Served by controller's HTTP server on port 8000
- Displays live NAT table, hopping history, and policy violations
- Uses AJAX polling to `/status` and `/logs` endpoints
- Provides "Operations Center" for triggering manual shuffles and data transfers

## Docker Notes

The Dockerfile pins critical dependencies:
- Python 3.8 (Ryu compatibility)
- setuptools==57.5.0 (avoid breaking changes)
- eventlet==0.30.2 (Ryu requirement)
- Uses `--network host` to allow Mininet (host) → Controller (container) communication

Controller logs to stdout (captured by Docker). View with `sudo docker logs mtd-controller`.

## Security Considerations

- SECRET key in `mtd_controller.py` is hardcoded for demo. Replace with environment variable in production.
- HTTPS simulation uses AES-256-GCM with random keys per session (not persistent).
- No actual TLS handshake - encryption shown is demonstrative.
- Zone policies are examples - real hospital networks require more granular rules.
