# MTD Packet Transfer with Acknowledgments

This guide explains how to see actual packet transfers between hosts with visible acknowledgments in the terminal.

## Overview

The MTD system now provides clear visual feedback for packet transfers:
- **Sender side**: Shows packet being sent and acknowledgment received
- **Receiver side**: Shows packet received and ACK sent back
- **Controller**: Shows complete trace with all steps

## Quick Start

### 1. Start the System

**Terminal 1 - Controller:**
```bash
sudo docker run --rm -it --network host --name mtd-controller mtd-controller
```

**Terminal 2 - Mininet:**
```bash
sudo python3 mininet_topo.py
```

Host agents automatically start on each host (h1-h6) listening on port 8080.

### 2. Basic Packet Transfer Test

**View receiver logs (Terminal 3):**
```bash
# Outside Mininet, monitor h2's log file
tail -f /tmp/h2_agent.log
```

**Send packet (In Mininet CLI):**
```bash
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 1
```

**Expected Output on h1 (sender):**
```
======================================================================
[12:34:56] [h1] INFO: 📤 SENDING PACKET
[12:34:56] [h1] INFO:    To: h2 (172.16.0.198:8080)
[12:34:56] [h1] INFO:    Message ID: #1
[12:34:56] [h1] INFO:    Payload: Test message #1 from h1 to h2...
======================================================================

======================================================================
[12:34:56] [h1] SUCCESS: ✅ ACKNOWLEDGMENT RECEIVED
[12:34:56] [h1] SUCCESS:    From: h2 (172.16.0.198)
[12:34:56] [h1] SUCCESS:    Status: ACK
[12:34:56] [h1] SUCCESS:    Message: Packet received and acknowledged
[12:34:56] [h1] SUCCESS:    Bytes delivered: 234
======================================================================
```

**Expected Output on h2 (receiver):**
```
======================================================================
[12:34:56] [h2] SUCCESS: 📥 PACKET RECEIVED
[12:34:56] [h2] SUCCESS:    From: h1 (172.16.0.21)
[12:34:56] [h2] SUCCESS:    Size: 234 bytes
[12:34:56] [h2] SUCCESS:    Data: Test message #1 from h1 to h2...
======================================================================

[12:34:56] [h2] INFO: ✅ ACK sent to h1
```

## Test Scenarios

### Scenario 1: Direct Host Communication

Watch packets flow between hosts in real-time.

**Terminal 3 - Monitor receiver:**
```bash
tail -f /tmp/h2_agent.log
```

**Terminal 4 - Monitor sender:**
```bash
tail -f /tmp/h1_agent.log
```

**Mininet CLI - Send packets:**
```bash
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 5 --interval 2
```

### Scenario 2: Controller-Orchestrated Transfer

Use the controller API to orchestrate transfers with full security policy checks.

**Command:**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h1","dst":"h2","payload":"Secure message with encryption"}' \
  | jq
```

**Response shows complete trace:**
```json
{
  "status": "success",
  "trace": [
    {
      "step": "POLICY",
      "msg": "Access GRANTED: Rule Match Found",
      "status": "success"
    },
    {
      "step": "NET",
      "msg": "✅ Connectivity Established",
      "status": "success"
    },
    {
      "step": "CRYPTO",
      "msg": "Payload Encrypted (AES-256)",
      "status": "success"
    },
    {
      "step": "NAT",
      "msg": "Outbound Mapping: 10.0.0.110 -> 172.16.0.21",
      "status": "info"
    },
    {
      "step": "APP",
      "msg": "📤 Initiating Packet Transfer to h2...",
      "status": "info"
    },
    {
      "step": "TRANSFER",
      "msg": "📤 Packet sent from h1 to h2",
      "status": "success"
    },
    {
      "step": "DELIVERY",
      "msg": "📥 Packet received by h2",
      "status": "success"
    },
    {
      "step": "ACK",
      "msg": "✅ Acknowledgment: Packet received and acknowledged",
      "status": "success"
    },
    {
      "step": "RESULT",
      "msg": "Communication Successful",
      "status": "success"
    }
  ]
}
```

### Scenario 3: MTD with Active Transfers

Demonstrate IP rotation while packets are being transferred.

**Terminal 3 - Start continuous transfer:**
```bash
# In Mininet CLI
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 20 --interval 3
```

**Terminal 4 - Monitor h2 receiving:**
```bash
tail -f /tmp/h2_agent.log
```

**Terminal 5 - Trigger MTD shuffle during transfer:**
```bash
# Wait 10 seconds, then trigger shuffle
sleep 10
curl -X POST http://127.0.0.1:8000/shuffle \
  -H "Content-Type: application/json" \
  -d '{"hosts":["h1","h2"]}'
```

**Observation:**
- Packets continue flowing despite IP changes
- DNS resolution happens automatically
- Acknowledgments continue without interruption
- Demonstrates session persistence through MTD

### Scenario 4: Zone-Based Communication

Test different zone policies.

**Allowed: High → High**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h1","dst":"h2","payload":"High to high communication"}'
```
✅ Expected: Success with full trace

**Allowed: Medium → Low**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h3","dst":"h5","payload":"Medium to low communication"}'
```
✅ Expected: Success

**Blocked: Medium → High**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h3","dst":"h1","payload":"Unauthorized access attempt"}'
```
❌ Expected: Blocked with security violation message

**Blocked: Low → High**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h5","dst":"h1","payload":"Unauthorized access attempt"}'
```
❌ Expected: Blocked

## Monitoring Options

### View All Host Logs Simultaneously

```bash
# In multiple terminals:
tail -f /tmp/h1_agent.log   # Terminal 3
tail -f /tmp/h2_agent.log   # Terminal 4
tail -f /tmp/h3_agent.log   # Terminal 5
```

Or use a single terminal with `multitail`:
```bash
multitail /tmp/h1_agent.log /tmp/h2_agent.log /tmp/h3_agent.log
```

### Check Host Agent Status

```bash
# In Mininet CLI
mininet> h1 ps aux | grep host_agent
mininet> h2 ps aux | grep host_agent
```

### Verify Port Listening

```bash
# In Mininet CLI
mininet> h1 netstat -tulpn | grep 8080
mininet> h2 netstat -tulpn | grep 8080
```

### Test Direct Connectivity

```bash
# In Mininet CLI
mininet> h1 curl http://10.0.0.2:8080
# Should return: {"status": "ok", "host": "h2", ...}
```

## Understanding the Output

### Sender Output Format
```
======================================================================
[HH:MM:SS] [h1] INFO: 📤 SENDING PACKET
[HH:MM:SS] [h1] INFO:    To: h2 (172.16.0.198:8080)
[HH:MM:SS] [h1] INFO:    Message ID: #N
[HH:MM:SS] [h1] INFO:    Payload: <first 50 chars>...
======================================================================

[HH:MM:SS] [h1] INFO: 🔍 Resolving h2...
[HH:MM:SS] [h1] INFO: ✓ Resolved h2 -> 172.16.0.198

======================================================================
[HH:MM:SS] [h1] SUCCESS: ✅ ACKNOWLEDGMENT RECEIVED
[HH:MM:SS] [h1] SUCCESS:    From: h2 (172.16.0.198)
[HH:MM:SS] [h1] SUCCESS:    Status: ACK
[HH:MM:SS] [h1] SUCCESS:    Message: Packet received and acknowledged
[HH:MM:SS] [h1] SUCCESS:    Bytes delivered: <bytes>
======================================================================
```

### Receiver Output Format
```
======================================================================
[HH:MM:SS] [h2] SUCCESS: 📥 PACKET RECEIVED
[HH:MM:SS] [h2] SUCCESS:    From: h1 (172.16.0.21)
[HH:MM:SS] [h2] SUCCESS:    Size: <bytes> bytes
[HH:MM:SS] [h2] SUCCESS:    Data: <first 50 chars>...
======================================================================

[HH:MM:SS] [h2] INFO: ✅ ACK sent to h1
```

### Controller Trace Steps

| Step | Description | Status |
|------|-------------|--------|
| POLICY | Zone-based access control check | success/error |
| NET | Network connectivity verification (ping) | success/error |
| CRYPTO | Payload encryption (AES-256-GCM) | success |
| NAT | IP address translation (private→public) | info |
| APP | Application layer transfer initiation | info |
| TRANSFER | Packet sent from source | success |
| DELIVERY | Packet received by destination | success |
| ACK | Acknowledgment from receiver | success |
| RESULT | Final communication status | success/error |

## Troubleshooting

### No Acknowledgment Received

**Symptom:** Sender shows "Connection refused" or timeout

**Check:**
```bash
# Verify host agent is running on destination
mininet> h2 ps aux | grep host_agent

# Check logs for errors
cat /tmp/h2_agent.log

# Test direct connectivity
mininet> h1 curl http://10.0.0.2:8080
```

**Fix:**
```bash
# Restart host agent if needed
mininet> h2 killall python3
mininet> h2 python3 scripts/host_agent.py --host h2 --server > /tmp/h2_agent.log 2>&1 &
```

### DNS Resolution Fails

**Symptom:** "DNS resolution failed for h2"

**Check:**
```bash
# Test controller API
curl http://127.0.0.1:8000/dns?q=h2
```

**Fix:** Ensure controller is running and host is registered

### Policy Blocking

**Symptom:** "Security Violation" in trace

**Check:** Review zone assignments in `policies.yml`
```bash
cat policies.yml
```

**Zones:**
- h1, h2: high
- h3, h4: medium
- h5, h6: low

**Rules:**
- high → ALL (allowed)
- medium → low, medium (allowed)
- medium → high (blocked)
- low → ALL except low (blocked)

## Advanced Usage

### Custom Payload

```bash
mininet> h1 python3 -c "
import requests, json
payload = {
    'source': 'h1',
    'destination': 'h2',
    'data': 'Custom encrypted payload',
    'timestamp': $(date +%s)
}
response = requests.post('http://172.16.0.198:8080', json=payload)
print(response.json())
"
```

### Batch Testing

```bash
# Send 100 packets and measure success rate
for i in {1..100}; do
  curl -s -X POST http://127.0.0.1:8000/sim/secure_transfer \
    -H "Content-Type: application/json" \
    -d "{\"src\":\"h1\",\"dst\":\"h2\",\"payload\":\"Test $i\"}" \
    | jq -r '.status'
done | sort | uniq -c
```

### Performance Testing

```bash
# High-frequency packet stream
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 1000 --interval 0.1
```

## Summary

The enhanced packet transfer system provides:

✅ **Visible sender feedback**: Shows packet being sent and ACK received
✅ **Visible receiver feedback**: Shows packet received and ACK sent
✅ **Complete trace**: Full path from policy check to acknowledgment
✅ **Real-time monitoring**: Live logs show actual transfers
✅ **MTD demonstration**: Packets continue through IP rotations
✅ **Security validation**: Zone policies enforced with clear feedback

All logs are written to `/tmp/h*_agent.log` for persistent review.
