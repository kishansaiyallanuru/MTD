# Quick Test - See Packet Acknowledgments

## 30-Second Test

```bash
# Terminal 1: Start controller
sudo docker run --rm -it --network host --name mtd-controller mtd-controller

# Terminal 2: Start Mininet
sudo python3 mininet_topo.py

# Terminal 3: Watch h2 receive packets
tail -f /tmp/h2_agent.log

# Terminal 2 (in Mininet CLI): Send one packet
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 1
```

**You'll see in Terminal 3 (receiver):**
```
======================================================================
[HH:MM:SS] [h2] SUCCESS: 📥 PACKET RECEIVED
[HH:MM:SS] [h2] SUCCESS:    From: h1 (172.16.0.21)
[HH:MM:SS] [h2] SUCCESS:    Size: 234 bytes
[HH:MM:SS] [h2] SUCCESS:    Data: Test message #1 from h1 to h2...
======================================================================
[HH:MM:SS] [h2] INFO: ✅ ACK sent to h1
```

**You'll see in Terminal 2 (sender):**
```
======================================================================
[HH:MM:SS] [h1] INFO: 📤 SENDING PACKET
[HH:MM:SS] [h1] INFO:    To: h2 (172.16.0.198:8080)
======================================================================
[HH:MM:SS] [h1] SUCCESS: ✅ ACKNOWLEDGMENT RECEIVED
[HH:MM:SS] [h1] SUCCESS:    Status: ACK
[HH:MM:SS] [h1] SUCCESS:    Bytes delivered: 234
======================================================================
```

## Via Controller API

```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h1","dst":"h2","payload":"Test message"}' | jq
```

Look for these steps in the trace:
- ✅ `"step": "POLICY"` - Access granted
- ✅ `"step": "TRANSFER"` - Packet sent from h1 to h2
- ✅ `"step": "DELIVERY"` - Packet received by h2
- ✅ `"step": "ACK"` - Acknowledgment received
- ✅ `"step": "RESULT"` - Communication successful

## Continuous Stream Test

```bash
# Terminal 3: Monitor receiver
tail -f /tmp/h2_agent.log

# Mininet: Send 10 packets, one every 2 seconds
mininet> h1 python3 scripts/host_agent.py --host h1 --client --target h2 --count 10 --interval 2
```

Watch packets arrive in real-time with acknowledgments!

## Troubleshooting

**Problem:** No output in /tmp/h2_agent.log

**Solution:**
```bash
# Check if agent is running
mininet> h2 ps aux | grep host_agent

# If not, start it manually
mininet> h2 python3 scripts/host_agent.py --host h2 --server > /tmp/h2_agent.log 2>&1 &
```

**Problem:** Connection refused

**Solution:**
```bash
# Test connectivity first
mininet> h1 curl http://10.0.0.2:8080
# Should return: {"status": "ok", "host": "h2", ...}
```

## What's Different Now?

**Before:** Only saw policy checks, no actual transfer confirmation
**Now:** See complete flow with sender/receiver acknowledgments

✅ Sender knows packet was delivered (gets ACK)
✅ Receiver confirms packet arrival
✅ Both show source, dest, size, and data preview
✅ Logs show actual transfer, not just checks
