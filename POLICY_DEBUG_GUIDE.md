# Policy Debug Guide - Zone Communication Issues

## Issue Reported

- ✅ High → Low: WORKING
- ❌ Low → Low: NOT WORKING
- ❌ Medium → Low: NOT WORKING

## Expected Behavior (Based on Code)

According to `check_connectivity_verbose()` in mtd_controller.py:

1. **Intra-zone communication** (line 1241-1243): Always allowed
   - Low → Low: Should work
   - Medium → Medium: Should work
   - High → High: Should work

2. **High zone** (line 1245-1247): Can access ALL
   - High → Low: Should work ✅ (confirmed working)
   - High → Medium: Should work
   - High → High: Should work

3. **Medium zone** (line 1249-1254): Can access Medium and Low
   - Medium → Low: Should work
   - Medium → Medium: Should work
   - Medium → High: Should be BLOCKED

4. **Low zone** (line 1256-1261): Can only access Low
   - Low → Low: Should work
   - Low → Medium: Should be BLOCKED
   - Low → High: Should be BLOCKED

## Diagnostic Steps

### Step 1: Run Debug Script

```bash
python3 debug_policy.py
```

This script will:
1. Show zone assignments from policies.yml
2. Test policy logic locally (same as controller)
3. Test via controller API (actual runtime)
4. Compare local vs API results

**Look for discrepancies:**
- If local shows ALLOWED but API shows BLOCKED → runtime issue
- If both show BLOCKED → policy logic issue

### Step 2: Check Controller Logs

The controller now has DEBUG logging for every policy check:

```bash
# View controller logs (if running in terminal)
# Look for lines like:
# DEBUG Policy Check: h5(low) -> h6(low)
# DEBUG   ✓ Intra-zone: low == low → ALLOW

# Or check controller.log file
grep "Policy Check" controller.log | tail -20
```

### Step 3: Manual API Tests

Test each combination manually:

**Low → Low (h5 → h6):**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h5","dst":"h6","payload":"Low to Low test"}' | jq '.status, .trace[] | select(.step == "POLICY")'
```

Expected: `"status": "success"` (not "blocked")

**Medium → Low (h3 → h5):**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h3","dst":"h5","payload":"Medium to Low test"}' | jq '.status, .trace[] | select(.step == "POLICY")'
```

Expected: `"status": "success"` (not "blocked")

**High → Low (h1 → h5):**
```bash
curl -X POST http://127.0.0.1:8000/sim/secure_transfer \
  -H "Content-Type: application/json" \
  -d '{"src":"h1","dst":"h5","payload":"High to Low test"}' | jq '.status, .trace[] | select(.step == "POLICY")'
```

Expected: `"status": "success"` ✅ (confirmed working)

### Step 4: Check Zone Assignment at Runtime

Query the controller to see what zones it thinks hosts are in:

```bash
# Get controller status
curl -s http://127.0.0.1:8000/status | jq '.host_map | to_entries[] | {host: .key, zone: .value.zone}'
```

Expected output:
```json
{"host": "h1", "zone": "high"}
{"host": "h2", "zone": "high"}
{"host": "h3", "zone": "medium"}
{"host": "h4", "zone": "medium"}
{"host": "h5", "zone": "low"}
{"host": "h6", "zone": "low"}
```

**If zones are missing or incorrect,** the issue is with how zones are assigned at runtime, not the policy logic.

## Possible Root Causes

### Cause 1: Hosts Not Registered

If hosts haven't sent DHCP requests yet, they won't be in `host_map` and zone detection may fail.

**Fix:**
```bash
# In Mininet CLI:
mininet> pingall

# This forces all hosts to communicate and register
```

### Cause 2: Zone Not Set in host_map

When hosts are registered, their zone might not be copied into `host_map`.

**Check:** Look at `simulate_dhcp_allocation()` function around line 1098. It should be setting the zone when creating the host entry.

**Verify:**
```bash
curl -s http://127.0.0.1:8000/status | jq '.host_map.h5'
# Should include: "zone": "low"
```

### Cause 3: Policy File Not Loaded

**Verify:**
```bash
# Check if policies.yml exists in the same directory as mtd_controller.py
ls -la policies.yml

# Check controller logs for policy loading
grep "Policies loaded" controller.log
# Should show: Policies loaded: ['periodic_shuffle', 'zones', 'acls']
```

### Cause 4: Old OpenFlow Rules

If you've been testing and there are old DROP rules installed:

**Fix:**
```bash
# Clear all flows on the switch
sudo ovs-ofctl del-flows s1

# Restart controller to reinstall correct rules
```

### Cause 5: Docker Network Isolation

If using Docker for the controller with `--network host`, ensure the controller can actually reach the Topology Agent on port 8888:

**Test:**
```bash
# From inside container or host
curl http://127.0.0.1:8888/test 2>&1

# Should NOT get "Connection refused"
```

## Code Logic Review

The `check_connectivity_verbose` function logic (lines 1230-1274):

```python
def check_connectivity_verbose(self, src_host, dst_host):
    src_zone = self.get_host_zone(src_host)  # Gets zone from policies['zones']
    dst_zone = self.get_host_zone(dst_host)

    # Step 1: Check intra-zone (line 1241-1243)
    if src_zone == dst_zone:
        return True, "Intra-zone communication allowed"
        # This should catch Low → Low and Medium → Medium

    # Step 2: Check if source is high (line 1245-1247)
    if src_zone == 'high':
        return True, "High integrity zone authorized"
        # This catches High → Low

    # Step 3: Check if source is medium (line 1249-1254)
    if src_zone == 'medium':
        if dst_zone == 'medium' or dst_zone == 'low':
            return True, "Medium zone authorized for Med/Low"
            # This should catch Medium → Low

    # Step 4: Check if source is low (line 1256-1261)
    if src_zone == 'low':
        if dst_zone == 'low':
            return True, "Low zone intra-zone allowed"
            # Redundant with Step 1, but explicit
        if dst_zone == 'medium' or dst_zone == 'high':
            return False, "Security Violation: Low cannot access Higher Zones"

    # Step 5: Fallback
    return False, "Implicit Deny"
```

**Analysis:**
- Low → Low: Should hit Step 1 (intra-zone) → ALLOW ✓
- Medium → Low: Should hit Step 3 (medium check) → ALLOW ✓
- High → Low: Should hit Step 2 (high can access all) → ALLOW ✓

The logic is correct! So the issue must be runtime-related.

## Temporary Workaround

If you need immediate functionality while debugging:

### Option 1: Modify policies.yml

Change the last ACL rule:

```yaml
# BEFORE:
acls:
  - {src: high, dst: ALL, action: allow}
  - {src: medium, dst: low, action: allow}
  - {src: medium, dst: high, action: deny}
  - {src: low, dst: ALL, action: deny}     # This blocks low → low!

# AFTER:
acls:
  - {src: high, dst: ALL, action: allow}
  - {src: medium, dst: low, action: allow}
  - {src: medium, dst: high, action: deny}
  - {src: low, dst: low, action: allow}    # Allow low → low explicitly
  - {src: low, dst: high, action: deny}    # Then deny low → high
  - {src: low, dst: medium, action: deny}  # And deny low → medium
```

**NOTE:** The code logic should already handle this correctly via the intra-zone check, so this shouldn't be necessary!

### Option 2: Disable Policy Checks Temporarily

For testing purposes only:

```python
# In check_connectivity_verbose(), add at the top:
def check_connectivity_verbose(self, src_host, dst_host):
    return True, "Policy checks temporarily disabled"  # DEBUG ONLY
```

## Expected Test Results

After running `debug_policy.py`:

```
LOCAL POLICY CHECKS:
h1 (high) → h5 (low)      : ✅ ALLOWED (High can access all)
h5 (low) → h6 (low)       : ✅ ALLOWED (Intra-zone)
h3 (medium) → h5 (low)    : ✅ ALLOWED (Medium can access low)
h3 (medium) → h1 (high)   : ❌ BLOCKED (Medium cannot access high)
h5 (low) → h1 (high)      : ❌ BLOCKED (Low cannot access higher)

CONTROLLER API CHECKS:
h1 → h5: status="success"
h5 → h6: status="success"   ← Should be success, not blocked!
h3 → h5: status="success"   ← Should be success, not blocked!
h3 → h1: status="blocked"
h5 → h1: status="blocked"
```

If API shows "blocked" where local shows "ALLOWED", there's a runtime issue.

## Next Steps

1. Run `python3 debug_policy.py` and share the output
2. Check controller logs for "Policy Check" debug lines
3. Verify zone assignments in `/status` endpoint
4. Check if hosts are registered (run `pingall` first)

The code logic is correct - this appears to be a runtime configuration or state issue.
