#!/usr/bin/env python3
"""
Debug script to test policy checks without running full transfer
"""
import requests
import json
import yaml

CONTROLLER = "http://127.0.0.1:8000"

def load_policies():
    """Load policies from policies.yml"""
    with open('policies.yml') as f:
        return yaml.safe_load(f)

def get_zone(policies, host):
    """Get zone for a host"""
    zones = policies.get('zones', {})
    return zones.get(host, zones.get('default', 'low'))

def check_policy_locally(policies, src, dst):
    """Check policy locally using same logic as controller"""
    src_zone = get_zone(policies, src)
    dst_zone = get_zone(policies, dst)

    print(f"\n{src} ({src_zone}) → {dst} ({dst_zone})")
    print("="*60)

    # Intra-zone always allowed
    if src_zone == dst_zone:
        print(f"✅ ALLOWED: Intra-zone communication ({src_zone})")
        return True

    # Explicit Matrix
    if src_zone == 'high':
        print(f"✅ ALLOWED: High zone can access all")
        return True

    if src_zone == 'medium':
        if dst_zone == 'medium' or dst_zone == 'low':
            print(f"✅ ALLOWED: Medium can access medium/low")
            return True
        if dst_zone == 'high':
            print(f"❌ BLOCKED: Medium cannot access high")
            return False

    if src_zone == 'low':
        if dst_zone == 'low':
            print(f"✅ ALLOWED: Low zone intra-zone")
            return True
        if dst_zone == 'medium' or dst_zone == 'high':
            print(f"❌ BLOCKED: Low cannot access higher zones")
            return False

    print(f"❌ BLOCKED: Implicit deny")
    return False

def test_via_api(src, dst):
    """Test via controller API"""
    print(f"\nTesting {src} → {dst} via API...")
    try:
        response = requests.post(
            f"{CONTROLLER}/sim/secure_transfer",
            json={"src": src, "dst": dst, "payload": "test"},
            timeout=10
        )
        data = response.json()
        status = data.get('status')

        # Find policy step in trace
        policy_steps = [t for t in data.get('trace', []) if t.get('step') == 'POLICY']

        print(f"API Response: {status}")
        for step in policy_steps:
            print(f"  {step.get('msg')}")

        return status
    except Exception as e:
        print(f"ERROR: {e}")
        return None

print("╔══════════════════════════════════════════════════════════════╗")
print("║            MTD Policy Debug Tool                             ║")
print("╚══════════════════════════════════════════════════════════════╝")

# Load policies
print("\nLoading policies from policies.yml...")
policies = load_policies()

print("\nZone Assignments:")
print("-" * 60)
zones = policies.get('zones', {})
for host, zone in sorted(zones.items()):
    if host != 'default':
        print(f"  {host}: {zone}")
print(f"  default: {zones.get('default', 'low')}")

print("\n\nACL Rules:")
print("-" * 60)
for i, rule in enumerate(policies.get('acls', []), 1):
    src = rule.get('src')
    dst = rule.get('dst')
    action = rule.get('action')
    print(f"  {i}. {src:8} → {dst:8} : {action}")

print("\n\n" + "="*60)
print("LOCAL POLICY CHECKS (using same logic as controller)")
print("="*60)

# Test cases
test_cases = [
    ("h1", "h5"),  # High → Low
    ("h5", "h6"),  # Low → Low
    ("h3", "h5"),  # Medium → Low
    ("h3", "h1"),  # Medium → High (should be blocked)
    ("h5", "h1"),  # Low → High (should be blocked)
]

print("\nRunning local checks...")
for src, dst in test_cases:
    check_policy_locally(policies, src, dst)

print("\n\n" + "="*60)
print("CONTROLLER API CHECKS (actual runtime behavior)")
print("="*60)
print("\nTesting via controller API...")
print("(Controller must be running on port 8000)")

for src, dst in test_cases:
    test_via_api(src, dst)
    print()

print("\n╔══════════════════════════════════════════════════════════════╗")
print("║  If local checks show ALLOWED but API shows BLOCKED,        ║")
print("║  there may be an issue with controller state or zone        ║")
print("║  detection at runtime.                                      ║")
print("╚══════════════════════════════════════════════════════════════╝")
