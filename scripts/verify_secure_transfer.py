import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_secure_transfer():
    print("[*] Testing Secure Transfer API...")
    payload = {
        "src": "h1",
        "dst": "h2",
        "payload": "Test Secret Data"
    }
    
    try:
        res = requests.post(f"{BASE_URL}/sim/secure_transfer", json=payload, timeout=5)
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(json.dumps(data, indent=2))
            
            # Assertions
            if data.get('status') == 'success':
                print("✅ Secure Transfer Successful")
                print(f"Cipher: {data.get('cipher_suite')}")
                print(f"Encrypted Preview: {data.get('encrypted_preview')}")
            else:
                print("❌ Secure Transfer Blocked/Failed")
        else:
            print("❌ API Error")
            print(res.text)
            
    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    test_secure_transfer()
