import requests
import json
import random

BASE_URL = "http://localhost:8000/api/v1"

def login(username, password, fingerprint):
    # Enforce unique session identity
    res = requests.post(f"{BASE_URL}/auth/login", json={
        "username": username,
        "password": password,
        "fingerprint": fingerprint
    })
    data = res.json()
    if data.get("status") == "MFA_REQUIRED":
        otp = data["demo_otp_hint"]
        res = requests.post(f"{BASE_URL}/auth/mfa/verify", json={
            "username": username,
            "otp": otp,
            "fingerprint": fingerprint
        })
        return res.json()["access_token"]
    if "access_token" not in data:
        raise Exception(f"Login Failed: {data}")
    return data["access_token"]

def check_threats(token, fingerprint):
    res = requests.get(f"{BASE_URL}/admin/threats", headers={
        "Authorization": f"Bearer {token}",
        "X-Device-Fingerprint": fingerprint
    })
    data = res.json()
    if not isinstance(data, list):
        print(f"DEBUG: Non-list response: {data}")
        return []
    return data

def generate_anomaly(token, to_acc, amount, fingerprint):
    print(f"Generating 6 rapid transfers to {to_acc}...")
    for _ in range(6):
        requests.post(f"{BASE_URL}/banking/transfer", json={
            "to_account_number": to_acc,
            "amount": amount,
            "idempotency_key": f"key_{random.randint(1000, 9999999)}"
        }, headers={
            "Authorization": f"Bearer {token}",
            "X-Device-Fingerprint": fingerprint
        })

if __name__ == "__main__":
    try:
        print("--- Initiating Tiered Anomaly Generation ---")
        
        # Branch 1 Anomaly (customer_3)
        c3_token = login("customer_3", "password123", "fp-cust3")
        generate_anomaly(c3_token, "ACC_CUSTOMER_4", 1000, "fp-cust3")
        
        # Branch 2 Anomaly (customer_1)
        c1_token = login("customer_1", "password123", "fp-cust1")
        generate_anomaly(c1_token, "ACC_CUSTOMER_4", 2000, "fp-cust1")
        
        print("\n--- Verifying Scoped Visibility ---")
        
        # 1. Branch 1 Head (Should see only Branch 1)
        br1_token = login("branch_1", "password123", "fp-br1")
        br1_threats = check_threats(br1_token, "fp-br1")
        print(f"Branch 1 Head (BR-001) saw {len(br1_threats)} threats.")
        for t in br1_threats: print(f"  - {t['message']} (User: {t['user']})")
        
        # 2. Regional North Head (Should see BR-001 and BR-002)
        reg_n_token = login("regional_north", "password123", "fp-regn")
        reg_n_threats = check_threats(reg_n_token, "fp-regn")
        print(f"Regional North Head saw {len(reg_n_threats)} threats.")
        
        # 3. Super Admin (Global View)
        admin_token = login("admin", "password123", "fp-admin")
        admin_threats = check_threats(admin_token, "fp-admin")
        print(f"Super Admin saw {len(admin_threats)} total threats.")
        
        print("\nVerification Completed.")
        
    except Exception as e:
        print(f"Verification Failed: {e}")
