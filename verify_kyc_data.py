import requests
import json

BASE_URL = "http://localhost:8000/api/v1"

def login(username, password, fingerprint):
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
    return data["access_token"]

def check_me(token):
    res = requests.get(f"{BASE_URL}/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    return res.json()

if __name__ == "__main__":
    try:
        print("--- Verifying KYC Data Integration ---")
        
        # 1. Login as customer_1
        token = login("customer_1", "password123", "fp-cust1")
        me_data = check_me(token)
        
        print(f"Customer profile retrieved for: {me_data['username']}")
        
        fields = ["phone_number", "address", "pan_number", "date_of_birth", "kyc_status"]
        missing = [f for f in fields if f not in me_data or not me_data[f]]
        
        if not missing:
            print("✅ All KYC fields are present in /auth/me")
            for f in fields:
                print(f"  - {f}: {me_data[f]}")
        else:
            print(f"❌ Missing KYC fields: {missing}")
            
        print("\nVerification Completed.")
        
    except Exception as e:
        print(f"Verification Failed: {e}")
