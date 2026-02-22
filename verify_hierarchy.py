import requests

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

def get_dashboard(token):
    res = requests.get(f"{BASE_URL}/admin/dashboard", headers={
        "Authorization": f"Bearer {token}"
    })
    return res.json()

if __name__ == "__main__":
    try:
        print("--- Verifying Hierarchical Scoping ---")
        
        # 1. Branch Head (BR-001) should only see their branch
        print("\n[Testing Branch Head - BR-001]")
        token_br1 = login("branch_1", "password123", "fp-br1")
        dash_br1 = get_dashboard(token_br1)
        print(f"Total Users Visible: {dash_br1['total_users']}")
        # Expecting less than global count
        
        # 2. Regional Head (REG-NORTH) should see North branches (BR-001, BR-002)
        print("\n[Testing Regional Head - NORTH]")
        token_reg = login("regional_north", "password123", "fp-regn")
        dash_reg = get_dashboard(token_reg)
        print(f"Total Users Visible: {dash_reg['total_users']}")
        # Expecting more than single branch but less than global
        
        # 3. Super Admin should see everyone
        print("\n[Testing Super Admin]")
        token_admin = login("admin", "password123", "fp-admin")
        dash_admin = get_dashboard(token_admin)
        print(f"Total Users Visible: {dash_admin['total_users']}")
        
        print("\nVerification Results:")
        print(f"BR1 Visibility: {dash_br1['total_users']}")
        print(f"Regional Visibility: {dash_reg['total_users']}")
        print(f"Global Visibility: {dash_admin['total_users']}")
        
        if dash_br1['total_users'] < dash_reg['total_users'] < dash_admin['total_users']:
            print("\n✅ Hierarchical Scoping is WORKING correctly.")
        else:
            print("\n❌ Hierarchy Mismatch detected.")
            
    except Exception as e:
        print(f"Verification Failed: {e}")
