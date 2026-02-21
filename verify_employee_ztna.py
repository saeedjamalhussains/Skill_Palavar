import requests
import uuid

API_URL = "http://localhost:8000/api/v1"

def test_employee_ztna():
    print("Testing ZTNA for Employees...")
    
    # 1. Login as Branch Manager
    login_data = {
        "username": "branch",
        "password": "password123",
        "fingerprint": "office_desktop_1"
    }
    resp = requests.post(f"{API_URL}/auth/login", json=login_data)
    if resp.status_code != 200:
        print(f"Login failed: {resp.text}")
        return
    
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Try to fetch approvals with SAME fingerprint (Should ALLOW)
    headers["X-Device-Fingerprint"] = "office_desktop_1"
    resp = requests.get(f"{API_URL}/banking/approvals", headers=headers)
    print(f"Fetch approvals (Trusted Device): {resp.status_code} - Action: ALLOW")
    
    # 3. Try to fetch approvals with DIFFERENT fingerprint (Should trigger STEP_UP_MFA/DENY)
    # Risk for new device is 0.4. Medium threshold is 0.4.
    headers["X-Device-Fingerprint"] = "unknown_device_x"
    resp = requests.get(f"{API_URL}/banking/approvals", headers=headers)
    print(f"Fetch approvals (New Device): {resp.status_code} - Detail: {resp.json().get('detail')}")

if __name__ == "__main__":
    test_employee_ztna()
