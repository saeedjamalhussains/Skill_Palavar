import requests, time, json

BASE = 'http://localhost:8000/api/v1'

def login(username):
    print(f"\n--- Login: {username} ---")
    r = requests.post(f'{BASE}/auth/login', json={'username':username,'password':'password123','fingerprint':'test_device_fp'})
    print(f"  Login response: {r.status_code} {r.json()}")
    data = r.json()
    
    if 'mfa_required' in data and data['mfa_required']:
        otp = data.get('demo_otp_hint','123456')
        print(f"  MFA required, using OTP: {otp}")
        mfa = requests.post(f'{BASE}/auth/mfa/verify', json={'username':username,'otp':otp,'fingerprint':'test_device_fp'})
        print(f"  MFA response: {mfa.status_code} {json.dumps(mfa.json(), indent=2)}")
        return {'Authorization': f'Bearer {mfa.json().get("access_token","")}', 'Content-Type': 'application/json', 'X-Device-Fingerprint': 'test_device_fp'}
    elif 'access_token' in data:
        return {'Authorization': f'Bearer {data["access_token"]}', 'Content-Type': 'application/json', 'X-Device-Fingerprint': 'test_device_fp'}
    else:
        print(f"  ERROR: No token received!")
        return {}

# Step 1: Login as customer_1
headers = login('customer_1')
if not headers.get('Authorization'):
    print("ABORT: Login failed!")
    exit()

# Step 2: Check accounts
print("\n--- Accounts ---")
accs = requests.get(f'{BASE}/banking/accounts', headers=headers)
print(f"  Status: {accs.status_code}")
print(f"  Response: {json.dumps(accs.json(), indent=2)}")

if accs.status_code == 200 and accs.json():
    balance_before = accs.json()[0]['balance']
    from_acc = accs.json()[0]['account_number']
    print(f"  Balance BEFORE: {balance_before}")
    print(f"  Account: {from_acc}")
else:
    print("  ERROR: Cannot fetch accounts")
    exit()

# Step 3: Attempt transfer
print("\n--- Transfer ---")
transfer_data = {
    'to_account_number': 'ACC_CUSTOMER_2',
    'amount': 1000,
    'idempotency_key': f'diag_{time.time()}'
}
print(f"  Sending: {json.dumps(transfer_data, indent=2)}")
tx = requests.post(f'{BASE}/banking/transfer', headers=headers, json=transfer_data)
print(f"  Status: {tx.status_code}")
print(f"  Response: {json.dumps(tx.json(), indent=2)}")

# Step 4: Re-check accounts
print("\n--- Accounts After Transfer ---")
accs2 = requests.get(f'{BASE}/banking/accounts', headers=headers)
print(f"  Status: {accs2.status_code}")
if accs2.status_code == 200 and accs2.json():
    balance_after = accs2.json()[0]['balance']
    print(f"  Balance AFTER: {balance_after}")
    print(f"  Difference: {balance_before - balance_after}")
else:
    print(f"  Response: {accs2.text}")

# Step 5: Check transaction history
print("\n--- Transaction History ---")
history = requests.get(f'{BASE}/banking/accounts', headers=headers)
print(f"  Full account data: {json.dumps(history.json(), indent=2)}")

print("\n=== DIAGNOSIS COMPLETE ===")
