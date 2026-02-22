import requests, time, json

BASE = 'http://localhost:8000/api/v1'

def login(username):
    r = requests.post(f'{BASE}/auth/login', json={'username':username,'password':'password123','fingerprint':'test_fp_123'})
    data = r.json()
    if data.get('status') == 'MFA_REQUIRED':
        otp = data.get('demo_otp_hint','123456')
        mfa = requests.post(f'{BASE}/auth/mfa/verify', json={'username':username,'otp':otp,'fingerprint':'test_fp_123'})
        return {'Authorization': f'Bearer {mfa.json()["access_token"]}', 'Content-Type': 'application/json', 'X-Device-Fingerprint': 'test_fp_123'}
    return {'Authorization': f'Bearer {data["access_token"]}', 'Content-Type': 'application/json', 'X-Device-Fingerprint': 'test_fp_123'}

print('=== Full Transfer Test ===')
h = login('customer_1')

# Balance before
accs = requests.get(f'{BASE}/banking/accounts', headers=h).json()
print(f'Balance BEFORE: {accs[0]["balance"]}')

# Transfer
tx = requests.post(f'{BASE}/banking/transfer', headers=h, json={
    'to_account_number': 'ACC_CUSTOMER_2', 'amount': 2500, 'idempotency_key': f'fix_test_{time.time()}'
})
print(f'Transfer status: {tx.status_code}')
print(f'Transfer response: {json.dumps(tx.json(), indent=2)}')

# Balance after
accs2 = requests.get(f'{BASE}/banking/accounts', headers=h).json()
print(f'Balance AFTER: {accs2[0]["balance"]}')
print(f'Deducted: {accs[0]["balance"] - accs2[0]["balance"]}')

# Transaction history
txs = requests.get(f'{BASE}/banking/transactions', headers=h)
print(f'\nTransaction history: {txs.status_code}')
for t in txs.json()[:3]:
    print(f'  [{t["status"]}] {"DEBIT" if t.get("is_debit") else "CREDIT"}: {t["amount"]} -> {t["to_account_number"]}')

print('\n=== DONE ===')
