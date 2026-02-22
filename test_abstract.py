import requests, time

BASE = 'http://localhost:8000/api/v1'

def login(username):
    r = requests.post(f'{BASE}/auth/login', json={'username':username,'password':'password123','fingerprint':'testfp'})
    otp = r.json().get('demo_otp_hint','')
    mfa = requests.post(f'{BASE}/auth/mfa/verify', json={'username':username,'otp':otp,'fingerprint':'testfp'})
    return {'Authorization': f'Bearer {mfa.json().get("access_token","")}', 'Content-Type': 'application/json', 'X-Device-Fingerprint': 'testfp'}

# TEST 3: Defreeze workflow
print('=== TEST 3: Defreeze Workflow ===')
h_branch = login('branch_north_1')
freeze = requests.post(f'{BASE}/admin/account/5/status', headers=h_branch, json={'status_update':'FROZEN'})
print(f'  Freeze account 5: {freeze.status_code} - {freeze.text}')

defreeze_req = requests.post(f'{BASE}/admin/defreeze-request/5', headers=h_branch)
print(f'  Defreeze request: {defreeze_req.status_code} - {defreeze_req.text}')

h_reg = login('regional_north')
defreeze_list = requests.get(f'{BASE}/admin/defreeze-requests', headers=h_reg)
pending = defreeze_list.json()
print(f'  Pending defreeze list: {defreeze_list.status_code} count={len(pending)}')
if pending:
    req_id = pending[0]['id']
    approve = requests.post(f'{BASE}/admin/defreeze-approve/{req_id}', headers=h_reg)
    print(f'  Approve defreeze: {approve.status_code} - {approve.text}')

# TEST 4: Velocity anomaly
print()
print('=== TEST 4: Velocity Anomaly ===')
h_cust = login('customer_5')
for i in range(6):
    r = requests.post(f'{BASE}/banking/transfer', headers=h_cust, json={
        'to_account_number':'ACC_CUSTOMER_6', 'amount':100, 'idempotency_key':f'vel_{time.time()}_{i}'
    })
    print(f'  Rapid tx {i+1}: {r.status_code}')
    time.sleep(0.1)

h_admin = login('admin')
alerts = requests.get(f'{BASE}/admin/alerts', headers=h_admin)
print(f'  Alerts generated: count={len(alerts.json())}')
for a in alerts.json():
    print(f'    [{a["severity"]}] {a["alert_type"]}: {a["reason"]}')

print()
print('ALL DONE')
