"""
INSIDER THREAT SIMULATION - ZTNA BANKING
Tests 4 threat categories with proper account targeting
"""

import requests, time, json

BASE = 'http://localhost:8000/api/v1'

def login(username):
    r = requests.post(f'{BASE}/auth/login', json={
        'username': username, 'password': 'password123', 'fingerprint': 'sim_fp_001'
    })
    data = r.json()
    if data.get('status') == 'MFA_REQUIRED':
        otp = data.get('demo_otp_hint', '123456')
        mfa = requests.post(f'{BASE}/auth/mfa/verify', json={
            'username': username, 'otp': otp, 'fingerprint': 'sim_fp_001'
        })
        return {'Authorization': f'Bearer {mfa.json()["access_token"]}',
                'Content-Type': 'application/json',
                'X-Device-Fingerprint': 'sim_fp_001'}
    return {'Authorization': f'Bearer {data["access_token"]}',
            'Content-Type': 'application/json',
            'X-Device-Fingerprint': 'sim_fp_001'}


def get_alerts(headers):
    r = requests.get(f'{BASE}/admin/alerts', headers=headers)
    if r.status_code == 200:
        return r.json()
    print(f'  [WARN] Alerts endpoint: {r.status_code} {r.text[:100]}')
    return []


LINE = '=' * 60

print(f'\n{LINE}')
print('  INSIDER THREAT SIMULATION - ZTNA BANKING')
print(f'{LINE}\n')

admin_h = login('admin')
initial_alerts = get_alerts(admin_h)
alert_count_before = len(initial_alerts)
print(f'Starting alert count: {alert_count_before}\n')

# First, discover customer accounts visible to branch_1
branch_h = login('branch_1')
dir_resp = requests.get(f'{BASE}/admin/customer-directory', headers=branch_h)
if dir_resp.status_code == 200:
    customers = dir_resp.json()
    print(f'Branch 1 sees {len(customers)} customers:')
    for c in customers[:5]:
        print(f'  - {c.get("owner_name","?")} | Account ID: {c.get("id","?")} | {c.get("account_number","?")} | {c.get("status","?")}')
    if len(customers) > 5:
        print(f'  ... and {len(customers)-5} more')
else:
    print(f'[ERROR] Directory: {dir_resp.status_code}')
    customers = []

# Get account IDs that branch_1 can change
changeable_ids = [c['id'] for c in customers if 'id' in c][:5]
print(f'Changeable account IDs: {changeable_ids}\n')


# SCENARIO 1: ROGUE BRANCH HEAD - Privilege Abuse
print(f'{LINE}')
print('SCENARIO 1: Rogue Branch Head - Privilege Abuse')
print(f'  5 rapid account status changes (threshold: >= 3/hour)')
print(f'{LINE}')

if len(changeable_ids) >= 2:
    acc_a, acc_b = changeable_ids[0], changeable_ids[1]
    changes = [
        (acc_a, 'FROZEN'), (acc_a, 'ACTIVE'),
        (acc_b, 'MONITORED'), (acc_b, 'ACTIVE'),
        (acc_a, 'FROZEN')
    ]
    for i, (acc_id, st) in enumerate(changes):
        r = requests.post(f'{BASE}/admin/account/{acc_id}/status', headers=branch_h, json={'status_update': st})
        ok = 'OK' if r.status_code == 200 else 'FAIL'
        print(f'  [{ok}] Change #{i+1}: Acc {acc_id} -> {st} [{r.status_code}]')
        time.sleep(0.2)
else:
    print('  [SKIP] Not enough accounts visible to branch_1')

admin_h = login('admin')
a1 = get_alerts(admin_h)
new1 = len(a1) - alert_count_before
print(f'  >> New alerts: {new1}')
for a in a1[alert_count_before:]:
    print(f'     [{a["severity"]}] {a["alert_type"]}: {a["reason"]}')
print()


# SCENARIO 2: DATA HARVESTER - Excessive Directory Lookups
print(f'{LINE}')
print('SCENARIO 2: Data Harvester - Excessive Directory Lookups')
print(f'  22 rapid accesses (threshold: >= 20 in 10 min)')
print(f'{LINE}')

branch_h2 = login('branch_2')
for i in range(22):
    r = requests.get(f'{BASE}/admin/customer-directory', headers=branch_h2)
    time.sleep(0.05)
print(f'  Completed 22 lookups (all returned {r.status_code})')

admin_h = login('admin')
a2 = get_alerts(admin_h)
new2 = len(a2) - len(a1)
print(f'  >> New alerts: {new2}')
for a in a2[len(a1):]:
    print(f'     [{a["severity"]}] {a["alert_type"]}: {a["reason"]}')
print()


# SCENARIO 3: MASS EXPORT - Bulk Data Extraction
print(f'{LINE}')
print('SCENARIO 3: Mass Export - Bulk Data Extraction')
print(f'  5 rapid exports (threshold: >= 3 in 5 min)')
print(f'{LINE}')

reg_h = login('regional_north')
for i in range(5):
    r = requests.post(f'{BASE}/admin/export-report', headers=reg_h)
    msg = r.json().get('message', r.json().get('detail', ''))[:60]
    ok = 'OK' if r.status_code == 200 else 'BLOCKED'
    print(f'  [{ok}] Export #{i+1}: [{r.status_code}] {msg}')
    time.sleep(0.1)

admin_h = login('admin')
a3 = get_alerts(admin_h)
new3 = len(a3) - len(a2)
print(f'  >> New alerts: {new3}')
for a in a3[len(a2):]:
    print(f'     [{a["severity"]}] {a["alert_type"]}: {a["reason"]}')
print()


# SCENARIO 4: VELOCITY ANOMALY - Rapid Transfers
print(f'{LINE}')
print('SCENARIO 4: Velocity Anomaly - Rapid Customer Transfers')
print(f'  7 rapid transfers (threshold: >= 5 in 10 min)')
print(f'{LINE}')

cust_h = login('customer_10')
for i in range(7):
    r = requests.post(f'{BASE}/banking/transfer', headers=cust_h, json={
        'to_account_number': 'ACC_CUSTOMER_11', 'amount': 500,
        'idempotency_key': f'sim_{time.time()}_{i}'
    })
    detail = r.json().get('status', r.json().get('detail', ''))
    ok = 'OK' if r.status_code == 200 else 'BLOCKED'
    print(f'  [{ok}] Transfer #{i+1}: [{r.status_code}] {str(detail)[:60]}')
    time.sleep(0.1)

admin_h = login('admin')
a4 = get_alerts(admin_h)
new4 = len(a4) - len(a3)
print(f'  >> New alerts: {new4}')
for a in a4[len(a3):]:
    print(f'     [{a["severity"]}] {a["alert_type"]}: {a["reason"]}')
print()


# SUMMARY
print(f'{LINE}')
print('FULL ALERT LOG')
print(f'{LINE}')
for i, a in enumerate(a4):
    res = 'RESOLVED' if a['is_resolved'] else 'ACTIVE'
    acc_num = a.get('account_number', 'N/A')
    print(f'  {i+1}. [{a["severity"]:8s}] {a["alert_type"]:20s} | {acc_num:20s} | {res}')
    print(f'     {a["reason"]}')

frozen_alerts = [a for a in a4 if a['alert_type'] == 'AUTO_FREEZE']
if frozen_alerts:
    print(f'\n  AUTO-FROZEN ACCOUNTS:')
    for a in frozen_alerts:
        print(f'    {a.get("account_number","?")}: {a["reason"]}')

total = len(a4) - alert_count_before
print(f'\n  Scenario 1 (Privilege Abuse):  {new1} alerts')
print(f'  Scenario 2 (Data Harvest):    {new2} alerts')
print(f'  Scenario 3 (Mass Export):     {new3} alerts')
print(f'  Scenario 4 (Velocity):        {new4} alerts')
print(f'  TOTAL NEW:                    {total} alerts')

status = 'PASS' if total >= 4 else 'PARTIAL' if total > 0 else 'FAIL'
print(f'\n  RESULT: {status}')
print(f'{LINE}')
print('  SIMULATION COMPLETE')
print(f'{LINE}\n')
