# ZTNA Secure Banking Application (V-Bank)

A modular, production-oriented full-stack banking application secured with Zero Trust Network Access (ZTNA) and hierarchical RBAC.

## 🚀 Key Features
- **ZTNA Gateway**: Continuous verification using contextual risk engine (Device, IP, Amount).
- **Hierarchical RBAC**: 7-tier role system from Customer to Central Head.
- **Banking Core**: Secure transfers with tiered approval logic.
- **Premium UI**: Glassmorphism dark-mode dashboard.

## 🛠️ Local Setup (Windows)

### 1. Prerequisites
- Python 3.10+
- PostgreSQL (Local or Docker)

### 2. Installation
```powershell
# Clone the repository
cd ZTNA

# Install dependencies
pip install fastapi uvicorn sqlalchemy psycopg2-binary passlib[bcrypt] python-jose[cryptography] pydantic-settings
```

### 3. Database Setup
Create a PostgreSQL database named `ztna_banking` and update `.env`:
```ini
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/ztna_banking
SECRET_KEY=your_secret_key_here
```

### 4. Running the App
```powershell
# Seed demo data
python seed.py

# Start Backend
uvicorn app.main:app --reload

# Open Frontend
# Navigate to /frontend/index.html in your browser
```

## 🔐 ZTNA Policy Example
The system evaluates risk on every login and transaction:
- **Low Risk (<0.4)**: Fingerprint recognized + Low value -> Allow.
- **Medium Risk (0.4 - 0.7)**: New device or Medium value -> Step-up MFA.
- **High Risk (>0.7)**: Critical value or Contextual anomalies -> Deny.

## 🏦 RBAC Hierarchy
| Role | Level | Key Permission |
|------|-------|----------------|
| Central Head | 80 | View Audit, Global Approvals |
| Branch Head | 60 | Local Approvals (>10k) |
| Teller | 40 | Initiate Transfers, View Users |
| Customer | 10 | Personal Transfers |

## ☁️ AWS Deployment Guide
1. **RDS**: Provision PostgreSQL (t3.micro).
2. **EC2**: Setup Ubuntu instance, install dependencies.
3. **Environment**: Set `DATABASE_URL` pointing to RDS endpoint.
4. **Production**: Run with `gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app`.
# Skill_Palavar
# Skill_Palavar
# Skill_Palavar
