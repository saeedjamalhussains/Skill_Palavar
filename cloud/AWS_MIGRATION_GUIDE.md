# AWS Cloud Migration Guide (Phase 2)

This guide outlines the steps to migrate the ZTNA Banking Application from a local development environment to AWS Cloud using EC2 and RDS.

## 1. AWS RDS PostgreSQL Setup
1. Log in to the AWS Console and navigate to **RDS**.
2. Click **Create database**.
3. Choose **Standard create** -> **PostgreSQL**.
4. Template: **Free Tier**.
5. DB instance identifier: `ztna-banking-db`.
6. Credentials:
   - Master username: `postgres`
   - Master password: `your_secure_password`
7. Connectivity:
   - Virtual private cloud (VPC): Choose your default VPC.
   - Public access: **No** (Recommended) or **Yes** (only if needed for direct migration).
   - Security Group: Create new, allow inbound port `5432` from your EC2 instance's IP.

## 2. Database Migration Script
Use the provided `cloud/migrate_to_rds.py` to transfer data or use `pg_dump`:
```bash
# Export local data
pg_dump -U postgres -d ztna_banking > local_dump.sql

# Import to RDS
psql -h <rds-endpoint> -U postgres -d ztna_banking < local_dump.sql
```

## 3. EC2 Backend Deployment
1. Launch an **EC2 t3.micro** (Ubuntu).
2. Install Python 3.10 and necessary build tools:
   ```bash
   sudo apt update && sudo apt install -y python3-pip libpq-dev
   ```
3. Clone the repo and set environment variables:
   ```bash
   export DATABASE_URL="postgresql://postgres:password@rds-endpoint:5432/ztna_banking"
   export SECRET_KEY="production-secret-key"
   ```
4. Run using Gunicorn:
   ```bash
   pip install -r requirements.txt
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.app.main:app --bind 0.0.0.0:8000
   ```

## 4. Environment Variables Checklist
- [ ] `DATABASE_URL`
- [ ] `SECRET_KEY`
- [ ] `ALLOWED_HOSTS`
- [ ] `ZTNA_RISK_THRESHOLD`
