from sqlalchemy.orm import Session
from app.db.session import SessionLocal, init_db
from app.db.models import User, Account, UserRole, Transaction, TransactionStatus
from app.core.security import get_password_hash
from datetime import datetime

def seed_data():
    init_db()
    db = SessionLocal()
    
    # Check if data already exists
    if db.query(User).count() > 40:
        print("Data already seeded (40+ users found).")
        db.close()
        return

    # programmatically generate 50 users with hierarchy
    user_data = [
        ("admin", "admin@vbank.com", UserRole.SUPER_ADMIN, None, None),
        ("central_1", "central1@vbank.com", UserRole.CENTRAL_HEAD, None, None),
        ("regional_north", "reg_n@vbank.com", UserRole.REGIONAL_HEAD, None, "REG-NORTH"),
        ("regional_south", "reg_s@vbank.com", UserRole.REGIONAL_HEAD, None, "REG-SOUTH"),
        ("branch_1", "br1@vbank.com", UserRole.BRANCH_HEAD, "BR-001", "REG-NORTH"),
        ("branch_2", "br2@vbank.com", UserRole.BRANCH_HEAD, "BR-002", "REG-NORTH"),
        ("branch_3", "br3@vbank.com", UserRole.BRANCH_HEAD, "BR-003", "REG-SOUTH"),
    ]

    # Add 10 Tellers and 32 Customers distributed across branches
    for i in range(1, 11):
        branch = f"BR-00{(i % 3) + 1}"
        region = "REG-NORTH" if branch in ["BR-001", "BR-002"] else "REG-SOUTH"
        user_data.append((f"teller_{i}", f"teller{i}@vbank.com", UserRole.TELLER, branch, region))

    for i in range(1, 33):
        branch = f"BR-00{(i % 3) + 1}"
        region = "REG-NORTH" if branch in ["BR-001", "BR-002"] else "REG-SOUTH"
        user_data.append((f"customer_{i}", f"cust{i}@vbank.com", UserRole.CUSTOMER, branch, region))

    print(f"Starting seed with {len(user_data)} potential users...")
    
    for index, (username, email, role, b_id, r_id) in enumerate(user_data):
        user = db.query(User).filter(User.username == username).first()
        if not user:
            is_customer = role == UserRole.CUSTOMER
            user = User(
                username=username,
                email=email,
                hashed_password=get_password_hash("password123"),
                role=role,
                branch_id=b_id,
                region_id=r_id,
                phone_number=f"+91 98765 {20000 + index}" if is_customer else None,
                address=f"{100 + index}, Banking Enclave, New Delhi" if is_customer else None,
                pan_number=f"ABCDE{2000 + index}F" if is_customer else None,
                date_of_birth="1990-01-01" if is_customer else None,
                kyc_status="VERIFIED" if is_customer else "NOT_APPLICABLE"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"  [+] Created User: {username}")
        
        # Add account ONLY for customers
        if role == UserRole.CUSTOMER:
            account = db.query(Account).filter(Account.user_id == user.id).first()
            if not account:
                account = Account(
                    account_number=f"ACC_{username.upper()}",
                    user_id=user.id,
                    balance=1000000.0,
                    status="ACTIVE"
                )
                db.add(account)
                db.commit()
                print(f"      [A] Created Account for {username}")

                # Add transactions for some customers to show history
                if index > 20: 
                    # Use a different account for target
                    target_acc = db.query(Account).filter(Account.id != account.id).first()
                    if target_acc:
                        for j in range(2):
                            tx = Transaction(
                                from_account_id=account.id,
                                to_account_id=target_acc.id,
                                amount=1000.0 * (j + 1),
                                status=TransactionStatus.COMPLETED,
                                risk_score=0.1,
                                idempotency_key=f"seed_tx_{username}_{j}_{datetime.utcnow().timestamp()}"
                            )
                            db.add(tx)
                db.commit()

    print("\n--- SEED COMPLETE ---")
    print(f"Total Users: {db.query(User).count()}")
    print(f"Total Accounts: {db.query(Account).count()}")
    print(f"Total Transactions: {db.query(Transaction).count()}")
    db.close()

if __name__ == "__main__":
    seed_data()
