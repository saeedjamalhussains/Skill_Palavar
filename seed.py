from sqlalchemy.orm import Session
from app.db.session import SessionLocal, init_db
from app.db.models import User, Account, UserRole
from app.core.security import get_password_hash

def seed_data():
    init_db()
    db = SessionLocal()
    
    # Check if data already exists
    if db.query(User).first():
        print("Data already seeded.")
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

    # Add 10 Tellers and 30+ Customers distributed across branches
    for i in range(1, 11):
        branch = f"BR-00{(i % 3) + 1}"
        region = "REG-NORTH" if branch in ["BR-001", "BR-002"] else "REG-SOUTH"
        user_data.append((f"teller_{i}", f"teller{i}@vbank.com", UserRole.TELLER, branch, region))

    for i in range(1, 33):
        branch = f"BR-00{(i % 3) + 1}"
        region = "REG-NORTH" if branch in ["BR-001", "BR-002"] else "REG-SOUTH"
        user_data.append((f"customer_{i}", f"cust{i}@vbank.com", UserRole.CUSTOMER, branch, region))

    for username, email, role, b_id, r_id in user_data:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                username=username,
                email=email,
                hashed_password=get_password_hash("password123"),
                role=role,
                branch_id=b_id,
                region_id=r_id
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
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

    print(f"Generated {len(user_data)} seeded identities successfully.")

    print("Comprehensive seed data created successfully.")
    db.close()

if __name__ == "__main__":
    seed_data()
