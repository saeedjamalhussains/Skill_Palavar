from app.db.session import engine, init_db
from app.db.models import Base
from seed import seed_data
import os

def reset():
    print("Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    print("Initializing fresh schema...")
    init_db()
    print("Seeding staff accounts...")
    seed_data()
    print("Reset complete.")

if __name__ == "__main__":
    reset()
