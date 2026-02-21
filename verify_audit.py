from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.models import AuditLog, User
from app.core.config import settings
import json

def verify_audit_logs():
    engine = create_engine(settings.DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    print("Recent Audit Logs:")
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    if not logs:
        print("No audit logs found.")
    else:
        for log in logs:
            user = db.query(User).filter(User.id == log.user_id).first()
            username = user.username if user else "Unknown"
            print(f"[{log.timestamp}] User: {username} | Action: {log.action} | Resource: {log.resource}")
            if log.context:
                print(f"   Context: {log.context}")
    
    db.close()

if __name__ == "__main__":
    verify_audit_logs()
