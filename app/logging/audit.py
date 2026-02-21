from sqlalchemy.orm import Session
from app.db.models import AuditLog
import json

class AuditLogger:
    @staticmethod
    def log_action(db: Session, user_id: int, action: str, resource: str, context: dict = None):
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            context=json.dumps(context) if context else None
        )
        db.add(log_entry)
        db.commit()

audit_logger = AuditLogger()
