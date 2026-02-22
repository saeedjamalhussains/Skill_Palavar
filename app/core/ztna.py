from typing import Optional
from app.core.config import settings
from app.db.models import User, Device, UserRole, Account
from datetime import datetime
from sqlalchemy.orm import Session

class ZTNAActions:
    LOGIN_FAILED = "LOGIN_FAILED"
    MFA_FAILED = "MFA_FAILED"
    FILE_EXPORT = "FILE_EXPORT"
    TRANSFER_INITIATE = "TRANSFER_INITIATE"
    UPDATE_ACCOUNT_STATUS = "UPDATE_ACCOUNT_STATUS"
    SEGMENT_ACCESS_DENIED = "SEGMENT_ACCESS_DENIED"
    CONCURRENT_LOGIN_ATTEMPT = "CONCURRENT_LOGIN_ATTEMPT"
    BRUTE_FORCE_DETECTED = "BRUTE_FORCE_DETECTED"

class RiskEngine:
    @staticmethod
    def calculate_risk(
        user: User,
        device_fingerprint: str,
        current_ip: str,
        transaction_amount: Optional[float] = None,
        db: Optional[Session] = None
    ) -> tuple[float, list[str]]:
        risk_score = 0.0
        reasons = []
        
        # 1. Device & Location Trust Check
        device = next((d for d in user.devices if d.fingerprint == device_fingerprint), None)
        if not device:
            risk_score += 0.2
            reasons.append("New/Unknown Device")
        elif not device.is_trusted:
            risk_score += 0.2
            reasons.append("Untrusted Device")
            
        # 2. Account Status Check
        account = user.accounts[0] if user.accounts else None
        if account:
            if account.status == "FROZEN":
                risk_score = 1.0
                reasons.append("Account Frozen")
                return risk_score, reasons
            if account.status == "MONITORED":
                risk_score += 0.2
                reasons.append("Account Under Monitoring")
                
        # 3. UEBA: Transaction Frequency & Amount
        if db:
            from app.db.models import AuditLog
            from datetime import timedelta
            
            # A. Check for Concurrent/Rapid Successive Logins (Session Hijacking / Account Sharing)
            recent_login_time = datetime.utcnow() - timedelta(seconds=10)
            recent_logins = db.query(AuditLog).filter(
                AuditLog.user_id == user.id,
                AuditLog.action == "LOGIN_SUCCESS",
                AuditLog.timestamp >= recent_login_time
            ).count()
            
            if recent_logins >= 3:
                risk_score += 0.4
                reasons.append("Suspicious: Rapid Successive Login (Possible Concurrent Session)")

            # B. Check for Brute Force Attempts
            brute_force_time = datetime.utcnow() - timedelta(minutes=5)
            failed_attempts = db.query(AuditLog).filter(
                AuditLog.user_id == user.id,
                AuditLog.action == ZTNAActions.LOGIN_FAILED,
                AuditLog.timestamp >= brute_force_time
            ).count()
            
            if failed_attempts >= 3:
                risk_score += 0.5
                reasons.append(f"Brute Force Detected: {failed_attempts} failed attempts")

            if transaction_amount:
                if transaction_amount > 500000:
                    risk_score += 0.3
                    reasons.append("High-Value Transaction")
                
                # Check for Rapid Successive Transactions (UEBA)
                recent_tx_time = datetime.utcnow() - timedelta(minutes=5)
                recent_count = db.query(AuditLog).filter(
                    AuditLog.user_id == user.id,
                    AuditLog.action == ZTNAActions.TRANSFER_INITIATE,
                    AuditLog.timestamp >= recent_tx_time
                ).count()
                
                if recent_count >= 3:
                    risk_score += 0.4
                    reasons.append("Abnormal Transaction Frequency")

                # Check for Rapid Successive File Exports (UEBA)
                recent_file_time = datetime.utcnow() - timedelta(minutes=5)
                file_count = db.query(AuditLog).filter(
                    AuditLog.user_id == user.id,
                    AuditLog.action == ZTNAActions.FILE_EXPORT,
                    AuditLog.timestamp >= recent_file_time
                ).count()
                
                if file_count >= 5:
                    risk_score += 0.5
                    reasons.append("Mass Data Export Detected")

        # 4. UEBA: Unusual Access Time (12 AM - 5 AM)
        hour = datetime.utcnow().hour
        if 0 <= hour <= 5:
            risk_score += 0.1
            reasons.append("Unusual Access Hours")

        # 5. UEBA: Daily Transaction Volume
        if db:
            from app.db.models import Transaction, TransactionStatus
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            daily_tx_count = db.query(Transaction).join(
                Account, Transaction.from_account_id == Account.id
            ).filter(
                Account.user_id == user.id,
                Transaction.timestamp >= today_start,
                Transaction.status == TransactionStatus.COMPLETED
            ).count()

            if daily_tx_count >= settings.DAILY_TRANSACTION_COUNT_LIMIT:
                risk_score += 0.15
                reasons.append(f"High Daily Volume: {daily_tx_count} transactions today")
            
        return min(risk_score, 1.0), reasons

    @staticmethod
    def get_action_for_risk(risk_score: float) -> str:
        if risk_score >= settings.RISK_THRESHOLD_HIGH:
            return "DENY"
        elif risk_score >= settings.RISK_THRESHOLD_MEDIUM:
            return "STEP_UP_MFA"
        return "ALLOW"

    @staticmethod
    def check_segment_access(user: User, resource_segment: str, risk_score: float) -> bool:
        """
        Micro-segmentation Logic: Even if role matches, high-risk context blocks 
        access to specific sensitive security segments.
        """
        # Critical Security Segment: Requires SENIOR role AND low risk (< 0.5)
        if resource_segment == "SECURITY_ADMIN":
            if user.role not in [UserRole.SUPER_ADMIN, UserRole.CENTRAL_HEAD, UserRole.REGIONAL_HEAD, UserRole.BRANCH_HEAD]:
                return False
            if risk_score > 0.5: # Even admins are blocked from sensitive segments if risk is elevated
                return False
                
        # Operational Segment: Requires STAFF role AND medium risk tolerance
        if resource_segment == "BRANCH_OPS":
            if user.role not in [UserRole.TELLER, UserRole.OPS_MANAGER, UserRole.BRANCH_HEAD]:
                return False
            if risk_score > 0.7:
                return False
                
        return True

ztna_risk_engine = RiskEngine()
