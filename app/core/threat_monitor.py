"""
Behavioral Anomaly Auto-Response Engine (ThreatMonitor)

Runs post-transaction to evaluate cumulative behavior and automatically
flag, monitor, or freeze accounts based on anomaly detection.

Covers: Velocity anomalies, amount deviations, insider threats, and auto-freeze.
"""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.models import (
    Account, Transaction, TransactionStatus, AuditLog,
    AccountAlert, User, UserRole
)
from app.core.config import settings
from app.logging.audit import audit_logger


class ThreatMonitor:

    @staticmethod
    def evaluate_post_transaction(db: Session, account: Account, transaction: Transaction):
        """
        Called after every completed transaction. Evaluates:
        1. Velocity anomaly (too many transactions in short window)
        2. Amount anomaly (transaction >> user's average)
        3. Auto-freeze (2+ unresolved alerts in 24h)
        """
        alerts_generated = []

        # 1. Velocity Anomaly:  5+ transactions in VELOCITY_WINDOW minutes
        window = datetime.utcnow() - timedelta(minutes=settings.VELOCITY_WINDOW_MINUTES)
        recent_tx_count = db.query(Transaction).filter(
            Transaction.from_account_id == account.id,
            Transaction.timestamp >= window,
            Transaction.status == TransactionStatus.COMPLETED
        ).count()

        if recent_tx_count >= settings.VELOCITY_THRESHOLD:
            alert = ThreatMonitor._create_alert(
                db, account.id,
                alert_type="VELOCITY_ANOMALY",
                severity="HIGH",
                reason=f"Abnormal frequency: {recent_tx_count} transactions in {settings.VELOCITY_WINDOW_MINUTES} minutes"
            )
            alerts_generated.append(alert)
            # Set account to MONITORED if currently ACTIVE
            if account.status == "ACTIVE":
                account.status = "MONITORED"
                db.commit()
                audit_logger.log_action(db, None, "AUTO_MONITOR", "THREAT_ENGINE", {
                    "account_id": account.id,
                    "reason": "velocity_anomaly",
                    "tx_count": recent_tx_count
                })

        # 2. Amount Anomaly: transaction > 3× user's average
        avg_result = db.query(func.avg(Transaction.amount)).filter(
            Transaction.from_account_id == account.id,
            Transaction.status == TransactionStatus.COMPLETED
        ).scalar()

        if avg_result and avg_result > 0:
            avg_amount = float(avg_result)
            if transaction.amount > (avg_amount * 3) and transaction.amount > 10000:
                alert = ThreatMonitor._create_alert(
                    db, account.id,
                    alert_type="AMOUNT_ANOMALY",
                    severity="MEDIUM",
                    reason=f"Transaction ₹{transaction.amount:,.0f} is {transaction.amount / avg_amount:.1f}× the average (₹{avg_amount:,.0f})"
                )
                alerts_generated.append(alert)

        # 3. Auto-Freeze: 2+ unresolved alerts in 24 hours
        ThreatMonitor._check_auto_freeze(db, account)

        return alerts_generated

    @staticmethod
    def evaluate_insider_activity(db: Session, user: User, action: str, target_account_id: int = None):
        """
        Called after staff actions to detect insider threat patterns:
        - Frequent account status changes (>3 in 1 hour)
        - Excessive customer directory lookups (>20 in 10 min)
        - Mass file exports (>3 in 5 min)
        
        target_account_id: the account being acted upon (for status changes).
                           For lookups/exports, first customer account is used as sentinel.
        """
        if user.role in [UserRole.CUSTOMER]:
            return []  # Only monitor staff

        alerts_generated = []
        
        # Resolve alert_account_id: use target_account_id if given, else find first customer account as sentinel
        if target_account_id:
            alert_account_id = target_account_id
        else:
            sentinel = db.query(Account).first()
            alert_account_id = sentinel.id if sentinel else None
        
        if not alert_account_id:
            return []  # No accounts exist yet

        # A. Frequent Account Status Changes (privilege abuse)
        if action == "UPDATE_ACCOUNT_STATUS":
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            status_change_count = db.query(AuditLog).filter(
                AuditLog.user_id == user.id,
                AuditLog.action == "UPDATE_ACCOUNT_STATUS",
                AuditLog.timestamp >= one_hour_ago
            ).count()

            if status_change_count >= 3:
                alert = ThreatMonitor._create_alert(
                    db, alert_account_id,
                    alert_type="INSIDER_THREAT",
                    severity="HIGH",
                    reason=f"Staff '{user.username}' made {status_change_count} account status changes in 1 hour (possible privilege abuse)"
                )
                alerts_generated.append(alert)

        # B. Excessive Customer Directory Lookups (data harvesting)
        if action == "VIEW_CUSTOMER_DIRECTORY":
            ten_min_ago = datetime.utcnow() - timedelta(minutes=10)
            lookup_count = db.query(AuditLog).filter(
                AuditLog.user_id == user.id,
                AuditLog.action.in_(["VIEW_CUSTOMER_DIRECTORY", "SEARCH_AUDIT_LOGS"]),
                AuditLog.timestamp >= ten_min_ago
            ).count()

            if lookup_count >= 20:
                alert = ThreatMonitor._create_alert(
                    db, alert_account_id,
                    alert_type="INSIDER_THREAT",
                    severity="CRITICAL",
                    reason=f"Staff '{user.username}' performed {lookup_count} data lookups in 10 min (possible data harvesting)"
                )
                alerts_generated.append(alert)

        # C. Mass File Exports
        if action == "FILE_EXPORT":
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)
            export_count = db.query(AuditLog).filter(
                AuditLog.user_id == user.id,
                AuditLog.action == "FILE_EXPORT",
                AuditLog.timestamp >= five_min_ago
            ).count()

            if export_count >= 3:
                alert = ThreatMonitor._create_alert(
                    db, alert_account_id,
                    alert_type="INSIDER_THREAT",
                    severity="CRITICAL",
                    reason=f"Staff '{user.username}' triggered {export_count} file exports in 5 min (data exfiltration risk)"
                )
                alerts_generated.append(alert)

        return alerts_generated

    @staticmethod
    def _create_alert(db: Session, account_id: int, alert_type: str, severity: str, reason: str) -> AccountAlert:
        """Create and persist an AccountAlert."""
        alert = AccountAlert(
            account_id=account_id,
            alert_type=alert_type,
            severity=severity,
            reason=reason
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def _check_auto_freeze(db: Session, account: Account):
        """If 2+ unresolved alerts exist in the last 24 hours, auto-freeze the account."""
        if account.status == "FROZEN":
            return  # Already frozen

        twenty_four_hours = datetime.utcnow() - timedelta(hours=24)
        unresolved_count = db.query(AccountAlert).filter(
            AccountAlert.account_id == account.id,
            AccountAlert.is_resolved == False,
            AccountAlert.created_at >= twenty_four_hours
        ).count()

        if unresolved_count >= settings.AUTO_FREEZE_ALERT_THRESHOLD:
            account.status = "FROZEN"
            # Create a special AUTO_FREEZE alert
            freeze_alert = AccountAlert(
                account_id=account.id,
                alert_type="AUTO_FREEZE",
                severity="CRITICAL",
                reason=f"Account auto-frozen: {unresolved_count} unresolved alerts in 24 hours"
            )
            db.add(freeze_alert)
            db.commit()

            audit_logger.log_action(db, None, "AUTO_FREEZE", "THREAT_ENGINE", {
                "account_id": account.id,
                "account_number": account.account_number,
                "unresolved_alerts": unresolved_count
            })


threat_monitor = ThreatMonitor()
