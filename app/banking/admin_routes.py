from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, Account, UserRole, AuditLog, Transaction, Approval
from app.rbac.enforcement import check_ztna, get_current_user
from app.core.ztna import ztna_risk_engine, ZTNAActions
from app.logging.audit import audit_logger
from typing import List

router = APIRouter(prefix="/admin", tags=["admin"])

def apply_hierarchical_scoping(query, model, user):
    """
    Centralized utility to apply branch/region scoping based on user hierarchy.
    Supported models: User, Transaction, AuditLog, Account
    """
    if user.role == UserRole.SUPER_ADMIN or user.role == UserRole.CENTRAL_HEAD:
        return query
        
    if user.role == UserRole.BRANCH_HEAD:
        if model == User:
            return query.filter(User.branch_id == user.branch_id)
        elif model == Account:
            return query.join(User, Account.user_id == User.id).filter(User.branch_id == user.branch_id)
        elif model == Transaction:
            return query.join(Account, Transaction.from_account_id == Account.id).join(User, Account.user_id == User.id).filter(User.branch_id == user.branch_id)
        elif model == AuditLog:
            return query.join(User, AuditLog.user_id == User.id).filter(User.branch_id == user.branch_id)
            
    elif user.role == UserRole.REGIONAL_HEAD:
        if model == User:
            return query.filter(User.region_id == user.region_id)
        elif model == Account:
            return query.join(User, Account.user_id == User.id).filter(User.region_id == user.region_id)
        elif model == Transaction:
            return query.join(Account, Transaction.from_account_id == Account.id).join(User, Account.user_id == User.id).filter(User.region_id == user.region_id)
        elif model == AuditLog:
            return query.join(User, AuditLog.user_id == User.id).filter(User.region_id == user.region_id)
            
    return query 

@router.get("/dashboard", response_model=dict)
def get_admin_dashboard(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.TELLER, UserRole.OPS_MANAGER, UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to access admin dashboard")
        
    total_users = apply_hierarchical_scoping(db.query(User), User, user).count()
    monitored_accounts = apply_hierarchical_scoping(db.query(Account), Account, user).filter(Account.status == "MONITORED").count()
    frozen_accounts = apply_hierarchical_scoping(db.query(Account), Account, user).filter(Account.status == "FROZEN").count()
    recent_logs = apply_hierarchical_scoping(db.query(AuditLog), AuditLog, user).order_by(AuditLog.timestamp.desc()).limit(5).all()
    
    audit_logger.log_action(db, user.id, "VIEW_ADMIN_DASHBOARD", "ADMIN", {"username": user.username})
    
    return {
        "total_users": total_users,
        "monitored_accounts": monitored_accounts,
        "frozen_accounts": frozen_accounts,
        "recent_logs": [
            {
                "id": log.id,
                "action": log.action,
                "resource": log.resource,
                "timestamp": log.timestamp.isoformat(),
                "context": log.context,
                "username": log.user.username if log.user else "System"
            } for log in recent_logs
        ]
    }

@router.post("/account/{account_id}/status")
def update_account_status(
    account_id: int,
    status_update: str, # ACTIVE, FROZEN, MONITORED
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to modify account status")
        
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
        
    old_status = account.status
    account.status = status_update.upper()
    db.commit()
    
    audit_logger.log_action(db, user.id, "UPDATE_ACCOUNT_STATUS", "ACCOUNT", {
        "account_id": account_id,
        "old_status": old_status,
        "new_status": account.status
    })
    
    return {"message": f"Account {account.account_number} status updated to {account.status}"}

@router.get("/audit/search", response_model=List[dict])
def search_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view audit logs")
        
    query = db.query(AuditLog)
    query = apply_hierarchical_scoping(query, AuditLog, user)
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    result = [
        {
            "id": log.id,
            "action": log.action,
            "resource": log.resource,
            "timestamp": log.timestamp.isoformat(),
            "context": log.context,
            "username": log.user.username if log.user else "System"
        } for log in logs
    ]
    
    audit_logger.log_action(db, user.id, "SEARCH_AUDIT_LOGS", "ADMIN", {"limit": limit})
    
    return result
@router.get("/customer-directory", response_model=List[dict])
def list_customer_accounts(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    # Staff can view accounts. Hierarchy filtering could be added here.
    if user.role not in [UserRole.TELLER, UserRole.OPS_MANAGER, UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view customer directory")
    
    query = db.query(Account)
    query = apply_hierarchical_scoping(query, Account, user)
    accounts = query.all()
    
    result = []
    for acc in accounts:
        result.append({
            "id": acc.id,
            "account_number": acc.account_number,
            "balance": acc.balance,
            "status": acc.status,
            "owner_name": acc.owner.username,
            "owner_role": acc.owner.role.value
        })
    
    return result

@router.get("/threats", response_model=List[dict])
def get_threat_intelligence(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    # 1. Micro-segmentation Check
    # Even though check_ztna passed baseline, we check if user is allowed in SECURITY_ADMIN segment
    risk_score, reasons = ztna_risk_engine.calculate_risk(user, "demo_fingerprint", "127.0.0.1", db=db)
    if not ztna_risk_engine.check_segment_access(user, "SECURITY_ADMIN", risk_score):
        audit_logger.log_action(db, user.id, "SEGMENT_ACCESS_DENIED", "SECURITY", {"segment": "SECURITY_ADMIN", "reasons": reasons})
        raise HTTPException(status_code=403, detail=f"ZTNA Micro-segmentation: Access to SECURITY_ADMIN segment denied due to elevated risk ({', '.join(reasons)})")

    # Only senior staff can view threat intelligence
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view threat intelligence")

    # Aggregate anomalies (UEBA) with Hierarchical Scoping
    trans_query = db.query(Transaction).filter(Transaction.risk_score > 0.6)
    log_query = db.query(AuditLog).filter(AuditLog.action.in_([
        ZTNAActions.LOGIN_FAILED, 
        ZTNAActions.MFA_FAILED, 
        ZTNAActions.FILE_EXPORT
    ]))

    # Apply Scoping Logic
    trans_query = apply_hierarchical_scoping(trans_query, Transaction, user)
    log_query = apply_hierarchical_scoping(log_query, AuditLog, user)

    high_risk_trans = trans_query.order_by(Transaction.timestamp.desc()).limit(15).all()
    suspicious_activities = log_query.order_by(AuditLog.timestamp.desc()).limit(20).all()

    threats = []
    # Process transactions...
    for trans in high_risk_trans:
        threats.append({
            "id": f"TR-{trans.id}",
            "type": "ANOMALOUS_TRANSACTION",
            "severity": "HIGH" if trans.risk_score > 0.8 else "MEDIUM",
            "message": f"High-risk transfer (₹{trans.amount}) detected for {trans.from_account.owner.username}",
            "timestamp": trans.timestamp.isoformat(),
            "user": trans.from_account.owner.username
        })

    # Process Suspicious Activities (Logs)
    for log in suspicious_activities:
        if log.action in [ZTNAActions.LOGIN_FAILED, ZTNAActions.MFA_FAILED]:
            threats.append({
                "id": f"LOG-{log.id}",
                "type": "AUTHENTICATION_ANOMALY",
                "severity": "MEDIUM",
                "message": f"Suspicious {log.action} attempt detected",
                "timestamp": log.timestamp.isoformat(),
                "user": log.user.username if log.user else "Unknown"
            })
        elif log.action == ZTNAActions.FILE_EXPORT:
            # UEBA Check for Mass Exports in the scoped list
            recent_count = db.query(AuditLog).filter(
                AuditLog.user_id == log.user_id,
                AuditLog.action == ZTNAActions.FILE_EXPORT
            ).count()
            
            if recent_count >= 3:
                threats.append({
                    "id": f"EX-{log.id}",
                    "type": "DATA_EXFILTRATION_RISK",
                    "severity": "HIGH" if recent_count >= 5 else "MEDIUM",
                    "message": f"Anomalous mass data export activity detected",
                    "timestamp": log.timestamp.isoformat(),
                    "user": log.user.username
                })

    return sorted(threats, key=lambda x: x["timestamp"], reverse=True)

@router.post("/export-report")
def export_report(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    # Log the action (this triggers UEBA risk escalation on subsequent calls)
    audit_logger.log_action(db, user.id, "FILE_EXPORT", "REPORT", {"filename": "customer_data_export.csv"})
    return {"message": "Report generated and access logged for ZTNA verification."}
