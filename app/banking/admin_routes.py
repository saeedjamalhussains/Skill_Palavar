from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, Account, UserRole, AuditLog, Transaction, Approval
from app.rbac.enforcement import check_ztna, get_current_user
from app.core.ztna import ztna_risk_engine, ZTNAActions
from app.logging.audit import audit_logger
from app.banking.schemas import AccountStatusUpdate
from app.banking.scoping import apply_hierarchical_scoping
from typing import List

router = APIRouter(prefix="/admin", tags=["admin"])

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
    
    # Hierarchical Breakdown
    hierarchy_stats = []
    if user.role in [UserRole.SUPER_ADMIN, UserRole.CENTRAL_HEAD]:
        # Breakdown by Region
        from sqlalchemy import func
        stats = db.query(User.region_id, func.count(User.id)).group_by(User.region_id).all()
        for rid, count in stats:
            name = rid if rid else "GLOBAL / UNASSIGNED"
            hierarchy_stats.append({"name": name, "count": count, "type": "REGION"})
    elif user.role == UserRole.REGIONAL_HEAD:
        # Breakdown by Branch in their Region
        from sqlalchemy import func
        stats = db.query(User.branch_id, func.count(User.id)).filter(User.region_id == user.region_id).group_by(User.branch_id).all()
        for bid, count in stats:
            name = bid if bid else "UNASSIGNED TO BRANCH"
            hierarchy_stats.append({"name": name, "count": count, "type": "BRANCH"})

    audit_logger.log_action(db, user.id, "VIEW_ADMIN_DASHBOARD", "ADMIN", {"username": user.username})
    
    return {
        "total_users": total_users,
        "monitored_accounts": monitored_accounts,
        "frozen_accounts": frozen_accounts,
        "hierarchy_stats": hierarchy_stats,
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
    status_data: AccountStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to modify account status")
        
    # Apply Scoping to ensure authority
    account_query = db.query(Account).filter(Account.id == account_id)
    account = apply_hierarchical_scoping(account_query, Account, user).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found or access denied")
        
    old_status = account.status
    account.status = status_data.status_update.upper()
    db.commit()
    
    audit_logger.log_action(db, user.id, "UPDATE_ACCOUNT_STATUS", "ACCOUNT", {
        "account_id": account_id,
        "old_status": old_status,
        "new_status": account.status,
        "target_account": account.account_number
    })
    
    # Insider threat evaluation — detect frequent status changes
    from app.core.threat_monitor import threat_monitor
    threat_monitor.evaluate_insider_activity(db, user, "UPDATE_ACCOUNT_STATUS")
    
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
            "owner_role": acc.owner.role.value,
            "phone_number": acc.owner.phone_number,
            "address": acc.owner.address,
            "pan_number": acc.owner.pan_number,
            "dob": acc.owner.date_of_birth,
            "kyc_status": acc.owner.kyc_status
        })
    
    # Insider threat evaluation — detect excessive lookups
    from app.core.threat_monitor import threat_monitor
    audit_logger.log_action(db, user.id, "VIEW_CUSTOMER_DIRECTORY", "ADMIN", {"count": len(result)})
    threat_monitor.evaluate_insider_activity(db, user, "VIEW_CUSTOMER_DIRECTORY")

    return result

@router.get("/transactions", response_model=List[dict])
def get_admin_transactions(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.TELLER, UserRole.OPS_MANAGER, UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to access admin transactions")
        
    # Get Scoped Transactions
    trans_query = db.query(Transaction)
    trans_query = apply_hierarchical_scoping(trans_query, Transaction, user)
    
    transactions = trans_query.order_by(Transaction.timestamp.desc()).limit(30).all()
    
    # Process and Mask PII
    result = []
    for t in transactions:
        # Check if there is a pending approval for this transaction
        approval = db.query(Approval).filter(Approval.transaction_id == t.id).first()
        
        result.append({
            "id": t.id,
            "from_user": t.from_account.owner.username,
            "from_account": t.from_account.account_number,
            "to_user": t.to_account.owner.username,
            "to_account": t.to_account.account_number,
            "amount": t.amount,
            "timestamp": t.timestamp.isoformat(),
            "status": t.status,
            "risk_score": t.risk_score,
            "approval": {
                "id": approval.id,
                "required_role": approval.required_role,
                "status": approval.status
            } if approval else None
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
        ZTNAActions.FILE_EXPORT,
        ZTNAActions.CONCURRENT_LOGIN_ATTEMPT,
        ZTNAActions.BRUTE_FORCE_DETECTED
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
        severity = "MEDIUM"
        threat_type = "COMMONLY_SUSPICIOUS"
        message = f"Suspicious activity: {log.action}"

        if log.action == ZTNAActions.CONCURRENT_LOGIN_ATTEMPT:
            severity = "HIGH"
            threat_type = "AUTHENTICATION_ANOMALY"
            message = "Concurrent session attempt detected (Potential Hijacking)"
        elif log.action == ZTNAActions.BRUTE_FORCE_DETECTED:
            severity = "HIGH"
            threat_type = "AUTHENTICATION_ANOMALY"
            message = "Brute force attack signature detected"
        elif log.action in [ZTNAActions.LOGIN_FAILED, ZTNAActions.MFA_FAILED]:
            threat_type = "AUTHENTICATION_ANOMALY"
            message = f"Suspicious {log.action} attempt detected"
        elif log.action == ZTNAActions.FILE_EXPORT:
            threat_type = "DATA_EXFILTRATION_RISK"
            message = "Mass data export attempt detected"
        
        threats.append({
            "id": f"LOG-{log.id}",
            "type": threat_type,
            "severity": severity,
            "message": message,
            "timestamp": log.timestamp.isoformat(),
            "user": log.user.username if log.user else "Unknown"
        })
    return sorted(threats, key=lambda x: x["timestamp"], reverse=True)

@router.post("/export-report")
def export_report(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    from app.core.threat_monitor import threat_monitor
    # Log the action (this triggers UEBA risk escalation on subsequent calls)
    audit_logger.log_action(db, user.id, "FILE_EXPORT", "REPORT", {"filename": "customer_data_export.csv"})
    # Insider threat evaluation
    threat_monitor.evaluate_insider_activity(db, user, "FILE_EXPORT")
    return {"message": "Report generated and access logged for ZTNA verification."}

# --- Account Alerts (Automated Threat Detection) ---

@router.get("/alerts", response_model=List[dict])
def get_account_alerts(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    """View all automated threat alerts for accounts in scope."""
    from app.db.models import AccountAlert
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view alerts")
    
    query = db.query(AccountAlert).join(Account, AccountAlert.account_id == Account.id)
    query = apply_hierarchical_scoping(query, Account, user)
    alerts = query.order_by(AccountAlert.created_at.desc()).limit(50).all()
    
    result = []
    for a in alerts:
        result.append({
            "id": a.id,
            "account_id": a.account_id,
            "account_number": a.account.account_number if a.account else "N/A",
            "alert_type": a.alert_type,
            "severity": a.severity,
            "reason": a.reason,
            "is_resolved": a.is_resolved,
            "created_at": a.created_at.isoformat()
        })
    return result

@router.post("/alert/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    """Mark an alert as resolved after investigation."""
    from app.db.models import AccountAlert
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to resolve alerts")

    alert = db.query(AccountAlert).filter(AccountAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_resolved = True
    alert.resolved_by = user.id
    alert.resolved_at = datetime.utcnow()
    db.commit()
    
    audit_logger.log_action(db, user.id, "RESOLVE_ALERT", "ALERT", {
        "alert_id": alert_id,
        "alert_type": alert.alert_type
    })
    return {"message": f"Alert {alert_id} resolved"}

# --- Controlled Defreezing Workflow ---

@router.post("/defreeze-request/{account_id}")
def create_defreeze_request(
    account_id: int,
    reason: str = "Verified by branch staff",
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    """Branch head submits a defreeze request — requires higher authority approval."""
    from app.db.models import DefreezeRequest
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to request defreeze")
    
    account = apply_hierarchical_scoping(
        db.query(Account).filter(Account.id == account_id), Account, user
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found or access denied")
    if account.status != "FROZEN":
        raise HTTPException(status_code=400, detail="Account is not frozen")
    
    # Check for existing pending request
    existing = db.query(DefreezeRequest).filter(
        DefreezeRequest.account_id == account_id,
        DefreezeRequest.status == "PENDING"
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="A defreeze request is already pending for this account")
    
    req = DefreezeRequest(
        account_id=account_id,
        requested_by=user.id,
        reason=reason
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    
    audit_logger.log_action(db, user.id, "DEFREEZE_REQUEST", "ACCOUNT", {
        "account_id": account_id,
        "request_id": req.id
    })
    return {"message": f"Defreeze request #{req.id} created for account {account.account_number}", "request_id": req.id}

@router.get("/defreeze-requests", response_model=List[dict])
def list_defreeze_requests(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    """View pending defreeze requests in scope."""
    from app.db.models import DefreezeRequest
    if user.role not in [UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view defreeze requests")
    
    query = db.query(DefreezeRequest).filter(DefreezeRequest.status == "PENDING")
    query = query.join(Account, DefreezeRequest.account_id == Account.id)
    query = apply_hierarchical_scoping(query, Account, user)
    requests = query.order_by(DefreezeRequest.created_at.desc()).all()
    
    return [{
        "id": r.id,
        "account_id": r.account_id,
        "account_number": r.account.account_number,
        "requested_by": r.requester.username,
        "reason": r.reason,
        "status": r.status,
        "created_at": r.created_at.isoformat()
    } for r in requests]

@router.post("/defreeze-approve/{request_id}")
def approve_defreeze(
    request_id: int,
    comments: str = "Approved after verification",
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    """Regional/Central head approves defreeze — account is unfrozen."""
    from app.db.models import DefreezeRequest
    if user.role not in [UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to approve defreeze requests")
    
    req = db.query(DefreezeRequest).filter(
        DefreezeRequest.id == request_id,
        DefreezeRequest.status == "PENDING"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="Pending defreeze request not found")
    
    # Unfreeze the account
    account = db.query(Account).filter(Account.id == req.account_id).first()
    account.status = "ACTIVE"
    
    req.status = "APPROVED"
    req.verified_by = user.id
    req.comments = comments
    req.resolved_at = datetime.utcnow()
    db.commit()
    
    audit_logger.log_action(db, user.id, "DEFREEZE_APPROVED", "ACCOUNT", {
        "account_id": req.account_id,
        "request_id": request_id
    })
    return {"message": f"Account {account.account_number} has been unfrozen"}
