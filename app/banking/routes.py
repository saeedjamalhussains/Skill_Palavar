from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, Account, Transaction, Approval, TransactionStatus, UserRole
from app.banking.schemas import TransactionCreate, TransactionResponse, AccountResponse, InteractionEvent
from app.rbac.enforcement import get_current_user, check_permission, check_ztna
from app.core.ztna import ztna_risk_engine
from app.logging.audit import audit_logger
from typing import List
import json

router = APIRouter(prefix="/banking", tags=["banking"])

@router.post("/log-interaction")
def log_interaction(
    event: InteractionEvent,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    audit_logger.log_action(db, user.id, "UI_CLICK", "FRONTEND", {
        "element_id": event.element_id,
        "class": event.element_class,
        "tag": event.tag_name,
        "text": event.text_content[:50] if event.text_content else None
    })
    return {"status": "recorded"}

@router.get("/accounts", response_model=List[AccountResponse])
def get_accounts(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return user.accounts

@router.post("/transfer", response_model=TransactionResponse)
def transfer(
    trans_in: TransactionCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    x_device_fingerprint: str = Header(None, alias="X-Device-Fingerprint")
):
    # 1. Identity & RBAC Check
    if not any(acc.user_id == user.id for acc in user.accounts) and user.role != UserRole.TELLER:
        raise HTTPException(status_code=403, detail="Not authorized to transfer from this account")

    # 2. Find accounts
    from_account = db.query(Account).filter(Account.user_id == user.id).first()
    
    # Normalize account number to uppercase for matching
    target_acc_num = trans_in.to_account_number.strip().upper()
    to_account = db.query(Account).filter(Account.account_number == target_acc_num).first()
    
    if not from_account:
        raise HTTPException(status_code=404, detail="Your source account was not found. Please contact support.")
    
    if not to_account:
        raise HTTPException(status_code=404, detail=f"Target account '{target_acc_num}' not found. Please check the account number.")
        
    if from_account.id == to_account.id:
        raise HTTPException(status_code=400, detail="Cannot transfer to the same account.")
        
    if from_account.status == "FROZEN":
        raise HTTPException(status_code=403, detail="Your account is frozen. Transactions are blocked.")

    if from_account.balance < trans_in.amount:
        raise HTTPException(status_code=400, detail=f"Insufficient funds. Available: ₹{from_account.balance}")

    # 3. Idempotency Check
    existing_trans = db.query(Transaction).filter(Transaction.idempotency_key == trans_in.idempotency_key).first()
    if existing_trans:
        return existing_trans

    # 4. ZTNA Risk Assessment on Transaction
    fp = x_device_fingerprint or "unknown"
    risk_score, reasons = ztna_risk_engine.calculate_risk(user, fp, request.client.host, trans_in.amount, db=db)
    action = ztna_risk_engine.get_action_for_risk(risk_score)
    
    if action == "DENY":
        audit_logger.log_action(db, user.id, "TRANSFER_BLOCKED", "ZTNA", {"reason": reasons, "amount": trans_in.amount})
        raise HTTPException(status_code=403, detail=f"Transaction blocked by ZTNA Risk Engine: {', '.join(reasons)}")
    
    if action == "STEP_UP_MFA":
        raise HTTPException(status_code=403, detail=f"ZTNA Security: Step-up MFA verification required. {', '.join(reasons)}")

    # 5. Create Transaction
    new_trans = Transaction(
        from_account_id=from_account.id,
        to_account_id=to_account.id,
        amount=trans_in.amount,
        status=TransactionStatus.PENDING,
        risk_score=risk_score,
        idempotency_key=trans_in.idempotency_key
    )
    db.add(new_trans)
    db.commit()
    db.refresh(new_trans)

    # 6. Check for Approval Requirement
    if trans_in.amount > 500000: # > 5 Lakh INR
        required_role = UserRole.BRANCH_HEAD
        if trans_in.amount > 2500000: # > 25 Lakh INR
            required_role = UserRole.REGIONAL_HEAD
            
        approval = Approval(
            transaction_id=new_trans.id,
            required_role=required_role,
            status=TransactionStatus.PENDING
        )
        db.add(approval)
        db.commit()
    else:
        # Immediate processing for low-value
        from_account.balance -= trans_in.amount
        to_account.balance += trans_in.amount
        new_trans.status = TransactionStatus.COMPLETED
        db.commit()

        # 7. Post-Transaction Threat Evaluation (velocity + amount anomaly + auto-freeze)
        from app.core.threat_monitor import threat_monitor
        threat_monitor.evaluate_post_transaction(db, from_account, new_trans)
    
    audit_logger.log_action(db, user.id, "TRANSFER_INITIATE", "TRANSACTION", {
        "transaction_id": new_trans.id,
        "amount": trans_in.amount,
        "status": new_trans.status
    })
        
    # Populate for response
    new_trans.to_user = to_account.owner.username
    new_trans.to_account_number = to_account.account_number
    
    return new_trans

from app.banking.scoping import apply_hierarchical_scoping

@router.get("/approvals", response_model=List[dict])
def get_pending_approvals(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to view approvals")
        
    query = db.query(Approval).filter(Approval.status == TransactionStatus.PENDING)
    query = apply_hierarchical_scoping(query, Approval, user)
    
    # Filter by role requirement if not Central Head
    if user.role not in [UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN]:
        query = query.filter(Approval.required_role == user.role)

    approvals = query.all()
    
    result = []
    for appr in approvals:
        result.append({
            "id": appr.id,
            "transaction_id": appr.transaction_id,
            "required_role": appr.required_role,
            "amount": appr.transaction.amount,
            "requester": appr.transaction.from_account.owner.username,
            "requested_at": appr.created_at.isoformat(),
            "tx_timestamp": appr.transaction.timestamp.isoformat()
        })
    
    audit_logger.log_action(db, user.id, "VIEW_APPROVALS", "APPROVAL", {"role": user.role})
    return result

@router.post("/approve/{approval_id}")
def approve_transaction(
    approval_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    # RBAC Check
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD]:
        raise HTTPException(status_code=403, detail="Not authorized to approve transactions")
        
    approval = db.query(Approval).filter(Approval.id == approval_id, Approval.status == TransactionStatus.PENDING).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Pending approval not found")
        
    # Verify hierarchical authority
    if approval.required_role != user.role and user.role != UserRole.CENTRAL_HEAD:
        # Note: Central head can approve anything, others must match their role
        raise HTTPException(status_code=403, detail=f"Your role ({user.role}) is not authorized for this approval level ({approval.required_role})")

    transaction = approval.transaction
    from_account = transaction.from_account
    to_account = transaction.to_account

    # Execute transaction
    if from_account.balance < transaction.amount:
        transaction.status = TransactionStatus.FAILED
        approval.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(status_code=400, detail="Insufficient funds in source account")

    from_account.balance -= transaction.amount
    to_account.balance += transaction.amount
    transaction.status = TransactionStatus.COMPLETED
    approval.status = TransactionStatus.COMPLETED
    
    db.commit()
    
    audit_logger.log_action(db, user.id, "APPROVE_TRANSACTION", "APPROVAL", {
        "approval_id": approval_id,
        "transaction_id": transaction.id,
        "amount": transaction.amount
    })
    
    return {"message": "Transaction approved and completed"}

@router.get("/transactions", response_model=List[TransactionResponse])
def get_transaction_history(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # Get all accounts owned by the user
    account_ids = [acc.id for acc in user.accounts]
    
    # Fetch transactions where either sender or receiver is one of user's accounts
    transactions = db.query(Transaction).filter(
        (Transaction.from_account_id.in_(account_ids)) | 
        (Transaction.to_account_id.in_(account_ids))
    ).order_by(Transaction.timestamp.desc()).limit(20).all()

    result = []
    for tx in transactions:
        # Determine the "other party"
        is_sender = tx.from_account_id in account_ids
        other_party_acc = tx.to_account if is_sender else tx.from_account
        
        # Create a dictionary for the response to avoid mutating DB objects directly if possible
        tx_resp = {
            "id": tx.id,
            "from_account_id": tx.from_account_id,
            "to_account_id": tx.to_account_id,
            "amount": tx.amount,
            "status": tx.status,
            "timestamp": tx.timestamp,
            "to_user": other_party_acc.owner.username if other_party_acc and other_party_acc.owner else "Unknown",
            "to_account_number": other_party_acc.account_number if other_party_acc else "N/A",
            "is_debit": is_sender
        }
        result.append(tx_resp)
    
    return result
