from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, Account, Transaction, Approval, TransactionStatus, UserRole
from app.banking.schemas import TransactionCreate, TransactionResponse, AccountResponse
from app.rbac.enforcement import get_current_user, check_permission, check_ztna
from app.core.ztna import ztna_risk_engine
from app.logging.audit import audit_logger
from typing import List

router = APIRouter(prefix="/banking", tags=["banking"])

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
    from_account = db.query(Account).filter(Account.user_id == user.id).first() # Simplified for demo
    to_account = db.query(Account).filter(Account.account_number == trans_in.to_account_number).first()
    
    if not from_account or not to_account:
        raise HTTPException(status_code=404, detail="Account not found")
        
    if from_account.status == "FROZEN":
        raise HTTPException(status_code=403, detail="Your account is frozen. Transactions are blocked.")

    if from_account.balance < trans_in.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # 3. Idempotency Check
    existing_trans = db.query(Transaction).filter(Transaction.idempotency_key == trans_in.idempotency_key).first()
    if existing_trans:
        return existing_trans

    # 4. ZTNA Risk Assessment on Transaction
    # Use real-time header if provided, fall back to "unknown"
    fp = x_device_fingerprint or "unknown"
    risk_score, reasons = ztna_risk_engine.calculate_risk(user, fp, request.client.host, trans_in.amount, db=db)
    action = ztna_risk_engine.get_action_for_risk(risk_score)
    
    if action == "DENY":
        raise HTTPException(status_code=403, detail=f"Transaction blocked by ZTNA: High Risk Activity ({', '.join(reasons)})")
    
    if action == "STEP_UP_MFA":
        raise HTTPException(status_code=403, detail=f"ZTNA: Step-up MFA verification required ({', '.join(reasons)})")

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
    
    audit_logger.log_action(db, user.id, "TRANSFER_INITIATE", "TRANSACTION", {
        "transaction_id": new_trans.id,
        "amount": trans_in.amount,
        "status": new_trans.status
    })
        
    return new_trans

@router.get("/approvals", response_model=List[dict])
def get_pending_approvals(
    db: Session = Depends(get_db),
    user: User = Depends(check_ztna)
):
    if user.role not in [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD]:
        raise HTTPException(status_code=403, detail="Not authorized to view approvals")
        
    audit_logger.log_action(db, user.id, "VIEW_APPROVALS", "APPROVAL", {"role": user.role})
    return db.query(Approval).filter(Approval.required_role == user.role, Approval.status == TransactionStatus.PENDING).all()

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
    ).order_by(Transaction.timestamp.desc()).limit(10).all()
    
    return transactions
