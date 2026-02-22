from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, Device, Account
from app.auth.schemas import UserCreate, UserResponse, LoginRequest, Token, MFAVerify
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.ztna import ztna_risk_engine
from app.rbac.enforcement import get_current_user
from app.logging.audit import audit_logger
import uuid

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user_in.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Determine role based on special code
    assigned_role = UserRole.CUSTOMER
    if user_in.special_code == "EMPLOYEE_2026":
        assigned_role = UserRole.TELLER
    elif user_in.special_code == "MANAGER_2026":
        assigned_role = UserRole.BRANCH_HEAD
    elif user_in.special_code == "ADMIN_2026":
        # Security Hardening: Only allow a SINGLE super_admin in the entire system
        existing_admin = db.query(User).filter(User.role == UserRole.SUPER_ADMIN).first()
        if existing_admin:
            raise HTTPException(status_code=403, detail="ZTNA Protocol: Global Root Limit reached. Only one Super Admin is permitted.")
        assigned_role = UserRole.SUPER_ADMIN
    
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=assigned_role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create a default account ONLY for Customers
    if assigned_role == UserRole.CUSTOMER:
        new_account = Account(
            account_number=str(uuid.uuid4().hex[:10]).upper(),
            user_id=new_user.id,
            balance=900000.0
        )
        db.add(new_account)
        db.commit()
    
    audit_logger.log_action(db, new_user.id, "REGISTER", "USER", {
        "username": new_user.username,
        "role": assigned_role.value
    })
    
    return new_user

import random
from datetime import timedelta

@router.post("/login")
def login(login_req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_req.username).first()
    if not user or not verify_password(login_req.password, user.hashed_password):
        if user:
            audit_logger.log_action(db, user.id, "LOGIN_FAILED", "AUTH", {"fingerprint": login_req.fingerprint, "reason": "invalid_credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # ZTNA Check
    risk_score, reasons = ztna_risk_engine.calculate_risk(user, login_req.fingerprint, "127.0.0.1", db=db)
    
    # Log detected behavioral anomalies for administrative oversight
    if any("Rapid Successive Login" in r for r in reasons):
        audit_logger.log_action(db, user.id, "CONCURRENT_LOGIN_ATTEMPT", "AUTH", {"fingerprint": login_req.fingerprint, "risk_score": risk_score})
    
    if any("Brute Force Detected" in r for r in reasons):
        audit_logger.log_action(db, user.id, "BRUTE_FORCE_DETECTED", "AUTH", {"reasons": reasons})

    action = ztna_risk_engine.get_action_for_risk(risk_score)
    
    if action == "DENY":
        audit_logger.log_action(db, user.id, "LOGIN_DENIED", "AUTH", {"risk_score": risk_score, "reasons": reasons})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied by ZTNA policy: {', '.join(reasons)}")
    
    # Industry Standard: Generate and save dynamic OTP
    otp = str(random.randint(100000, 999999))
    user.current_otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.commit()
    
    # In a real app, send OTP via SMS/Email. For demo, we log it.
    print(f"DEBUG: MFA OTP for {user.username}: {otp}")
    
    audit_logger.log_action(db, user.id, "LOGIN_PHASE_1", "AUTH", {"fingerprint": login_req.fingerprint, "risk_score": risk_score})
    
    return {
        "status": "MFA_REQUIRED",
        "detail": "Multi-Factor Authentication required",
        "username": user.username,
        "demo_otp_hint": otp # Optional: Give hint for easier testing
    }

@router.post("/mfa/verify", response_model=Token)
def mfa_verify(mfa_req: MFAVerify, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == mfa_req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify OTP and Expiry
    if not user.current_otp or user.current_otp != mfa_req.otp:
        audit_logger.log_action(db, user.id, "MFA_FAILED", "AUTH", {"otp_tried": mfa_req.otp, "reason": "invalid_code"})
        raise HTTPException(status_code=401, detail="Invalid security code")
        
    if user.otp_expiry < datetime.utcnow():
        audit_logger.log_action(db, user.id, "MFA_FAILED", "AUTH", {"otp_tried": mfa_req.otp, "reason": "expired"})
        raise HTTPException(status_code=401, detail="Security code has expired")
    
    # Clear OTP after successful use
    user.current_otp = None
    user.otp_expiry = None
    
    # Record trusted device upon successful MFA
    device = db.query(Device).filter(Device.user_id == user.id, Device.fingerprint == mfa_req.fingerprint).first()
    if not device:
        device = Device(user_id=user.id, fingerprint=mfa_req.fingerprint, is_trusted=True)
        db.add(device)
    else:
        device.is_trusted = True
    
    db.commit()

    access_token = create_access_token(subject=user.username)
    audit_logger.log_action(db, user.id, "LOGIN_SUCCESS", "AUTH", {"fingerprint": mfa_req.fingerprint})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user)):
    return user
