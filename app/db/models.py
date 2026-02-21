from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    CENTRAL_HEAD = "central_head"
    REGIONAL_HEAD = "regional_head"
    BRANCH_HEAD = "branch_head"
    OPS_MANAGER = "ops_manager"
    TELLER = "teller"
    CUSTOMER = "customer"

class TransactionStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SQLEnum(UserRole), default=UserRole.CUSTOMER)
    is_active = Column(Boolean, default=True)
    mfa_secret = Column(String, nullable=True)
    current_otp = Column(String, nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    avatar_url = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    branch_id = Column(String, nullable=True, index=True)
    region_id = Column(String, nullable=True, index=True)
    last_login_at = Column(DateTime, default=datetime.utcnow)
    
    accounts = relationship("Account", back_populates="owner")
    devices = relationship("Device", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    fingerprint = Column(String, index=True)
    is_trusted = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    last_ip = Column(String, nullable=True)
    location_city = Column(String, nullable=True)
    trust_score = Column(Float, default=1.0)
    
    user = relationship("User", back_populates="devices")

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    account_number = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    balance = Column(Float, default=0.0)
    status = Column(String, default="ACTIVE") # ACTIVE, FROZEN, MONITORED
    daily_limit = Column(Float, default=1000000.0) # Default 10 Lakh
    
    owner = relationship("User", back_populates="accounts")
    transactions_from = relationship("Transaction", foreign_keys="Transaction.from_account_id")
    transactions_to = relationship("Transaction", foreign_keys="Transaction.to_account_id")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    from_account_id = Column(Integer, ForeignKey("accounts.id"))
    to_account_id = Column(Integer, ForeignKey("accounts.id"))
    amount = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    risk_score = Column(Float, default=0.0)
    idempotency_key = Column(String, unique=True, index=True)

class Approval(Base):
    __tablename__ = "approvals"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"))
    required_role = Column(SQLEnum(UserRole))
    assigned_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    comments = Column(String, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String)
    resource = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    context = Column(String) # JSON or descriptive string
    
    user = relationship("User", back_populates="audit_logs")
