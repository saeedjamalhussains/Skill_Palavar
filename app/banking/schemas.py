from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.db.models import TransactionStatus

class TransactionCreate(BaseModel):
    to_account_number: str
    amount: float
    idempotency_key: str

class TransactionResponse(BaseModel):
    id: int
    from_account_id: int
    to_account_id: int
    to_user: Optional[str] = None
    to_account_number: Optional[str] = None
    amount: float
    status: TransactionStatus
    timestamp: datetime
    is_debit: Optional[bool] = None

    class Config:
        from_attributes = True

class AccountResponse(BaseModel):
    account_number: str
    balance: float
    status: str

    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    username: str
    email: str
    role: str
    bio: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    pan_number: Optional[str] = None
    date_of_birth: Optional[str] = None
    kyc_status: str

    class Config:
        from_attributes = True

class AccountStatusUpdate(BaseModel):
    status_update: str # ACTIVE, FROZEN, MONITORED

class InteractionEvent(BaseModel):
    element_id: Optional[str] = None
    element_class: Optional[str] = None
    tag_name: str
    text_content: Optional[str] = None
