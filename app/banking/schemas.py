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
    amount: float
    status: TransactionStatus
    timestamp: datetime

    class Config:
        from_attributes = True

class AccountResponse(BaseModel):
    account_number: str
    balance: float
    status: str

    class Config:
        from_attributes = True
