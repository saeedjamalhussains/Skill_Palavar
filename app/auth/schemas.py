from pydantic import BaseModel, EmailStr
from typing import Optional, List
from app.db.models import UserRole

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole = UserRole.CUSTOMER

class UserCreate(UserBase):
    password: str
    special_code: Optional[str] = None

class UserResponse(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    fingerprint: str # Device fingerprint for ZTNA

class MFAVerify(BaseModel):
    username: str
    otp: str
    fingerprint: str
