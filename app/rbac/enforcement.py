from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User
from app.core.config import settings
from app.rbac.policies import has_permission
from app.core.ztna import ztna_risk_engine
from fastapi import Request, Header

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def check_permission(permission: str):
    def decorator(user: User = Depends(get_current_user)):
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} required"
            )
        return user
    return decorator

def check_ztna(
    request: Request,
    user: User = Depends(get_current_user),
    x_device_fingerprint: str = Header(None, alias="X-Device-Fingerprint"),
    db: Session = Depends(get_db)
):
    # Enforce continuous verification
    # If fingerprint is missing for a staff action, we consider it high risk or invalid
    if not x_device_fingerprint:
        # For demo purposes, we'll allow but log a warning if missing, 
        # but for employees, we should be stricter.
        x_device_fingerprint = "unknown"

    risk_score, reasons = ztna_risk_engine.calculate_risk(
        user=user,
        device_fingerprint=x_device_fingerprint,
        current_ip=request.client.host,
        db=db
    )
    
    action = ztna_risk_engine.get_action_for_risk(risk_score)
    
    if action == "DENY":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access blocked by ZTNA: High Risk Activity ({', '.join(reasons)})"
        )
    elif action == "STEP_UP_MFA":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ZTNA: Step-up MFA required ({', '.join(reasons)})"
        )
    
    return user
