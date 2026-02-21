from typing import List, Dict
from app.db.models import UserRole

# Define hierarchy: Higher roles include permissions of lower roles in practice
ROLE_HIERARCHY: Dict[UserRole, int] = {
    UserRole.SUPER_ADMIN: 100,
    UserRole.CENTRAL_HEAD: 80,
    UserRole.REGIONAL_HEAD: 70,
    UserRole.BRANCH_HEAD: 60,
    UserRole.OPS_MANAGER: 50,
    UserRole.TELLER: 40,
    UserRole.CUSTOMER: 10,
}

# Specific permission mapping (simplified for implementation)
PERMISSIONS = {
    "VIEW_BALANCE": [UserRole.CUSTOMER, UserRole.TELLER, UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD],
    "INITIATE_TRANSFER": [UserRole.CUSTOMER, UserRole.TELLER],
    "APPROVE_MEDIUM": [UserRole.BRANCH_HEAD, UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD],
    "APPROVE_HIGH": [UserRole.REGIONAL_HEAD, UserRole.CENTRAL_HEAD],
    "VIEW_AUDIT": [UserRole.CENTRAL_HEAD, UserRole.SUPER_ADMIN],
    "MANAGE_USERS": [UserRole.SUPER_ADMIN],
}

def has_permission(user_role: UserRole, permission: str) -> bool:
    allowed_roles = PERMISSIONS.get(permission, [])
    return user_role in allowed_roles or user_role == UserRole.SUPER_ADMIN
