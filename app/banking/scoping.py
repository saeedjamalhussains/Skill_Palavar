from app.db.models import User, Account, UserRole, AuditLog, Transaction, Approval
from sqlalchemy import or_

def apply_hierarchical_scoping(query, model, user: User):
    """
    Apply visibility filters based on the banking hierarchy.
    """
    if user.role in [UserRole.SUPER_ADMIN, UserRole.CENTRAL_HEAD]:
        return query
        
    if user.role == UserRole.REGIONAL_HEAD:
        if model == User:
            return query.filter(User.region_id == user.region_id)
        if model == Account:
            return query.join(User).filter(User.region_id == user.region_id)
        if model == AuditLog:
            return query.outerjoin(User).filter(or_(User.region_id == user.region_id, AuditLog.user_id == None))
        if model == Transaction:
            return query.join(Account, Transaction.from_account_id == Account.id).join(User).filter(User.region_id == user.region_id)
        if model == Approval:
            return query.join(Transaction).join(Account, Transaction.from_account_id == Account.id).join(User).filter(User.region_id == user.region_id)
            
    if user.role in [UserRole.BRANCH_HEAD, UserRole.OPS_MANAGER, UserRole.TELLER]:
        if model == User:
            return query.filter(User.branch_id == user.branch_id)
        if model == Account:
            return query.join(User).filter(User.branch_id == user.branch_id)
        if model == AuditLog:
            return query.outerjoin(User).filter(or_(User.branch_id == user.branch_id, AuditLog.user_id == None))
        if model == Transaction:
            return query.join(Account, Transaction.from_account_id == Account.id).join(User).filter(User.branch_id == user.branch_id)
        if model == Approval:
            return query.join(Transaction).join(Account, Transaction.from_account_id == Account.id).join(User).filter(User.branch_id == user.branch_id)

    return query.filter(False)
