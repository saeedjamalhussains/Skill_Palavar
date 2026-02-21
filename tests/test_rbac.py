from app.rbac.policies import has_permission
from app.db.models import UserRole

def test_rbac_customer_permissions():
    assert has_permission(UserRole.CUSTOMER, "VIEW_BALANCE") is True
    assert has_permission(UserRole.CUSTOMER, "INITIATE_TRANSFER") is True
