import pytest
from app.core.ztna import ztna_risk_engine
from app.db.models import User, Device

def test_risk_engine_new_device():
    user = User(id=1, devices=[])
    risk = ztna_risk_engine.calculate_risk(user, "new_fingerprint", "127.0.0.1")
    assert risk >= 0.4 # New device risk
    assert ztna_risk_engine.get_action_for_risk(risk) == "STEP_UP_MFA"

def test_risk_engine_trusted_device():
    device = Device(fingerprint="trusted_one", is_trusted=True)
    user = User(id=1, devices=[device])
    risk = ztna_risk_engine.calculate_risk(user, "trusted_one", "127.0.0.1")
    assert risk < 0.2 # Low risk for trusted device
    assert ztna_risk_engine.get_action_for_risk(risk) == "ALLOW"
