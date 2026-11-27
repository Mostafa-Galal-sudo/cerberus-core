import pytest

from src.policy import ActionRequest, ApprovedDecision, PolicyEngine


@pytest.fixture
def pol(tmp_path):
    return PolicyEngine(audit_path=tmp_path / "audit.jsonl")


def req(**kw):
    base = dict(actor="defense_agent", action="block_device", target="esp32-05",
                params={"duration_s": 300}, confidence=0.9)
    base.update(kw)
    return ActionRequest(**base)


def test_allows_valid_action(pol):
    d = pol.evaluate(req())
    assert d.allowed and d.token is not None


@pytest.mark.parametrize("kw,needle", [
    (dict(action="format_disk"), "allowlist"),
    (dict(target="esp32-99"), "out of scope"),
    (dict(target="broker"), "out of scope"),
    (dict(params={"duration_s": 99999}), "outside"),
    (dict(params={}), "missing"),
    (dict(params={"duration_s": 60, "evil": 1}), "unexpected"),
    (dict(confidence=0.5), "below minimum"),
    (dict(actor="nobody"), "unknown actor"),
    (dict(actor="attack_agent"), "allowlist"),
])
def test_denials(pol, kw, needle):
    d = pol.evaluate(req(**kw))
    assert not d.allowed and needle in d.reason and d.token is None


def test_rate_limit(pol):
    for _ in range(10):
        assert pol.evaluate(req(action="notify_only", params={}, confidence=0)).allowed
    assert "rate limit" in pol.evaluate(req(action="notify_only", params={}, confidence=0)).reason


def test_token_single_use_and_no_forgery(pol):
    d = pol.evaluate(req())
    assert pol.consume(d.token, "defense_agent").target == "esp32-05"
    with pytest.raises(PermissionError):
        pol.consume(d.token)                       # replay
    with pytest.raises(PermissionError):
        ApprovedDecision(object(), "DEC-x", req())  # cannot mint
    with pytest.raises(PermissionError):
        pol.consume("block esp32-05")              # not a token
    other = PolicyEngine(audit_path=pol.audit_path)
    with pytest.raises(PermissionError):
        other.consume(pol.evaluate(req()).token)   # token from a different engine


def test_actor_mismatch(pol):
    d = pol.evaluate(req())
    with pytest.raises(PermissionError):
        pol.consume(d.token, "attack_agent")


def test_audit_log_written(pol):
    pol.evaluate(req()); pol.evaluate(req(action="nope"))
    assert len(pol.audit_path.read_text().splitlines()) == 2
