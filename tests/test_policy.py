from __future__ import annotations

import pytest

from src.policy import PolicyDeniedError, PolicyGate, RateLimiter
from src.storage.db import open_db


def test_policy_allows_valid_defense_and_attack_actions(tmp_path):
    conn = open_db(tmp_path / "policy.db")
    try:
        gate = PolicyGate(conn=conn, log_path=tmp_path / "audit.jsonl")

        d1 = gate.authorize("defense", "isolate_device", "esp32_temp_01")
        assert d1.allowed is True

        d2 = gate.authorize(
            "attack",
            "attack_flood",
            "esp32_plug_01",
            context={"topic": "lab/room1/power"},
        )
        assert d2.allowed is True

        rows = gate.audit.query()
        assert len(rows) == 2
        assert all(r["verdict"] == "ALLOW" for r in rows)
        assert (tmp_path / "audit.jsonl").exists()
    finally:
        conn.close()


def test_policy_blocks_cross_role_and_unknown_actions(tmp_path):
    conn = open_db(tmp_path / "policy_deny.db")
    try:
        gate = PolicyGate(conn=conn)

        assert gate.authorize("attack", "isolate_device", "esp32_temp_01").allowed is False
        assert gate.authorize("defense", "attack_flood", "esp32_temp_01").allowed is False
        assert gate.authorize("defense", "drop_database", "esp32_temp_01").allowed is False
        assert gate.authorize("rogue_actor", "isolate_device", "esp32_temp_01").allowed is False

        with pytest.raises(PolicyDeniedError):
            gate.require("attack", "isolate_device", "esp32_temp_01")

        rows = gate.audit.query(verdict="DENY")
        assert len(rows) == 5
    finally:
        conn.close()


def test_policy_blocks_wildcards_and_out_of_scope_targets_and_topics(tmp_path):
    conn = open_db(tmp_path / "scope.db")
    try:
        gate = PolicyGate(conn=conn)

        assert gate.authorize("defense", "isolate_device", "*").allowed is False
        assert gate.authorize("defense", "isolate_device", "unknown_prod_host").allowed is False
        assert gate.authorize("defense", "isolate_device", "rogue_node_99").allowed is True
        assert (
            gate.authorize(
                "attack",
                "attack_flood",
                "esp32_temp_01",
                context={"topic": "prod/room1/climate"},
            ).allowed
            is False
        )
        assert (
            gate.authorize(
                "attack",
                "attack_flood",
                "esp32_temp_01",
                context={"topic": "lab/#"},
            ).allowed
            is False
        )
    finally:
        conn.close()


def test_policy_rate_limiter_enforces_window_and_recovers(tmp_path):
    conn = open_db(tmp_path / "ratelimit.db")
    try:
        limiter = RateLimiter(limits={"attack_flood": (2, 60.0)})
        gate = PolicyGate(conn=conn, ratelimiter=limiter)

        assert gate.authorize("attack", "attack_flood", "esp32_temp_01", now=100.0).allowed is True
        assert gate.authorize("attack", "attack_flood", "esp32_temp_01", now=110.0).allowed is True
        denied = gate.authorize("attack", "attack_flood", "esp32_temp_01", now=120.0)
        assert denied.allowed is False
        assert "rate limit exceeded" in denied.reason

        # After 60s window expires, next call succeeds
        assert gate.authorize("attack", "attack_flood", "esp32_temp_01", now=161.0).allowed is True
    finally:
        conn.close()
