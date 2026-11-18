"""Tests for the push-alerting module (network calls mocked)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import alerting
from backend.alerting import (
    AlertDispatcher,
    TelegramNotifier,
    WebhookNotifier,
    format_alert_message,
)


@pytest.fixture()
def alert():
    return {
        "id": 7, "device_id": "cam-1", "attack_class": "DoS",
        "source_label": "Sim-MQTT_Flood", "confidence": 0.98,
        "explanation": ["[shap] raw IF score 0.31 driven by: Rate (+0.40)",
                        "flood_rate: Rate=200000"],
    }


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {"ok": True}
        self.text = str(self._body)

    def json(self):
        return self._body


def test_format_alert_message(alert):
    msg = format_alert_message(alert)
    assert "CERBERUS alert #7" in msg
    assert "cam-1" in msg
    assert "DoS" in msg
    assert "0.98" in msg
    assert "Rate (+0.40)" in msg  # explanation included


def test_telegram_send(monkeypatch, alert):
    calls = []
    monkeypatch.setattr(alerting.requests, "post",
                        lambda url, **k: calls.append((url, k)) or FakeResponse())
    notifier = TelegramNotifier(token="tok", chat_id="chat1", min_interval=0)
    assert notifier.send(alert) is True
    assert len(calls) == 1
    assert calls[0][0].endswith("/bottok/sendMessage")
    assert calls[0][1]["json"]["chat_id"] == "chat1"
    assert "CERBERUS" in calls[0][1]["json"]["text"]


def test_telegram_rate_limit_drops(alert):
    notifier = TelegramNotifier(token="tok", chat_id="chat", min_interval=60)
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(1)
        return FakeResponse()

    alerting.requests.post = fake_post
    assert notifier.send(alert) is True
    assert notifier.send(alert) is False  # within min_interval -> dropped
    assert len(calls) == 1


def test_telegram_unconfigured_is_noop(alert):
    notifier = TelegramNotifier(token="", chat_id="")
    assert notifier.configured is False
    assert notifier.send(alert) is False


def test_telegram_network_failure_graceful(monkeypatch, alert):
    class Boom:
        def post(self, *a, **k):
            raise alerting.requests.ConnectionError("down")

    monkeypatch.setattr(alerting.requests, "post", Boom().post)
    notifier = TelegramNotifier(token="t", chat_id="c", min_interval=0)
    assert notifier.send(alert) is False  # never raises


def test_telegram_rejection(monkeypatch, alert):
    monkeypatch.setattr(alerting.requests, "post",
                        lambda *a, **k: FakeResponse(status_code=403, body={"ok": False}))
    notifier = TelegramNotifier(token="t", chat_id="c", min_interval=0)
    assert notifier.send(alert) is False


def test_webhook_notifier(monkeypatch, alert):
    calls = []
    monkeypatch.setattr(alerting.requests, "post",
                        lambda url, **k: calls.append(url) or FakeResponse())
    notifier = WebhookNotifier(urls=["http://hook/1", "http://hook/2"])
    assert notifier.send(alert) is True
    assert calls == ["http://hook/1", "http://hook/2"]


def test_webhook_unconfigured(alert):
    notifier = WebhookNotifier(urls=[])
    assert notifier.send(alert) is False


def test_dispatcher_fanout(monkeypatch, alert):
    class Counting(alerting.Notifier):
        def __init__(self, n):
            self.n = n
            self.seen = 0

        def send(self, a):
            self.seen += 1
            return True

    a, b = Counting(1), Counting(2)
    results = AlertDispatcher([a, b]).dispatch([alert, alert, alert])
    assert [r["sent"] for r in results] == [3, 3]
    assert [r["total"] for r in results] == [3, 3]
    assert a.seen == 3 and b.seen == 3


def test_dispatcher_with_real_notifiers_unconfigured(monkeypatch, alert):
    monkeypatch.setattr(alerting.config, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(alerting.config, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(alerting.config, "WEBHOOK_URLS", [])
    results = AlertDispatcher().dispatch([alert])
    assert [r["sent"] for r in results] == [0, 0]
