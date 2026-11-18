"""Push-alerting: Telegram + generic webhook notifiers.

Presentation-layer component. Never raises into the detection pipeline: a
missing token, network failure, or rate-limit drop degrades to a logged
no-op. Telegram messages are rate-limited (Telegram allows ~1 msg/s per
chat); webhooks receive the full alert record as JSON.
"""
from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod

import requests

import config

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"
SEND_TIMEOUT = 10  # seconds


def format_alert_message(alert: dict) -> str:
    """Human-readable Telegram message for one alert record."""
    confidence = alert.get("confidence") or alert.get("fused_score") or 0.0
    lines = [
        f"\U0001F6A8 CERBERUS alert #{alert.get('id', '?')}",
        f"Device: {alert.get('device_id') or 'unknown'}",
        (
            f"Class: {alert.get('attack_class') or 'unknown'}"
            f" ({alert.get('source_label') or 'no label'})"
        ),
        f"Confidence: {float(confidence):.2f}",
    ]
    explanation = alert.get("explanation") or alert.get("reasons") or []
    if explanation:
        lines.append("Why: " + "; ".join(str(e) for e in explanation[:2]))
    return "\n".join(lines)


class Notifier(ABC):
    @abstractmethod
    def send(self, alert: dict) -> bool:
        """Push one alert record. Returns True on success."""


class TelegramNotifier(Notifier):
    def __init__(self, token: str | None = None, chat_id: str | None = None,
                 min_interval: float = 1.1):
        self.token = token if token is not None else config.TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id if chat_id is not None else config.TELEGRAM_CHAT_ID
        self.min_interval = min_interval
        self._last_sent = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, alert: dict) -> bool:
        if not self.configured:
            logger.warning("TelegramNotifier not configured (TELEGRAM_BOT_TOKEN/CHAT_ID)")
            return False
        now = time.monotonic()
        if now - self._last_sent < self.min_interval:
            logger.info("Telegram rate limit: dropped alert %s", alert.get("id"))
            return False
        try:
            resp = requests.post(
                f"{TELEGRAM_API}/bot{self.token}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": format_alert_message(alert),
                },
                timeout=SEND_TIMEOUT,
            )
            ok = resp.status_code == 200 and resp.json().get("ok") is True
        except requests.RequestException as exc:
            logger.error("Telegram send failed: %s", exc)
            return False
        if ok:
            self._last_sent = now
        else:
            logger.error("Telegram rejected message: %s", resp.text[:200])
        return ok


class WebhookNotifier(Notifier):
    def __init__(self, urls: list[str] | None = None):
        self.urls = urls if urls is not None else config.WEBHOOK_URLS

    @property
    def configured(self) -> bool:
        return bool(self.urls)

    def send(self, alert: dict) -> bool:
        if not self.configured:
            logger.info("WebhookNotifier has no URLs configured; skipping")
            return False
        payload = json.dumps(alert, default=str).encode()
        ok = True
        for url in self.urls:
            try:
                resp = requests.post(
                    url, data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=SEND_TIMEOUT,
                )
                ok = ok and resp.status_code < 400
            except requests.RequestException as exc:
                logger.error("Webhook %s failed: %s", url, exc)
                ok = False
        return ok


class AlertDispatcher:
    """Fans alerts out to every configured notifier."""

    def __init__(self, notifiers: list[Notifier] | None = None):
        self.notifiers = notifiers if notifiers is not None else [
            TelegramNotifier(), WebhookNotifier(),
        ]

    def dispatch(self, alerts: list[dict]) -> list[dict]:
        """Send each alert via each notifier.

        Returns one entry per notifier (order preserved): class name, sent
        count, and total attempted.
        """
        results = []
        for notifier in self.notifiers:
            sent = sum(1 for alert in alerts if notifier.send(alert))
            results.append({
                "notifier": type(notifier).__name__,
                "sent": sent,
                "total": len(alerts),
            })
        if alerts:
            logger.info("Dispatched %d alerts: %s", len(alerts), results)
        return results
