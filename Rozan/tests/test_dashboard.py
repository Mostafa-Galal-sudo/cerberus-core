"""Tests for the SOC dashboard static serving."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import create_app


@pytest.fixture()
def client(tmp_path):
    return create_app(str(tmp_path / "dash.db")).test_client()


def test_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "CERBERUS" in html
    assert "app.js" in html


def test_static_assets_served(client):
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200


def test_missing_asset_404(client):
    assert client.get("/nonexistent.js").status_code == 404


def test_api_routes_not_shadowed(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    assert "alerts" in resp.get_json()
