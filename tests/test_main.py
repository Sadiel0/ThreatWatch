import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_get_blacklist_returns_list():
    response = client.get("/api/ips/blacklist")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_get_blacklist_ip_has_required_fields():
    response = client.get("/api/ips/blacklist")
    assert response.status_code == 200
    ip = response.json()[0]
    assert "ip" in ip
    assert "abuse_confidence_score" in ip
    assert "severity" in ip


def test_get_blacklist_severity_values():
    response = client.get("/api/ips/blacklist")
    assert response.status_code == 200
    valid_severities = {"critical", "high", "medium", "low", "unknown"}
    for ip in response.json():
        assert ip["severity"] in valid_severities


def test_get_pulses_returns_list():
    response = client.get("/api/threats/pulses")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_get_pulses_has_required_fields():
    response = client.get("/api/threats/pulses")
    assert response.status_code == 200
    pulse = response.json()[0]
    assert "id" in pulse
    assert "name" in pulse
    assert "severity" in pulse


def test_root_returns_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
