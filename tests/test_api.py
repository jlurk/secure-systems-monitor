"""Comprehensive test suite for the Secure Systems Monitor API.

Covers: authentication, RBAC enforcement, event/alert/metric CRUD,
dashboard aggregation, admin user management, and edge cases.
"""

from fastapi.testclient import TestClient

from app.main import app
from app.store import alert_store, event_store, metric_store, user_store

client = TestClient(app)

# ── Test data ───────────────────────────────────────────────────

ADMIN_USER = {"username": "adminuser", "password": "admin1234", "role": "admin"}
ANALYST_USER = {"username": "analystuser", "password": "analyst1234", "role": "analyst"}
VIEWER_USER = {"username": "vieweruser", "password": "viewer1234", "role": "viewer"}

SAMPLE_EVENT = {
    "source_ip": "192.168.1.100",
    "category": "authentication",
    "severity": "warning",
    "message": "Failed SSH login attempt from unknown host",
}


# ── Helpers ─────────────────────────────────────────────────────


def setup_function():
    """Reset all stores before each test."""
    user_store.reset()
    event_store.reset()
    alert_store.reset()
    metric_store.reset()


def _register(user: dict = ANALYST_USER) -> dict:
    resp = client.post("/register", json=user)
    assert resp.status_code == 201
    return resp.json()


def _login(user: dict = ANALYST_USER) -> str:
    """Register + login a user, return the Bearer token string."""
    _register(user)
    resp = client.post(
        "/token", data={"username": user["username"], "password": user["password"]}
    )
    assert resp.status_code == 200
    return f"Bearer {resp.json()['access_token']}"


def _auth_header(user: dict = ANALYST_USER) -> dict:
    return {"Authorization": _login(user)}


def _create_event(headers: dict) -> dict:
    """Create a sample event and return the response JSON."""
    resp = client.post("/events", json=SAMPLE_EVENT, headers=headers)
    assert resp.status_code == 201
    return resp.json()


# ═══════════════════════════════════════════════════════════════
#  ROOT / HEALTH CHECK
# ═══════════════════════════════════════════════════════════════


def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Secure Systems Monitor" in resp.json()["message"]


# ═══════════════════════════════════════════════════════════════
#  REGISTRATION
# ═══════════════════════════════════════════════════════════════


def test_register_success():
    data = _register(ANALYST_USER)
    assert data["username"] == "analystuser"
    assert data["role"] == "analyst"
    assert data["id"] == 1


def test_register_default_role_is_viewer():
    resp = client.post(
        "/register", json={"username": "newuser", "password": "password1234"}
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"


def test_register_duplicate_username():
    _register(ANALYST_USER)
    resp = client.post("/register", json=ANALYST_USER)
    assert resp.status_code == 409


def test_register_short_username():
    resp = client.post("/register", json={"username": "ab", "password": "password1234"})
    assert resp.status_code == 422


def test_register_short_password():
    resp = client.post("/register", json={"username": "validuser", "password": "short"})
    assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════
#  LOGIN / TOKEN
# ═══════════════════════════════════════════════════════════════


def test_login_success():
    _register(ANALYST_USER)
    resp = client.post(
        "/token",
        data={"username": ANALYST_USER["username"], "password": ANALYST_USER["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_login_wrong_password():
    _register(ANALYST_USER)
    resp = client.post(
        "/token", data={"username": ANALYST_USER["username"], "password": "wrongpassword"}
    )
    assert resp.status_code == 401


def test_login_nonexistent_user():
    resp = client.post("/token", data={"username": "ghost", "password": "nope12345"})
    assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════
#  AUTHENTICATION REQUIRED
# ═══════════════════════════════════════════════════════════════


def test_endpoints_require_auth():
    """All protected endpoints return 401 without a token."""
    assert client.get("/events").status_code == 401
    assert client.post("/events", json=SAMPLE_EVENT).status_code == 401
    assert client.get("/alerts").status_code == 401
    assert client.get("/metrics").status_code == 401
    assert client.get("/dashboard").status_code == 401
    assert client.get("/admin/users").status_code == 401


def test_bad_token_rejected():
    headers = {"Authorization": "Bearer invalid.token.here"}
    assert client.get("/events", headers=headers).status_code == 401


# ═══════════════════════════════════════════════════════════════
#  RBAC – ROLE-BASED ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════


def test_viewer_cannot_create_event():
    """Viewers are read-only – they cannot create events."""
    headers = _auth_header(VIEWER_USER)
    resp = client.post("/events", json=SAMPLE_EVENT, headers=headers)
    assert resp.status_code == 403


def test_viewer_can_read_events():
    # First create event as analyst
    analyst_headers = _auth_header(ANALYST_USER)
    _create_event(analyst_headers)

    # Register + login viewer (analyst is already registered from above helper)
    client.post("/register", json=VIEWER_USER)
    resp = client.post(
        "/token",
        data={"username": VIEWER_USER["username"], "password": VIEWER_USER["password"]},
    )
    viewer_headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

    resp = client.get("/events", headers=viewer_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_analyst_can_create_event():
    headers = _auth_header(ANALYST_USER)
    resp = client.post("/events", json=SAMPLE_EVENT, headers=headers)
    assert resp.status_code == 201


def test_admin_can_create_event():
    """Admin is higher than analyst, so creation should succeed."""
    headers = _auth_header(ADMIN_USER)
    resp = client.post("/events", json=SAMPLE_EVENT, headers=headers)
    assert resp.status_code == 201


def test_viewer_cannot_create_alert():
    headers = _auth_header(VIEWER_USER)
    resp = client.post("/alerts", json={"event_id": 1, "title": "Test"}, headers=headers)
    assert resp.status_code == 403


def test_viewer_cannot_record_metric():
    headers = _auth_header(VIEWER_USER)
    resp = client.post(
        "/metrics", json={"name": "cpu", "value": 50.0, "unit": "percent"}, headers=headers
    )
    assert resp.status_code == 403


def test_analyst_cannot_delete_alert():
    """Only admins can delete alerts."""
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    client.post(
        "/alerts",
        json={"event_id": event["id"], "title": "Alert"},
        headers=headers,
    )
    resp = client.delete("/alerts/1", headers=headers)
    assert resp.status_code == 403


def test_admin_can_delete_alert():
    admin_headers = _auth_header(ADMIN_USER)
    event = _create_event(admin_headers)
    client.post(
        "/alerts",
        json={"event_id": event["id"], "title": "Alert"},
        headers=admin_headers,
    )
    resp = client.delete("/alerts/1", headers=admin_headers)
    assert resp.status_code == 204


# ═══════════════════════════════════════════════════════════════
#  EVENT CRUD
# ═══════════════════════════════════════════════════════════════


def test_create_event_full():
    headers = _auth_header(ANALYST_USER)
    payload = {
        "source_ip": "10.0.0.1",
        "category": "network",
        "severity": "critical",
        "message": "Port scan detected",
        "metadata": {"ports": [22, 80, 443]},
    }
    resp = client.post("/events", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["source_ip"] == "10.0.0.1"
    assert data["severity"] == "critical"
    assert data["metadata"] == {"ports": [22, 80, 443]}


def test_list_events_filter_by_severity():
    headers = _auth_header(ANALYST_USER)
    client.post(
        "/events",
        json={**SAMPLE_EVENT, "severity": "info", "message": "Info event"},
        headers=headers,
    )
    client.post(
        "/events",
        json={**SAMPLE_EVENT, "severity": "critical", "message": "Critical event"},
        headers=headers,
    )
    resp = client.get("/events", params={"severity": "critical"}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["severity"] == "critical"


def test_list_events_filter_by_category():
    headers = _auth_header(ANALYST_USER)
    client.post(
        "/events",
        json={**SAMPLE_EVENT, "category": "network", "message": "Net event"},
        headers=headers,
    )
    client.post(
        "/events",
        json={**SAMPLE_EVENT, "category": "process", "message": "Proc event"},
        headers=headers,
    )
    resp = client.get("/events", params={"category": "process"}, headers=headers)
    assert len(resp.json()) == 1
    assert resp.json()[0]["category"] == "process"


def test_get_event_by_id():
    headers = _auth_header(ANALYST_USER)
    created = _create_event(headers)
    resp = client.get(f"/events/{created['id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_get_event_not_found():
    headers = _auth_header(ANALYST_USER)
    resp = client.get("/events/999", headers=headers)
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  ALERT CRUD
# ═══════════════════════════════════════════════════════════════


def test_create_alert():
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    resp = client.post(
        "/alerts",
        json={"event_id": event["id"], "title": "Suspicious activity", "description": "Investigate"},
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Suspicious activity"
    assert data["status"] == "open"
    assert data["event_id"] == event["id"]


def test_create_alert_invalid_event():
    headers = _auth_header(ANALYST_USER)
    resp = client.post(
        "/alerts",
        json={"event_id": 999, "title": "Ghost alert"},
        headers=headers,
    )
    assert resp.status_code == 404


def test_list_alerts_filter_by_status():
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    client.post("/alerts", json={"event_id": event["id"], "title": "A1"}, headers=headers)
    client.post("/alerts", json={"event_id": event["id"], "title": "A2"}, headers=headers)
    # Acknowledge alert 1
    client.put("/alerts/1", json={"status": "acknowledged"}, headers=headers)

    resp = client.get("/alerts", params={"status": "open"}, headers=headers)
    assert len(resp.json()) == 1
    assert resp.json()[0]["title"] == "A2"


def test_update_alert_status():
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    client.post("/alerts", json={"event_id": event["id"], "title": "Alert"}, headers=headers)

    resp = client.put("/alerts/1", json={"status": "resolved"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


def test_update_alert_not_found():
    headers = _auth_header(ANALYST_USER)
    resp = client.put("/alerts/999", json={"status": "resolved"}, headers=headers)
    assert resp.status_code == 404


def test_get_alert_by_id():
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    client.post("/alerts", json={"event_id": event["id"], "title": "Alert"}, headers=headers)
    resp = client.get("/alerts/1", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Alert"


def test_get_alert_not_found():
    headers = _auth_header(ANALYST_USER)
    resp = client.get("/alerts/999", headers=headers)
    assert resp.status_code == 404


def test_delete_alert_not_found():
    headers = _auth_header(ADMIN_USER)
    resp = client.delete("/alerts/999", headers=headers)
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  METRIC CRUD
# ═══════════════════════════════════════════════════════════════


def test_record_metric():
    headers = _auth_header(ANALYST_USER)
    resp = client.post(
        "/metrics",
        json={"name": "cpu_usage", "value": 72.5, "unit": "percent"},
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "cpu_usage"
    assert data["value"] == 72.5


def test_list_metrics_filter_by_name():
    headers = _auth_header(ANALYST_USER)
    client.post("/metrics", json={"name": "cpu_usage", "value": 50, "unit": "percent"}, headers=headers)
    client.post("/metrics", json={"name": "mem_usage", "value": 4096, "unit": "MB"}, headers=headers)

    resp = client.get("/metrics", params={"name": "cpu_usage"}, headers=headers)
    assert len(resp.json()) == 1
    assert resp.json()[0]["name"] == "cpu_usage"


def test_get_metric_by_id():
    headers = _auth_header(ANALYST_USER)
    client.post("/metrics", json={"name": "disk_io", "value": 120, "unit": "MB/s"}, headers=headers)
    resp = client.get("/metrics/1", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "disk_io"


def test_get_metric_not_found():
    headers = _auth_header(ANALYST_USER)
    resp = client.get("/metrics/999", headers=headers)
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════════════


def test_dashboard_empty():
    headers = _auth_header(ANALYST_USER)
    resp = client.get("/dashboard", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 0
    assert data["total_alerts"] == 0
    assert data["total_metrics"] == 0
    assert data["open_alerts"] == 0


def test_dashboard_aggregation():
    headers = _auth_header(ANALYST_USER)

    # Create events
    client.post("/events", json={**SAMPLE_EVENT, "severity": "info", "message": "E1"}, headers=headers)
    client.post("/events", json={**SAMPLE_EVENT, "severity": "critical", "message": "E2"}, headers=headers)
    client.post("/events", json={**SAMPLE_EVENT, "severity": "critical", "message": "E3"}, headers=headers)

    # Create alerts
    client.post("/alerts", json={"event_id": 1, "title": "A1"}, headers=headers)
    client.post("/alerts", json={"event_id": 2, "title": "A2"}, headers=headers)
    client.put("/alerts/1", json={"status": "acknowledged"}, headers=headers)

    # Create metric
    client.post("/metrics", json={"name": "cpu", "value": 90, "unit": "percent"}, headers=headers)

    resp = client.get("/dashboard", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 3
    assert data["events_by_severity"]["critical"] == 2
    assert data["events_by_severity"]["info"] == 1
    assert data["total_alerts"] == 2
    assert data["open_alerts"] == 1
    assert data["acknowledged_alerts"] == 1
    assert data["total_metrics"] == 1
    assert len(data["recent_events"]) <= 5


# ═══════════════════════════════════════════════════════════════
#  ADMIN: USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════


def test_admin_list_users():
    admin_headers = _auth_header(ADMIN_USER)
    # Register a second user
    client.post("/register", json=VIEWER_USER)

    resp = client.get("/admin/users", headers=admin_headers)
    assert resp.status_code == 200
    users = resp.json()
    assert len(users) == 2
    # Ensure password hash is NOT exposed
    for u in users:
        assert "hashed_password" not in u


def test_viewer_cannot_list_users():
    headers = _auth_header(VIEWER_USER)
    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403


def test_analyst_cannot_list_users():
    headers = _auth_header(ANALYST_USER)
    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403


def test_admin_delete_user():
    admin_headers = _auth_header(ADMIN_USER)
    client.post("/register", json=VIEWER_USER)

    # Delete the viewer (id=2)
    resp = client.delete("/admin/users/2", headers=admin_headers)
    assert resp.status_code == 204

    # Confirm deletion
    resp = client.get("/admin/users", headers=admin_headers)
    assert len(resp.json()) == 1


def test_admin_cannot_delete_self():
    admin_headers = _auth_header(ADMIN_USER)
    resp = client.delete("/admin/users/1", headers=admin_headers)
    assert resp.status_code == 400


def test_admin_delete_nonexistent_user():
    admin_headers = _auth_header(ADMIN_USER)
    resp = client.delete("/admin/users/999", headers=admin_headers)
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  EDGE CASES & VALIDATION
# ═══════════════════════════════════════════════════════════════


def test_create_event_empty_message_rejected():
    headers = _auth_header(ANALYST_USER)
    payload = {**SAMPLE_EVENT, "message": ""}
    resp = client.post("/events", json=payload, headers=headers)
    assert resp.status_code == 422


def test_create_alert_empty_title_rejected():
    headers = _auth_header(ANALYST_USER)
    event = _create_event(headers)
    resp = client.post(
        "/alerts", json={"event_id": event["id"], "title": ""}, headers=headers
    )
    assert resp.status_code == 422


def test_create_metric_missing_unit_rejected():
    headers = _auth_header(ANALYST_USER)
    resp = client.post("/metrics", json={"name": "cpu", "value": 50}, headers=headers)
    assert resp.status_code == 422


def test_invalid_severity_rejected():
    headers = _auth_header(ANALYST_USER)
    payload = {**SAMPLE_EVENT, "severity": "apocalyptic"}
    resp = client.post("/events", json=payload, headers=headers)
    assert resp.status_code == 422


def test_invalid_category_rejected():
    headers = _auth_header(ANALYST_USER)
    payload = {**SAMPLE_EVENT, "category": "alien_invasion"}
    resp = client.post("/events", json=payload, headers=headers)
    assert resp.status_code == 422
