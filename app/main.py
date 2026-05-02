"""Secure Systems Monitor – main FastAPI application."""

from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import (
    CurrentUser,
    create_access_token,
    hash_password,
    require_role,
    verify_password,
)
from app.models import (
    AlertCreate,
    AlertResponse,
    AlertStatus,
    AlertUpdate,
    DashboardSummary,
    EventCategory,
    EventCreate,
    EventResponse,
    EventSeverity,
    MetricCreate,
    MetricSnapshot,
    Token,
    UserCreate,
    UserResponse,
    UserRole,
)
from app.store import alert_store, event_store, metric_store, user_store

app = FastAPI(
    title="Secure Systems Monitor API",
    description=(
        "A security-focused monitoring platform with JWT authentication, "
        "role-based access control (RBAC), event logging, alert management, "
        "system metrics collection, and an aggregated dashboard."
    ),
    version="1.0.0",
)


# ── Health check ────────────────────────────────────────────────


@app.get("/")
def root() -> dict:
    """Health-check / welcome endpoint."""
    return {"message": "Secure Systems Monitor API is running", "docs": "/docs"}


# ═══════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════


@app.post("/register", response_model=UserResponse, status_code=201)
def register(data: UserCreate) -> UserResponse:
    """Register a new user account.

    - Default role is **viewer** (read-only).
    - Only admins should assign **analyst** or **admin** roles via their own flows
      in production; this endpoint accepts a role for demonstration purposes.
    """
    if user_store.username_exists(data.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    hashed = hash_password(data.password)
    user = user_store.create(data.username, hashed, role=data.role.value)
    return UserResponse(
        id=user.id, username=user.username, role=user.role, created_at=user.created_at
    )


@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """Authenticate and receive a JWT access token (OAuth2 password flow)."""
    user = user_store.get_by_username(form_data.username)
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=access_token)


# ═══════════════════════════════════════════════════════════════
#  EVENT ENDPOINTS  (analyst+ can create; all authenticated can read)
# ═══════════════════════════════════════════════════════════════


@app.post(
    "/events",
    response_model=EventResponse,
    status_code=201,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
def create_event(data: EventCreate, current_user: CurrentUser) -> EventResponse:
    """Log a new security event. Requires **analyst** role or higher."""
    return event_store.create(data, reported_by=current_user.id)


@app.get("/events", response_model=list[EventResponse])
def list_events(
    current_user: CurrentUser,
    severity: Optional[EventSeverity] = Query(None, description="Filter by severity"),
    category: Optional[EventCategory] = Query(None, description="Filter by category"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
) -> list[EventResponse]:
    """List security events. All authenticated users can read."""
    return event_store.list_all(severity=severity, category=category, limit=limit)


@app.get("/events/{event_id}", response_model=EventResponse)
def get_event(event_id: int, current_user: CurrentUser) -> EventResponse:
    """Get a single event by ID."""
    event = event_store.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


# ═══════════════════════════════════════════════════════════════
#  ALERT ENDPOINTS  (analyst+ can create/update; admin can delete)
# ═══════════════════════════════════════════════════════════════


@app.post(
    "/alerts",
    response_model=AlertResponse,
    status_code=201,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
def create_alert(data: AlertCreate, current_user: CurrentUser) -> AlertResponse:
    """Create an alert linked to an existing event. Requires **analyst** role."""
    # Validate that the referenced event exists
    if event_store.get(data.event_id) is None:
        raise HTTPException(status_code=404, detail="Referenced event not found")
    return alert_store.create(data, created_by=current_user.id)


@app.get("/alerts", response_model=list[AlertResponse])
def list_alerts(
    current_user: CurrentUser,
    status: Optional[AlertStatus] = Query(None, description="Filter by status"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
) -> list[AlertResponse]:
    """List alerts. All authenticated users can read."""
    return alert_store.list_all(status=status, limit=limit)


@app.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, current_user: CurrentUser) -> AlertResponse:
    """Get a single alert by ID."""
    alert = alert_store.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.put(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
def update_alert(alert_id: int, data: AlertUpdate, current_user: CurrentUser) -> AlertResponse:
    """Update an alert (e.g. acknowledge or resolve). Requires **analyst** role."""
    alert = alert_store.update(alert_id, data)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.delete(
    "/alerts/{alert_id}",
    status_code=204,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
def delete_alert(alert_id: int, current_user: CurrentUser) -> None:
    """Delete an alert. Requires **admin** role."""
    if not alert_store.delete(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")


# ═══════════════════════════════════════════════════════════════
#  METRIC ENDPOINTS  (analyst+ can record; all authenticated can read)
# ═══════════════════════════════════════════════════════════════


@app.post(
    "/metrics",
    response_model=MetricSnapshot,
    status_code=201,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
def record_metric(data: MetricCreate, current_user: CurrentUser) -> MetricSnapshot:
    """Record a system metric snapshot. Requires **analyst** role."""
    return metric_store.create(data, recorded_by=current_user.id)


@app.get("/metrics", response_model=list[MetricSnapshot])
def list_metrics(
    current_user: CurrentUser,
    name: Optional[str] = Query(None, description="Filter by metric name"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
) -> list[MetricSnapshot]:
    """List metric snapshots. All authenticated users can read."""
    return metric_store.list_all(name=name, limit=limit)


@app.get("/metrics/{metric_id}", response_model=MetricSnapshot)
def get_metric(metric_id: int, current_user: CurrentUser) -> MetricSnapshot:
    """Get a single metric by ID."""
    metric = metric_store.get(metric_id)
    if metric is None:
        raise HTTPException(status_code=404, detail="Metric not found")
    return metric


# ═══════════════════════════════════════════════════════════════
#  DASHBOARD  (all authenticated users)
# ═══════════════════════════════════════════════════════════════


@app.get("/dashboard", response_model=DashboardSummary)
def dashboard(current_user: CurrentUser) -> DashboardSummary:
    """Aggregated security dashboard overview."""
    alert_counts = alert_store.count_by_status()
    return DashboardSummary(
        total_events=event_store.count(),
        events_by_severity=event_store.count_by_severity(),
        total_alerts=alert_store.count(),
        open_alerts=alert_counts.get("open", 0),
        acknowledged_alerts=alert_counts.get("acknowledged", 0),
        resolved_alerts=alert_counts.get("resolved", 0),
        total_metrics=metric_store.count(),
        recent_events=event_store.recent(5),
    )


# ═══════════════════════════════════════════════════════════════
#  ADMIN: USER MANAGEMENT  (admin only)
# ═══════════════════════════════════════════════════════════════


@app.get(
    "/admin/users",
    response_model=list[UserResponse],
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
def list_users(current_user: CurrentUser) -> list[UserResponse]:
    """List all registered users. Requires **admin** role."""
    return [
        UserResponse(id=u.id, username=u.username, role=u.role, created_at=u.created_at)
        for u in user_store.list_all()
    ]


@app.delete(
    "/admin/users/{user_id}",
    status_code=204,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
def delete_user(user_id: int, current_user: CurrentUser) -> None:
    """Delete a user account. Requires **admin** role. Admins cannot delete themselves."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if not user_store.delete(user_id):
        raise HTTPException(status_code=404, detail="User not found")
