"""Pydantic models for the Secure Systems Monitor API."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ───────────────────────────────────────────────────────


class UserRole(str, Enum):
    """Authorization roles with ascending privilege."""
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class EventSeverity(str, Enum):
    """Severity classification for system events."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """Broad category of a security event."""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    PROCESS = "process"
    CONFIGURATION = "configuration"


class AlertStatus(str, Enum):
    """Lifecycle status of an alert."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# ── User models ─────────────────────────────────────────────────


class UserCreate(BaseModel):
    """Request body for registering a new user."""
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    password: str = Field(..., min_length=8, max_length=128, description="Plain-text password (min 8 chars)")
    role: UserRole = Field(default=UserRole.VIEWER, description="Assigned role")


class UserResponse(BaseModel):
    """Public user representation (never exposes the password hash)."""
    id: int
    username: str
    role: UserRole
    created_at: datetime


class UserInDB(BaseModel):
    """Internal user representation (includes hash). Never returned to clients."""
    id: int
    username: str
    hashed_password: str
    role: UserRole
    created_at: datetime


# ── Auth / Token models ─────────────────────────────────────────


class Token(BaseModel):
    """OAuth2-compatible token response."""
    access_token: str
    token_type: str = "bearer"


# ── System Event models ─────────────────────────────────────────


class EventCreate(BaseModel):
    """Request body for logging a new security event."""
    source_ip: str = Field(..., min_length=1, max_length=45, description="Source IP address")
    category: EventCategory
    severity: EventSeverity = Field(default=EventSeverity.INFO)
    message: str = Field(..., min_length=1, max_length=2000, description="Human-readable description")
    metadata: Optional[dict] = Field(None, description="Additional structured data")


class EventResponse(BaseModel):
    """A security event as returned by the API."""
    id: int
    source_ip: str
    category: EventCategory
    severity: EventSeverity
    message: str
    metadata: Optional[dict] = None
    reported_by: int
    timestamp: datetime


# ── Alert models ────────────────────────────────────────────────


class AlertCreate(BaseModel):
    """Request body for creating an alert (from an event)."""
    event_id: int = Field(..., description="ID of the triggering event")
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class AlertUpdate(BaseModel):
    """Fields that can be updated on an existing alert."""
    status: Optional[AlertStatus] = None
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class AlertResponse(BaseModel):
    """An alert as returned by the API."""
    id: int
    event_id: int
    title: str
    description: Optional[str] = None
    status: AlertStatus
    created_by: int
    created_at: datetime
    updated_at: datetime


# ── Metric models ───────────────────────────────────────────────


class MetricSnapshot(BaseModel):
    """A point-in-time system metric reading."""
    id: int
    name: str
    value: float
    unit: str
    recorded_by: int
    timestamp: datetime


class MetricCreate(BaseModel):
    """Request body for recording a metric."""
    name: str = Field(..., min_length=1, max_length=100, description="Metric name (e.g. cpu_usage)")
    value: float = Field(..., description="Numeric value")
    unit: str = Field(..., min_length=1, max_length=20, description="Unit label (e.g. percent, MB)")


# ── Dashboard model ─────────────────────────────────────────────


class DashboardSummary(BaseModel):
    """Aggregated overview returned by the dashboard endpoint."""
    total_events: int
    events_by_severity: dict[str, int]
    total_alerts: int
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    total_metrics: int
    recent_events: list[EventResponse]
