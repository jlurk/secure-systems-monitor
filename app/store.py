"""In-memory stores for users, events, alerts, and metrics."""

from datetime import datetime, timezone
from typing import Optional

from app.models import (
    AlertCreate,
    AlertResponse,
    AlertStatus,
    AlertUpdate,
    EventCategory,
    EventCreate,
    EventResponse,
    EventSeverity,
    MetricCreate,
    MetricSnapshot,
    UserInDB,
)


# ── User Store ──────────────────────────────────────────────────


class UserStore:
    """In-memory user store with username indexing."""

    def __init__(self) -> None:
        self._users: dict[int, UserInDB] = {}
        self._username_index: dict[str, int] = {}
        self._next_id: int = 1

    def create(self, username: str, hashed_password: str, role: str) -> UserInDB:
        user = UserInDB(
            id=self._next_id,
            username=username,
            hashed_password=hashed_password,
            role=role,
            created_at=datetime.now(timezone.utc),
        )
        self._users[user.id] = user
        self._username_index[username] = user.id
        self._next_id += 1
        return user

    def get_by_username(self, username: str) -> Optional[UserInDB]:
        uid = self._username_index.get(username)
        if uid is None:
            return None
        return self._users.get(uid)

    def get_by_id(self, user_id: int) -> Optional[UserInDB]:
        return self._users.get(user_id)

    def username_exists(self, username: str) -> bool:
        return username in self._username_index

    def list_all(self) -> list[UserInDB]:
        return list(self._users.values())

    def delete(self, user_id: int) -> bool:
        user = self._users.get(user_id)
        if user is None:
            return False
        del self._users[user_id]
        del self._username_index[user.username]
        return True

    def reset(self) -> None:
        self._users.clear()
        self._username_index.clear()
        self._next_id = 1


# ── Event Store ─────────────────────────────────────────────────


class EventStore:
    """In-memory store for security events."""

    def __init__(self) -> None:
        self._events: dict[int, EventResponse] = {}
        self._next_id: int = 1

    def create(self, data: EventCreate, reported_by: int) -> EventResponse:
        event = EventResponse(
            id=self._next_id,
            source_ip=data.source_ip,
            category=data.category,
            severity=data.severity,
            message=data.message,
            metadata=data.metadata,
            reported_by=reported_by,
            timestamp=datetime.now(timezone.utc),
        )
        self._events[event.id] = event
        self._next_id += 1
        return event

    def get(self, event_id: int) -> Optional[EventResponse]:
        return self._events.get(event_id)

    def list_all(
        self,
        severity: Optional[EventSeverity] = None,
        category: Optional[EventCategory] = None,
        limit: int = 100,
    ) -> list[EventResponse]:
        events = list(self._events.values())
        if severity is not None:
            events = [e for e in events if e.severity == severity]
        if category is not None:
            events = [e for e in events if e.category == category]
        # Return most recent first
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    def count(self) -> int:
        return len(self._events)

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in EventSeverity}
        for event in self._events.values():
            counts[event.severity.value] += 1
        return counts

    def recent(self, n: int = 5) -> list[EventResponse]:
        events = sorted(self._events.values(), key=lambda e: e.timestamp, reverse=True)
        return events[:n]

    def reset(self) -> None:
        self._events.clear()
        self._next_id = 1


# ── Alert Store ─────────────────────────────────────────────────


class AlertStore:
    """In-memory store for alerts linked to events."""

    def __init__(self) -> None:
        self._alerts: dict[int, AlertResponse] = {}
        self._next_id: int = 1

    def create(self, data: AlertCreate, created_by: int) -> AlertResponse:
        now = datetime.now(timezone.utc)
        alert = AlertResponse(
            id=self._next_id,
            event_id=data.event_id,
            title=data.title,
            description=data.description,
            status=AlertStatus.OPEN,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        self._alerts[alert.id] = alert
        self._next_id += 1
        return alert

    def get(self, alert_id: int) -> Optional[AlertResponse]:
        return self._alerts.get(alert_id)

    def list_all(
        self, status: Optional[AlertStatus] = None, limit: int = 100
    ) -> list[AlertResponse]:
        alerts = list(self._alerts.values())
        if status is not None:
            alerts = [a for a in alerts if a.status == status]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def update(self, alert_id: int, data: AlertUpdate) -> Optional[AlertResponse]:
        existing = self._alerts.get(alert_id)
        if existing is None:
            return None
        updated_fields = data.model_dump(exclude_unset=True)
        if not updated_fields:
            return existing
        updated_fields["updated_at"] = datetime.now(timezone.utc)
        new_alert = existing.model_copy(update=updated_fields)
        self._alerts[alert_id] = new_alert
        return new_alert

    def delete(self, alert_id: int) -> bool:
        if alert_id not in self._alerts:
            return False
        del self._alerts[alert_id]
        return True

    def count(self) -> int:
        return len(self._alerts)

    def count_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in AlertStatus}
        for alert in self._alerts.values():
            counts[alert.status.value] += 1
        return counts

    def reset(self) -> None:
        self._alerts.clear()
        self._next_id = 1


# ── Metric Store ────────────────────────────────────────────────


class MetricStore:
    """In-memory store for system metric snapshots."""

    def __init__(self) -> None:
        self._metrics: dict[int, MetricSnapshot] = {}
        self._next_id: int = 1

    def create(self, data: MetricCreate, recorded_by: int) -> MetricSnapshot:
        metric = MetricSnapshot(
            id=self._next_id,
            name=data.name,
            value=data.value,
            unit=data.unit,
            recorded_by=recorded_by,
            timestamp=datetime.now(timezone.utc),
        )
        self._metrics[metric.id] = metric
        self._next_id += 1
        return metric

    def get(self, metric_id: int) -> Optional[MetricSnapshot]:
        return self._metrics.get(metric_id)

    def list_all(self, name: Optional[str] = None, limit: int = 100) -> list[MetricSnapshot]:
        metrics = list(self._metrics.values())
        if name is not None:
            metrics = [m for m in metrics if m.name == name]
        metrics.sort(key=lambda m: m.timestamp, reverse=True)
        return metrics[:limit]

    def count(self) -> int:
        return len(self._metrics)

    def reset(self) -> None:
        self._metrics.clear()
        self._next_id = 1


# ── Singleton instances ─────────────────────────────────────────
user_store = UserStore()
event_store = EventStore()
alert_store = AlertStore()
metric_store = MetricStore()
