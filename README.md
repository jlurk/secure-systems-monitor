# 🛡️ Secure Systems Monitor API

### A Security-Focused Monitoring Platform with RBAC, Event Logging & Real-Time Dashboard

---

## 📌 Overview

A production-style backend API built with **FastAPI** that provides a complete security operations platform. The system enables teams to log security events, manage alerts through their full lifecycle, collect system metrics, and view aggregated dashboards — all protected by JWT authentication and three-tier role-based access control.

This project demonstrates advanced backend engineering concepts including:

* **Role-Based Access Control (RBAC)** with hierarchical permission enforcement
* **JWT Authentication** with role-embedded tokens
* **Security event lifecycle management** (event → alert → resolution)
* **Aggregated dashboard** with real-time statistics
* **Admin user management** with self-deletion protection
* **Comprehensive input validation** and error handling
* **50+ automated tests** covering security boundaries

---

## ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔐 **JWT Authentication** | OAuth2 password flow with role-embedded tokens |
| 👥 **Three-Tier RBAC** | Viewer → Analyst → Admin with hierarchical enforcement |
| 🚨 **Security Event Logging** | Log events with severity, category, source IP, and metadata |
| 🔔 **Alert Management** | Create, acknowledge, resolve, and delete alerts linked to events |
| 📊 **System Metrics** | Record and query point-in-time metric snapshots |
| 📈 **Aggregated Dashboard** | Real-time counts, severity breakdown, and recent events |
| 👤 **Admin User Management** | List users, delete accounts (with self-deletion guard) |
| ✅ **50+ Automated Tests** | Auth, RBAC, CRUD, validation, and edge case coverage |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    FastAPI App                       │
├──────────┬──────────┬──────────┬───────────────────┤
│  Events  │  Alerts  │ Metrics  │  Dashboard/Admin   │
├──────────┴──────────┴──────────┴───────────────────┤
│              RBAC Middleware (require_role)          │
├────────────────────────────────────────────────────┤
│              JWT Authentication Layer               │
├──────────┬──────────┬──────────┬──────────────────┤
│  auth.py │ models.py│ store.py │     main.py       │
└──────────┴──────────┴──────────┴──────────────────┘
```

| Layer        | File         | Responsibility |
|--------------|--------------|----------------|
| **Routes**   | `main.py`    | API endpoints, dependency wiring, RBAC enforcement |
| **Auth**     | `auth.py`    | JWT creation/validation, password hashing, role dependencies |
| **Schemas**  | `models.py`  | Pydantic v2 request/response models with validation |
| **Business** | `store.py`   | In-memory data stores with filtering and aggregation |

---

## 🔐 Security Model

### Role Hierarchy

```
ADMIN (full control)
  ├── All ANALYST permissions
  ├── Delete alerts
  ├── List all users
  └── Delete user accounts

ANALYST (read + write)
  ├── All VIEWER permissions
  ├── Create security events
  ├── Create and update alerts
  └── Record metrics

VIEWER (read-only)
  ├── View events, alerts, metrics
  └── View dashboard
```

### Security Principles

* Passwords are **hashed using bcrypt** (never stored in plaintext)
* JWT tokens carry both `sub` (username) and `role` claims
* The `require_role()` dependency enforces minimum privilege at the route level
* All endpoints except `/register`, `/token`, and `/` require authentication
* Admins **cannot delete their own account** (self-deletion guard)
* No secrets are stored in the repository

---

## 🔑 Authentication Flow

```
1. Register  →  POST /register  →  { username, password, role? }
2. Login     →  POST /token     →  { access_token, token_type }
3. Use token →  Authorization: Bearer <access_token>
```

---

## 📂 Project Structure

```
secure-systems-monitor/
├── app/
│   ├── __init__.py
│   ├── main.py          # API routes + RBAC wiring
│   ├── auth.py          # JWT + bcrypt + role enforcement
│   ├── models.py        # Pydantic v2 schemas
│   └── store.py         # In-memory data stores
├── tests/
│   ├── __init__.py
│   └── test_api.py      # 50+ automated tests
├── requirements.txt
├── run.py               # Uvicorn entry point
├── CLAUDE.md
├── .gitignore
└── README.md
```

---

## ⚙️ Setup

```bash
# Clone the repository
git clone <repo-url>
cd secure-systems-monitor

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Run the API

```bash
python run.py
```

🌐 **API Base URL**: `http://127.0.0.1:8000`
📘 **Swagger Docs**: `http://127.0.0.1:8000/docs`
📗 **ReDoc**: `http://127.0.0.1:8000/redoc`

---

## 🧪 Testing

```bash
pytest tests/ -v
```

### ✔️ Test Coverage Includes

| Category | Tests |
|----------|-------|
| Authentication | Login, registration, token validation, bad tokens |
| RBAC Enforcement | Viewer/analyst/admin permission boundaries |
| Event CRUD | Create, list, filter by severity/category, get by ID |
| Alert CRUD | Create, update status, delete, filter, event validation |
| Metric CRUD | Record, list, filter by name, get by ID |
| Dashboard | Empty state, aggregation accuracy |
| Admin | User listing, deletion, self-deletion guard |
| Validation | Empty fields, invalid enums, missing required fields |

---

## 📊 API Endpoints

### Authentication
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| `POST` | `/register` | ✗ | — | Register a new user |
| `POST` | `/token` | ✗ | — | Login and get JWT |

### Security Events
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| `POST` | `/events` | ✓ | analyst+ | Log a security event |
| `GET` | `/events` | ✓ | viewer+ | List events (filterable) |
| `GET` | `/events/{id}` | ✓ | viewer+ | Get event by ID |

### Alerts
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| `POST` | `/alerts` | ✓ | analyst+ | Create alert from event |
| `GET` | `/alerts` | ✓ | viewer+ | List alerts (filterable) |
| `GET` | `/alerts/{id}` | ✓ | viewer+ | Get alert by ID |
| `PUT` | `/alerts/{id}` | ✓ | analyst+ | Update alert status |
| `DELETE` | `/alerts/{id}` | ✓ | admin | Delete alert |

### Metrics
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| `POST` | `/metrics` | ✓ | analyst+ | Record a metric |
| `GET` | `/metrics` | ✓ | viewer+ | List metrics (filterable) |
| `GET` | `/metrics/{id}` | ✓ | viewer+ | Get metric by ID |

### Dashboard & Admin
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| `GET` | `/dashboard` | ✓ | viewer+ | Aggregated overview |
| `GET` | `/admin/users` | ✓ | admin | List all users |
| `DELETE` | `/admin/users/{id}` | ✓ | admin | Delete a user |

---

## 🧾 Enums

### Event Severity
`info` · `warning` · `critical`

### Event Category
`authentication` · `network` · `file_system` · `process` · `configuration`

### Alert Status
`open` · `acknowledged` · `resolved`

### User Roles
`viewer` · `analyst` · `admin`

---

## 🎯 Why This Project Matters

This project demonstrates:

* **Security-first API design** with defense-in-depth (authentication + authorization + validation)
* **Role-Based Access Control** implemented as reusable FastAPI dependencies
* **Domain modeling** for security operations (events → alerts → resolution workflow)
* **Clean architecture** with clear separation of concerns across 4 modules
* **Production-grade testing** with 50+ tests covering every security boundary
* **API documentation** auto-generated via OpenAPI/Swagger

---

## 🚀 Future Enhancements

* PostgreSQL / SQLAlchemy integration
* Async endpoints with `asyncio`
* WebSocket real-time alert notifications
* Rate limiting and IP throttling
* Docker + CI/CD pipeline
* Prometheus-compatible metric export
* Audit logging for admin actions

---

## ⚠️ Security Notes

* `.env` is gitignored — use environment variables for all secrets
* The hardcoded `SECRET_KEY` in `auth.py` is for **development only**
* In production: rotate keys, use HTTPS, add rate limiting, and store secrets in a vault

---

## 👨‍💻 Author

Built as part of a backend engineering & security-focused portfolio project.
