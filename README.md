# 🛡️ Secure Systems Monitor API  
### 🔐 Systems Monitoring, Security Events, RBAC, and Alert Management

---

## 📌 Overview

Secure Systems Monitor API is a portfolio-grade backend system built with **FastAPI** for tracking system health, security events, alerts, user roles, and operational risk.

This project demonstrates secure backend engineering, systems monitoring concepts, access control, event logging, and automated validation through testing and CI.

---

## 🎯 Purpose

The goal of this project is to model a lightweight security and systems monitoring backend that could be used by security, infrastructure, or operations teams to:

- Track systems and monitored assets
- Record security events
- Manage alert lifecycle status
- Enforce role-based access control
- Support auditability and operational visibility
- Validate functionality through automated tests

---

## ✨ Core Features

| Feature | Description |
|---|---|
| JWT Authentication | OAuth2 password flow with access tokens |
| Secure Password Hashing | Passwords are hashed using bcrypt/passlib |
| Role-Based Access Control | Admin, Analyst, and Viewer access levels |
| Security Event Logging | Capture system/security events with severity and metadata |
| Alert Management | Create, update, resolve, and delete alerts |
| System / Asset Tracking | Track monitored systems and operational records |
| Dashboard Metrics | Provide summarized system and alert visibility |
| Audit-Oriented Design | Supports traceability of security and operational actions |
| Automated Testing | Pytest test suite validates key API behavior |
| CI Validation | GitHub Actions runs tests automatically on push and pull request |

---

## 🏗️ Architecture

| Layer | File | Responsibility |
|---|---|---|
| API Layer | `app/main.py` | FastAPI routes, request handling, dependency wiring |
| Auth Layer | `app/auth.py` | JWT creation, token validation, password hashing, role checks |
| Data Models | `app/models.py` | Pydantic schemas and validation models |
| Business Logic | `app/store.py` | In-memory data handling, filtering, and workflow logic |
| Tests | `tests/test_api.py` | Automated tests for auth, RBAC, alerts, events, and API behavior |
| Runner | `run.py` | Local application startup entry point |

---

## 🔐 Security Model

This project applies basic secure backend design patterns:

- Passwords are never stored in plaintext
- Password hashing uses bcrypt/passlib
- JWT access tokens protect authenticated endpoints
- Role-based access control limits privileged operations
- Viewer, Analyst, and Admin roles enforce access boundaries
- Secrets are excluded from source control
- Local environment files are ignored through `.gitignore`
- CI validates test execution before changes are considered stable

---

## 👥 Role-Based Access Control

| Role | Capabilities |
|---|---|
| Viewer | Can view permitted systems, events, alerts, and dashboard data |
| Analyst | Can create and update security events and alerts |
| Admin | Can manage privileged operations, including administrative user or alert actions |

---

## 🔑 Authentication Flow

1. A user registers or is created in the system.
2. The user logs in through `/token`.
3. The API returns a JWT access token.
4. The client sends the token in the authorization header:

```http
Authorization: Bearer <access_token>

## 📊 API Endpoint Summary

| Method   | Endpoint       | Auth Required | Role     | Description            |
| -------- | -------------- | ------------- | -------- | ---------------------- |
| `GET`    | `/`            | No            | Public   | Health check           |
| `POST`   | `/register`    | No            | Public   | Register a user        |
| `POST`   | `/token`       | No            | Public   | Login and receive JWT  |
| `GET`    | `/events`      | Yes           | Viewer+  | List security events   |
| `POST`   | `/events`      | Yes           | Analyst+ | Create security event  |
| `GET`    | `/events/{id}` | Yes           | Viewer+  | Get event by ID        |
| `GET`    | `/alerts`      | Yes           | Viewer+  | List alerts            |
| `POST`   | `/alerts`      | Yes           | Analyst+ | Create alert           |
| `PUT`    | `/alerts/{id}` | Yes           | Analyst+ | Update alert           |
| `DELETE` | `/alerts/{id}` | Yes           | Admin    | Delete alert           |
| `GET`    | `/dashboard`   | Yes           | Viewer+  | View dashboard summary |

---

## 🧪 Testing