# CLAUDE.md — Watchdog Operational Instructions

## What We Are Building

Multi-tenant, production-grade Intelligent Observability & Event Watchdog SaaS.

**Stack:**
- Backend: Python 3.11 · FastAPI · SQLAlchemy · Alembic · SQLite (default)
- Frontend: Jinja2 (server-rendered templates) · Alpine.js via CDN (client-side
  reactivity, no build step) · Chart.js via CDN (trend charts)
- Auth: bcrypt · RS256 JWT · Fernet (cryptography library)
- Infra: slowapi (rate limiting) · python-dotenv · watchdog (file events) · pytest

**Frontend model:** FastAPI renders all HTML via Jinja2 templates. Alpine.js handles
client-side reactivity (auto-refresh, form state, inline interactions). Chart.js
renders trend charts. No npm, no build pipeline, no second server. Everything served
by FastAPI on one port.

**Before writing any code, read:**
1. `FEATURES.md` — what the product does (source of truth)
2. `ARCHITECTURE.md` — how it is built (technical design)
3. `tasks/todo.md` — current state and next module

Do not re-derive architecture from scratch. Do not make design decisions not covered
in ARCHITECTURE.md without flagging them to me first.

---

## Vibe Coding Rules (Non-Negotiable)

- I am the Architect. You are the Engineer. I direct; you execute.
- **No code written until I explicitly say "GO" or "proceed to module N"**
- All code comes from you — I will never manually edit files
- After every response, append the prompt I just used to `prompts.md`
- Report **Elapsed Time** at the end of every response
- One module at a time. Complete → test → confirm → wait for approval
- If something goes wrong: STOP, diagnose, propose fix, wait for approval
- Bug fixes: show reasoning first (what broke, why, proposed fix), then wait for "go"

---

## Security Rules (Enforced on Every Line of Code)

- **Never log API key values** — log `api_key_id` (UUID) only
- **Never log Authorization header values**
- **Never include secrets in prompts.md** — use placeholder values in examples
- **Never hardcode secrets** — all secrets from .env via config.py
- **Never store API key plaintext** — SHA-256 hash only
- **Never store webhook secrets as hash** — must be Fernet-encrypted (need to retrieve)
- **Never store connection strings in plaintext** — Fernet-encrypted
- **Never return secrets in API responses** — connection strings masked after save
- **Never commit .env** — only .env.example with placeholders
- **Every query scoped to tenant_id** — no cross-tenant data leakage ever

If any of the above rules would be violated by a proposed implementation, stop
and redesign before writing code.

---

## Session Start Checklist

Every new session, before writing any code:
1. Read `FEATURES.md` — confirm product scope
2. Read `ARCHITECTURE.md` — confirm technical design
3. Read `tasks/todo.md` — confirm current module and what is complete
4. Read `tasks/lessons.md` — review mistakes already made and rules derived
5. State your understanding of current position and next step
6. Wait for my "GO" before proceeding

---

## File Structure Reference

```
/watchdog
  CLAUDE.md                         # This file — operational rules only
  FEATURES.md                       # Product feature list — source of truth
  ARCHITECTURE.md                   # Technical design — read before building
  DECISIONS.md                      # Architecture reasoning (submission artifact)
  main.py                           # FastAPI app, routers, lifespan events
  config.py                         # pydantic-settings, all config from .env
  database.py                       # SQLAlchemy engine, session, Base, get_db
  security.py                       # JWT, API key hashing, RBAC, TenantContext
  middleware.py                     # Request logging, X-Request-ID, latency, redaction

  routers/
    v1/
      auth.py                       # /api/v1/auth/login, /logout, /refresh
      ingest.py                     # /api/v1/ingest (push connector endpoint)
      alerts.py                     # /api/v1/alerts (list, get, acknowledge)
      health.py                     # /api/v1/health
      webhook.py                    # /api/v1/webhook/receive (simulated consumer)
      admin/
        sources.py                  # Tenant source CRUD
        users.py                    # Tenant user management
        keys.py                     # API key self-service (generate, rotate, revoke)
        webhooks.py                 # Webhook subscription management
        config.py                   # Tenant retention + EWMA defaults
      platform/
        tenants.py                  # Platform Admin: tenant management
        health.py                   # Platform Admin: platform overview

  services/
    anomaly_engine.py               # EWMA + all 6 anomaly types
    webhook_dispatcher.py           # Alert delivery, HMAC signing, retry
    log_service.py                  # Ingest pipeline, tenant routing
    connector_manager.py            # Start/stop/monitor connectors per tenant
    retention_service.py            # Hourly cleanup job
    cache.py                        # CacheBackend ABC + InProcessCache

  connectors/
    base.py                         # LogSourceConnector ABC
    file_connector.py               # File tail + rotation detection
    db_connector.py                 # High-water mark polling
    push_connector.py               # Passive (ingest endpoint feeds this)

  models/
    db.py                           # All SQLAlchemy ORM models
    schemas/
      v1/
        auth.py                     # LoginRequest, TokenResponse
        ingest.py                   # LogEntryRequest, LogEntryResponse
        alerts.py                   # AnomalyAlertResponse, AnomalyListResponse
        admin.py                    # SourceConfig, UserRequest, KeyRequest
        health.py                   # HealthResponse
        webhook.py                  # WebhookRegistration, DeliveryRecord

  migrations/
    env.py
    versions/
      001_initial_schema.py

  static/
    dashboard.html                  # Operator view: trends, alert feed, service grid
    admin.html                      # Tenant Admin: sources, users, settings
    consumer.html                   # Consumer portal: keys, webhooks, delivery history
    platform.html                   # Platform Admin: tenant management

  tests/
    conftest.py                     # Fixtures: in-memory DB, test client, test tenants
    test_auth.py
    test_ingest.py
    test_anomaly_engine.py
    test_connectors.py
    test_webhook.py
    test_alerts.py
    test_admin.py
    test_retention.py
    test_security.py
    test_health.py
    evals/
      eval_anomaly_precision_recall.py
      eval_false_positive_rate.py
      eval_connector_lag.py

  scripts/
    seed_data.py                    # Multi-tenant demo data, known anomaly events
    generate_api_key.py             # CLI: mint + register API key

  prompts.md                        # Prompt audit log (auto-maintained, no secrets)
  requirements.txt                  # Pinned versions
  .env.example                      # All config variables with placeholders + comments
  .gitignore                        # Includes .env, *.db, __pycache__
  alembic.ini
  pytest.ini
  CHANGELOG.md
  README.md
  tasks/
    todo.md                         # Module checklist (auto-maintained)
    lessons.md                      # Error patterns (updated after every correction)
```

---

## Build Order

```
Module 1   Foundation: config, database, migrations, requirements, .env.example
Module 2   Security: JWT, RBAC, TenantContext, API key hashing, key generation script
Module 3   Auth endpoints: login, logout, refresh, platform admin bootstrap
Module 4   Connectors: base class, file, DB, push; ConnectorManager lifespan
Module 5   Log ingestion: push ingest endpoint, log service, middleware
Module 6   Anomaly engine: EWMA state, all 6 types, cache layer, auto-resolution
Module 7   Webhook system: dispatcher, HMAC signing, retry, webhook receive endpoint
Module 8   Alerts API: list, get, acknowledge, cursor pagination, filters
Module 9   Admin APIs: source CRUD, user management, key self-service, webhook mgmt
Module 10  Retention service: hourly cleanup job, system_config table
Module 11  Health endpoint, deprecation middleware, CHANGELOG
Module 12  Dashboard + UI: operator view, admin panel, consumer portal
Module 13  Platform Admin: tenant management, platform health UI
Module 14  Seed data + README: multi-tenant demo, curl examples
Module 15  Evals: precision/recall, FPR, connector lag
```

Each module requires my explicit "proceed to module N" before starting.

---

## Testing Standards

Every module ships with:
- **Unit tests:** happy path, boundary conditions, error paths, edge cases
- **Integration tests:** full HTTP layer, correct status codes, correct schema
- **Security tests:** auth required, wrong tenant 403/404, scope enforcement
- **Evals** (Module 6 + 15 only): precision, recall, FPR with numeric targets

Conventions:
- In-memory SQLite in conftest.py — never touch production DB
- Two test tenants in every fixture (verify no cross-tenant leakage)
- `pytest.mark.parametrize` for boundary/edge variants
- Mock all external I/O in unit tests
- Every test independent — no shared mutable state

---

## Task Tracking (Auto-Maintained)

After each module, update `tasks/todo.md`:
```
## Module N — [Name] ✓
Built: [2-sentence summary]
Tests: [X unit / X integration / X security passing]
Decisions: [any tradeoffs made]
Limitations: [honest known gaps]
```

After any correction, update `tasks/lessons.md`:
```
## Lesson N
Mistake: [what went wrong]
Root cause: [why]
Rule: [specific prevention rule]
```

---

## Core Principles

- Simplicity first — minimal footprint per change
- No shortcuts — root causes, senior standards throughout
- Testability — if it cannot be tested, the design is wrong; redesign first
- Security by default — auth, tenant isolation, secret hygiene are not features
- Show your work — narrate decisions clearly, this is a judged submission
- Never expose secrets — in code, logs, responses, or this audit file
