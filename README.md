# Watchdog — Intelligent Observability & Event Watchdog

> Multi-tenant SaaS log monitoring with EWMA anomaly detection, webhook push delivery,
> and role-based operator dashboards. Built on FastAPI · SQLAlchemy · Alpine.js.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Features](#3-features)
4. [Security Architecture](#4-security-architecture)
5. [Screenshots](#5-screenshots)
6. [Roles & Access Control](#6-roles--access-control)
7. [Architectural Decisions & Tradeoffs](#7-architectural-decisions--tradeoffs)
8. [API Reference](#8-api-reference)
9. [Setup & Installation](#9-setup--installation)
10. [Known Limitations & Upgrade Paths](#10-known-limitations--upgrade-paths)
11. [Prompts Audit Log Reference](#11-prompts-audit-log-reference)

---

## 1. Executive Summary

**Watchdog** is a production-grade, multi-tenant SaaS observability service that ingests
log streams from running applications, applies Exponentially Weighted Moving Average (EWMA)
anomaly detection across six failure modes, and delivers real-time alerts to operators via
a live dashboard and to external consumers via signed webhook push. Each tenant operates
in complete data isolation — their sources, alerts, API keys, and webhook subscriptions are
invisible to every other tenant on the platform.

**The problem it solves:** Engineering teams waste incident response time because their
observability tooling either (a) alerts too late — polling-based systems with coarse
thresholds miss early-stage anomalies — or (b) alerts too often — static threshold systems
produce false positives that operators learn to ignore. Watchdog's EWMA engine learns each
service's individual baseline and adapts continuously, triggering with high precision while
suppressing noise.

---

### Quick Start — Get Into the Running App in Under 2 Minutes

The app is already running. Open your browser:

| View | URL | Who can access |
|------|-----|----------------|
| Login | `http://127.0.0.1:8080/login` | Anyone |
| Operator Dashboard | `http://127.0.0.1:8080/dashboard` | Operator, Admin |
| Tenant Admin | `http://127.0.0.1:8080/admin` | Tenant Admin only |
| Consumer Portal | `http://127.0.0.1:8080/consumer` | All authenticated |
| Platform Admin | `http://127.0.0.1:8080/platform-admin` | Platform Admin only |
| API Docs (Swagger) | `http://127.0.0.1:8080/docs` | No auth required |

**Demo credentials (seeded by `scripts/seed_data.py`):**

| Tenant | Role | Email | Password |
|--------|------|-------|----------|
| Acme Corp | Tenant Admin | `admin@acme.example.com` | `WatchdogDemo1!` |
| Acme Corp | Tenant Operator | `ops@acme.example.com` | `WatchdogDemo1!` |
| Beta Inc | Tenant Admin | `admin@beta.example.com` | `WatchdogDemo1!` |
| Beta Inc | Tenant Operator | `ops@beta.example.com` | `WatchdogDemo1!` |

Sign in as `admin@acme.example.com`. You will immediately see 4 open alerts (2 CRITICAL,
2 WARNING) across 2 services, 3 acknowledged, 3 resolved, and a 24-hour trend chart showing
the detection window.

---

### Test Results Summary

| Metric | Result | Target |
|--------|--------|--------|
| Total tests passing | **266 / 266** | All pass |
| Coverage | **91.73%** | >= 80% |
| Anomaly precision | **1.000** | > 0.85 |
| Anomaly recall | **1.000** | > 0.90 |
| False positive rate | **0.000** | < 0.05 |
| Ingest latency P50 | **< 10ms** | < 500ms |
| Ingest latency P95 | **< 50ms** | < 1,000ms |
| Cross-tenant isolation | **0 leaks / 6 checks** | 0 leaks |

Tests span 15 modules: unit, integration, security (auth enforcement, wrong-tenant 403/404,
scope enforcement), and evals (anomaly precision/recall, connector lag, cross-tenant isolation).

---

### Project Architecture Documents

This project was built using a structured vibe coding methodology where architecture was
fully designed before a single line of code was written. The following documents drove
every decision in the build:

| Document | Purpose |
|----------|---------|
| [CLAUDE.md](CLAUDE.md) | AI operating rules — vibe coding constraints, security rules, session start checklist, and a self-improving lessons loop baked in |
| [FEATURES.md](FEATURES.md) | Complete product feature list — source of truth for what gets built. Database schema and API surface derived from this. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Full technical design — DB schema, connector architecture, EWMA algorithm, security model, caching strategy, API versioning |
| [DECISIONS.md](DECISIONS.md) | 18 architectural decisions with full tradeoff analysis — every major choice documented with alternatives considered and reasons rejected |
| [ARCHITECT_PROMPTS.md](ARCHITECT_PROMPTS.md) | The architectural questions and challenges raised before and during the build — demonstrates the thinking process behind the system design |
| [tasks/todo.md](tasks/todo.md) | Module-by-module implementation checklist — 15 modules, exact test cases per module, approval gates |
| [tasks/lessons.md](tasks/lessons.md) | Self-improving lessons log — every bug found, root cause, and rule derived to prevent recurrence. Updated throughout the build. |

**Why these documents matter:**

The build followed a strict Architect → Engineer model:
- Architecture was fully specified before Claude Code wrote any code
- Every module required explicit approval before the next began
- Claude Code maintained a self-improvement loop via `tasks/lessons.md` — logging mistakes and deriving rules to prevent recurrence
- Security rules were enforced as hard constraints in `CLAUDE.md`, not guidelines

This approach produced a codebase where every decision is traceable to a document,
every tradeoff is recorded, and the reasoning is available for review.

> Full prompts audit log of every instruction given to Claude Code during the build: see [prompts.md](prompts.md)

---

## 2. Architecture Overview

### System Diagram

```
+-------------------------------------------------------------------------+
|                           WATCHDOG SERVICE                              |
|                                                                         |
|  External Log Sources          +------------+   +-------------------+  |
|  (per tenant, isolated)        | Connectors |   |  Anomaly Engine   |  |
|                                |            +-->|                   |  |
|  +-------------+  tail+rotate  | File       |   |  EWMA state       |  |
|  | Log files   +-------------->| Connector  |   |  per source       |  |
|  +-------------+               |            |   |                   |  |
|                                | DB         |   |  6 anomaly types  |  |
|  +-------------+  high-water   | Connector  |   |                   |  |
|  | DB tables   +-------------->|            |   |  In-memory cache  |  |
|  +-------------+  mark poll    |            |   |  (DB-persisted)   |  |
|                                | Push       |   +--------+----------+  |
|  +-------------+  POST /ingest | Connector  |            |             |
|  | Live apps   +-------------->| (passive)  |            v             |
|  +-------------+               +------------+   +-------------------+  |
|                                                  |  Alert Delivery   |  |
|  +--------------------------------------+        |                   |  |
|  |          Background Jobs             |        |  REST API (pull)  |  |
|  |                                      |        |  Webhooks (push)  |  |
|  |  Connector polling  (asyncio/source) |        |  Dashboard (UI)   |  |
|  |  EWMA persistence   (every 10 events)|        +-------------------+  |
|  |  Webhook retry      (every 30s)      |                               |
|  |  Retention cleanup  (hourly)         |   +-----------------------+   |
|  |  Key expiry         (hourly)         |   |  FastAPI + Jinja2 UI  |   |
|  +--------------------------------------+   |  Alpine.js reactivity |   |
|                                             |  Chart.js trend charts|   |
|                          SQLite (dev)       +-----------------------+   |
|                          PostgreSQL (prod)                              |
+-------------------------------------------------------------------------+
```

---

### Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Web framework | FastAPI 0.138 | Async-native, automatic OpenAPI, Pydantic integration |
| ORM / migrations | SQLAlchemy 2.0 + Alembic | Type-safe queries; schema versioned, never ad-hoc DDL |
| Database | SQLite (dev) / PostgreSQL (prod) | Zero-dep local dev; PostgreSQL for RLS + write concurrency |
| Auth | RS256 JWT + bcrypt | Asymmetric signing — public key verifiable without private key |
| Encryption at rest | Fernet (cryptography library) | AES-128-CBC + HMAC — authenticated encryption, not just encryption |
| Secret hashing | SHA-256 (keys), bcrypt cost-12 (passwords) | SHA-256 for O(1) lookup; bcrypt for slow brute-force resistance |
| Rate limiting | slowapi | FastAPI-native; per-endpoint limits without middleware overhead |
| Server rendering | Jinja2 | Python-native; role enforcement happens before template renders |
| Client reactivity | Alpine.js 3.x (CDN) | ~15KB, no build step, readable by any Python engineer |
| Charts | Chart.js 4.x (CDN) | Best-in-class canvas charts; JSON data from `/api/v1/dashboard/trend` |
| File monitoring | watchdog library | Inode-aware rotation detection; polling fallback for NFS |
| Testing | pytest + httpx | Async-native; in-memory SQLite per test; no shared state |
| Coverage | pytest-cov | 91.73% measured at every run |

---

### Multi-Tenant SaaS Model

Watchdog serves multiple independent engineering teams (tenants) from a single deployment.
Each tenant is a fully isolated account:

- **Complete data isolation:** every user-facing table carries a `tenant_id` FK. No query
  ever returns data across tenant boundaries.
- **TenantContext pattern:** a FastAPI dependency injected into every route handler extracts
  and validates the caller's tenant identity from their verified JWT or API key. No service
  function ever accepts a raw `tenant_id` from a request parameter — it always comes from
  the verified context. This eliminates IDOR vulnerabilities by design.
- **Invite-only onboarding (MVP):** a Platform Admin creates tenant accounts. Post-MVP:
  public self-signup with email verification.
- **Per-tenant configuration:** retention days, log retention days, max sources, and EWMA
  parameters are all independently configurable per tenant.

---

### Three Connector Types

| Connector | How it works | Best for |
|-----------|-------------|----------|
| **File** | Tails log files using inode tracking and byte offsets. Detects log rotation by inode change or file shrink. Survives Watchdog restarts without re-reading from the beginning. | Application log files on accessible filesystems |
| **DB** | High-water mark polling: `SELECT ... WHERE id > :last_seen_id ORDER BY id ASC LIMIT 500`. The `last_seen_id` is persisted in `source_state` after every successful batch. Validates at setup that the target column is indexed. | External PostgreSQL/MySQL/SQLite audit or event log tables |
| **Push** | Passive receiver. External apps POST log entries directly to `/api/v1/ingest` using a scoped API key. No polling loop, no connector configuration — zero-friction integration for greenfield applications. | Any application that can make an HTTP call |

---

## AI Detection Engine

### Algorithm: Exponentially Weighted Moving Average (EWMA)

Watchdog uses EWMA with adaptive variance tracking as its core AI detection algorithm.
This is classical statistical AI — not an LLM — and it is the deliberate right choice
for this use case.

EWMA is the same algorithm used by:
- AWS CloudWatch Anomaly Detection
- Netflix Atlas (their internal metrics platform)
- Google SRE spike detection systems

**How it works:**

EWMA maintains a continuously updated weighted average where recent observations
matter more than older ones:

```
EWMA_t      = α × x_t + (1 − α) × EWMA_{t-1}
Variance_t  = α × (x_t − EWMA_{t-1})² + (1 − α) × Variance_{t-1}
Upper Bound = EWMA_t + sensitivity × √Variance_t
```

Alpha (α = 0.3) controls how quickly the baseline adapts. An anomaly fires when the
current observation exceeds the upper bound. Default sensitivity is 2.5× for WARNING
and 5.0× for CRITICAL.

**Why EWMA over alternatives:**

| Algorithm | Reason Not Chosen |
|-----------|------------------|
| Static threshold | Requires manual tuning per service. A service at 50 errors/min looks fine; at 2 errors/min it is on fire. Cannot distinguish. |
| Simple rolling average | Weights old data equally. Lags badly on real spikes. |
| Z-score (static baseline) | Assumes stationary distribution. Real traffic grows and shifts over time. Generates false positives on normal traffic growth. |
| LSTM / neural network | Requires training data we do not have at setup time. Not explainable. Overkill for error rate monitoring. |
| Prophet (Facebook) | Handles seasonality well but requires historical data, external dependency, and slow retraining cycles. |

**Why EWMA is sufficient:**

Three properties make EWMA the correct choice for production anomaly detection at this scale:

1. **Adapts automatically** — as traffic grows or patterns shift, the baseline drifts
   with it. No manual recalibration required.

2. **O(1) per event** — maintains only two numbers per service (EWMA value and variance).
   Processes any volume of log entries with constant memory and constant compute.

3. **Explainable** — every alert can report exactly: current rate is X, weighted baseline
   is Y, threshold is Z. An operator immediately understands why an alert fired without
   needing to interpret a neural network.

**Eval results from this build:**

| Metric | Score | Target |
|--------|-------|--------|
| ERROR_RATE_SPIKE Precision | 1.000 | > 0.85 |
| ERROR_RATE_SPIKE Recall | 1.000 | > 0.90 |
| False Positive Rate | 0.000 | < 0.05 |
| LATENCY_SPIKE Precision | 1.000 | > 0.85 |
| LATENCY_SPIKE Recall | 1.000 | > 0.90 |
| SUSTAINED_ELEVATION Recall | 1.000 | > 0.90 |

All targets exceeded. Zero false positives across 1000 normal-traffic test events.

**Six anomaly types detected:**

| Type | What It Detects | Severity |
|------|----------------|----------|
| `ERROR_RATE_SPIKE` | Sudden burst of errors above EWMA upper bound | WARNING / CRITICAL |
| `SUSTAINED_ELEVATION` | Error rate above baseline for >10 consecutive minutes | WARNING / CRITICAL |
| `SERVICE_SILENCE` | Active service stops emitting logs entirely | CRITICAL |
| `LATENCY_SPIKE` | Response time EWMA upper bound breach | WARNING / CRITICAL |
| `NOVEL_ERROR` | Error message pattern not seen in last 24 hours | WARNING |
| `CASCADE` | 3+ services spiking within a 5-minute window | CRITICAL |

**Phase 2 Enhancement — LLM Enrichment:**

The EWMA layer detects anomalies reliably and instantly with zero external dependencies.
A planned Phase 2 enhancement would add an LLM layer (Claude claude-sonnet-4-6) on top of
the existing detection to enrich each alert with:

- Plain English explanation of what the anomaly means
- Likely root causes based on the evidence pattern
- Suggested immediate actions for the operator
- Natural language incident summary for CASCADE events

The architecture is explicitly designed for this — the anomaly output contract includes
an `ai_enrichment` field (currently `null`) that Phase 2 would populate. Detection via
EWMA would never depend on LLM availability — enrichment would be additive and
gracefully skipped if the API is unavailable. This separation ensures the detection
system remains fast, reliable, and free of external dependencies while the explanation
layer adds operator value on top.

---

### API-First Design

All application logic is exposed via `GET/POST/PATCH/DELETE /api/v1/...` endpoints. The
Jinja2 UI is a consumer of those same endpoints — there is no server-side state that the
UI has access to that the API does not expose.

**Versioning strategy:**

- URL path versioning: `/api/v1/`, `/api/v2/` (additive, never modifying existing paths)
- Schema namespacing: `models/schemas/v1/` — a v2 breaking change lives in `models/schemas/v2/`
  without touching v1 Pydantic models. Existing consumers never break.
- Response header: `X-API-Version: 1.0.0` on every response
- Deprecation headers when sunsetting: `Deprecation: true`, `Sunset: <date>`, `Link: </api/v2/...>`
- OpenAPI spec auto-generated at `/docs` (Swagger UI) and `/redoc`

---

## 3. Features

### Tenant & Account Management

- **Platform Admin** creates tenant accounts (name, plan tier, contact email)
- Suspend or reactivate tenant accounts from the platform admin UI
- Platform-wide health view: active tenants, sources monitored, alerts today
- **Tenant Admin** invites users by email (Admin and Operator roles)
- Deactivate users, view last login timestamps
- **Authentication:** email + password -> RS256 JWT (15-min access token, 7-day refresh)
- Logout revokes the refresh token server-side; token refresh without re-login

---

### Log Source Configuration

Three connector types (see Architecture section above). Per-source configuration:

- **Poll interval:** 1s-300s, adaptive by default (backs off on consecutive empty polls)
- **EWMA tuning per source:** alpha (0.1-0.9), sensitivity multiplier (1.5-5.0), warmup period (5-50 observations)
- **Latency field name:** when specified, enables LATENCY_SPIKE detection on that JSON field
- **Log format:** JSON-per-line, logfmt, or plain text (regex-parsed)
- **Maintenance windows:** suppresses SERVICE_SILENCE alerts during configured downtime
- Source health status visible in admin panel: active / idle / backoff / error
- DB connection strings encrypted at rest (Fernet), never returned after initial save

---

### Anomaly Detection — Six Types

| Type | Plain English | Severity | Auto-Resolves |
|------|--------------|----------|---------------|
| **ERROR_RATE_SPIKE** | The 1-minute error rate just blew past the EWMA upper bound — something broke suddenly | WARNING at 2.5x sigma, CRITICAL at 5x sigma | Yes — 2 consecutive clean windows |
| **SUSTAINED_ELEVATION** | Error rate is above baseline and has stayed there for 10+ minutes — systemic, not a blip | WARNING at 10min, CRITICAL at 15min | Yes — when rate returns to baseline |
| **SERVICE_SILENCE** | A previously active service has emitted zero logs for 2+ minutes — likely crashed or network-partitioned | CRITICAL always | Yes — when logs resume |
| **LATENCY_SPIKE** | The latency field in log entries is spiking beyond its EWMA upper bound — slow responses degrading UX | WARNING/CRITICAL same as error rate | Yes — 2 clean windows |
| **NOVEL_ERROR** | An error message pattern appeared that has not been seen in the past 24 hours — a new failure mode | WARNING (leading indicator) | N/A — point-in-time |
| **CASCADE** | Three or more services triggered ERROR_RATE_SPIKE within a 5-minute window — shared infrastructure failure | CRITICAL always | Yes — when all contributing alerts resolve |

Every alert stores a full evidence snapshot at detection time: current value, EWMA baseline,
upper bound, analysis window timestamps, sample count, top 3 representative error messages,
and all EWMA parameters used — making every alert fully auditable and explainable.

---

### Alert Management & Lifecycle

- **Lifecycle:** `open` -> `acknowledged` -> `resolved`
- **Auto-resolution:** Watchdog marks alerts resolved when the anomaly condition clears
- **Manual acknowledgment:** Tenant Operator or Admin via dashboard ACK button or API
- **Filtering:** service name, severity, anomaly type, status, date range
- **Pagination:** cursor-based (stable under concurrent inserts)
- **Retention:** configurable per tenant (default 30 days). Open alerts are **never** auto-deleted.

---

### API Key Self-Service

- Generate keys from the consumer portal — no Admin involvement required
- **Format:** `wdog_live_<32-byte-random>` (production) or `wdog_test_<32-byte-random>` (test)
- Plaintext returned **exactly once** at creation — never stored, never retrievable again
- SHA-256 hash persisted for O(1) lookup — zero timing-attack surface
- **Four scopes:** `ingest`, `alerts:read`, `webhooks:manage`, `sources:read`
- **Zero-downtime rotation:** rotate generates a new key; old key enters 24-hour grace period
  during which both keys are valid. Background job revokes the old key after 24h.
- Immediate revocation available (bypasses grace period)
- Last-used timestamp visible in portal; key value never shown after creation

---

### Webhook Push Delivery

- Register a webhook URL against an API key (with optional severity and service filters)
- Watchdog generates a per-webhook HMAC signing secret at registration — shown once, stored
  Fernet-encrypted (must be retrievable for HMAC computation — cannot hash)
- **Delivery headers:** `X-Watchdog-Signature: sha256=<hex>`, `X-Watchdog-Delivery-ID: <uuid>`,
  `X-Watchdog-Event: anomaly.detected`
- **Retry policy:** 3 attempts, exponential backoff (2s -> 4s -> 8s)
- All delivery attempts logged (status code, latency, response body)
- Webhook auto-disabled after 10 consecutive failures; re-enable in consumer portal
- Full delivery history visible in portal (last 100 attempts per webhook)

**Consumer signature verification (Python):**
```python
import hmac, hashlib

def verify_webhook(payload: bytes, secret: str, signature_header: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)
    # MUST use compare_digest — string equality is timing-vulnerable
```

---

### Dashboards & UI

| View | URL | Role | What it shows |
|------|-----|------|---------------|
| **Operator Dashboard** | `/dashboard` | Operator, Admin | Stat cards (open/warning/resolved/sources), recent alerts table with ACK button, 24h trend chart with 6h/24h/72h toggle, 30s auto-refresh |
| **Tenant Admin** | `/admin` | Admin only | Log sources (add/delete), user management (invite/remove), retention policy |
| **Consumer Portal** | `/consumer` | All authenticated | API keys (create/rotate/revoke), webhook attachment, key prefix and scope display |
| **Platform Admin** | `/platform-admin` | Platform Admin | Tenant list (activate/suspend/plan), platform health summary |

All four views are server-rendered Jinja2 templates. Alpine.js handles client-side reactivity
(auto-refresh, form state, inline ACK). Chart.js renders the trend chart from
`/api/v1/dashboard/trend` JSON. No npm, no build pipeline, no second server process.

---

### Security Features

- RS256 JWT (asymmetric) — public key verifiable without exposing private key
- Fernet-encrypted secrets at rest (webhook signing secrets, DB connection strings)
- SHA-256 hashed API keys (one-way — never retrieved, only compared)
- bcrypt cost-12 password hashing
- TenantContext pattern — every query is scoped to a verified `tenant_id`
- Rate limiting on ingest (100/min) and auth (10/min) via slowapi
- Pydantic validation on every request body — 422 on malformed input
- No SQL string concatenation — SQLAlchemy ORM/Core only
- No secrets in API responses after initial creation
- No secrets in log lines — `api_key_id` (UUID) logged, never the key value
- CORS explicit allowlist — never wildcard
- `X-Request-ID` on every response for distributed tracing
- `X-API-Version` on every response

---

### Background Jobs

| Job | Trigger | What it does |
|-----|---------|--------------|
| Connector polling | asyncio task per active source | Tails files, polls DB tables, routes entries to anomaly engine |
| EWMA persistence | Every 10 events + graceful shutdown | Writes in-memory EWMA state to `ewma_state` table |
| Webhook retry | Every 30s | Retries failed deliveries with exponential backoff; auto-disables after 10 failures |
| Retention cleanup | Every hour | Deletes resolved/acknowledged alerts and webhook events older than tenant's retention setting |
| Key expiry | Every hour | Marks keys `revoked_at` when `expires_at` elapsed or grace period ended |

---

## 4. Security Architecture

### Three-Tier Secret Storage Model

Every secret in Watchdog is assigned to exactly one storage tier. Conflating tiers is a
code review failure.

| Tier | What | How stored | Why |
|------|------|-----------|-----|
| **Tier 1 — Never stored** | API key plaintext | Returned once in response, then discarded. Never written to DB, logs, or cache. | Cannot leak from a DB breach if it is never in the DB |
| **Tier 2 — Hashed (one-way)** | User passwords, API key hashes, refresh token hashes | bcrypt cost-12 (passwords) · SHA-256 (keys, tokens) | We verify, never retrieve. Hash comparison is sufficient for all operations. |
| **Tier 3 — Encrypted (two-way)** | Webhook signing secrets · DB connector connection strings | Fernet AES-128-CBC + HMAC-SHA256 | Must be retrieved: signing secret decrypted on each webhook delivery; connection string decrypted at connector startup. Encryption key lives in `.env` only. |

**Why Fernet over AES-GCM directly:** Fernet is an authenticated encryption scheme —
it validates the key and integrity on decrypt, preventing padding oracle and bit-flip attacks.
It is a higher-level abstraction than raw AES with fewer implementation footguns.

---

### API Key Format — Why Prefixed Keys Matter

```
wdog_live_vmKcah-ElpmRfQBi1TVu8n6Xgn2T-3vG8HR8gmVh6lE
wdog_test_g0rbgYm2u4u1lWiP-GE3wx8ZDV4h0svP5xxYoNJw4vI
```

The `wdog_live_` and `wdog_test_` prefixes enable **automated secret scanning**:

- **GitHub secret scanning** can be configured with a custom pattern to block pushes containing
  `wdog_live_` keys — preventing accidental commit of production credentials.
- **truffleHog** and similar git history scanners detect the pattern in CI/CD pipelines.
- The prefix immediately signals to an operator reviewing logs whether a key is production
  or test — no guessing from an opaque token.
- First 12 characters (`wdog_test_vm...`) stored as `key_prefix` for UI display — operators
  can identify a key without ever seeing the sensitive portion.

---

### Tenant Data Isolation — TenantContext Pattern

```python
class TenantContext:
    tenant_id: str       # verified from JWT or API key — never from request params
    user_id: str | None  # None for API key auth
    api_key_id: str | None
    role: Role
    scopes: list[str]
```

Every route handler receives a `TenantContext` injected by FastAPI's dependency system.
The `tenant_id` inside it is extracted from the cryptographically verified JWT or from the
API key record in the database — never from a URL parameter, query string, or request body.
A request body that includes a `tenant_id` field is ignored for access control; the verified
context is the sole source of truth.

This eliminates **Insecure Direct Object Reference (IDOR)** vulnerabilities: there is no
path by which a caller of tenant A can pass tenant B's UUID and receive tenant B's data.
The application layer makes it structurally impossible, not just "checked at the top of the function."

---

### What Was Considered But Not Implemented: Row Level Security

PostgreSQL Row Level Security would add a database-layer tenant isolation guarantee:

```sql
-- PostgreSQL only — not implemented in SQLite MVP
ALTER TABLE anomaly_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON anomaly_alerts
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

With RLS, even a SQL injection or application-layer RBAC bug cannot return cross-tenant data —
the database engine enforces isolation independently.

**Why not in MVP:** SQLite does not support RLS. The TenantContext pattern provides equivalent
isolation at the application layer for a single-process deployment. The eval suite
(`tests/evals/eval_cross_tenant_isolation.py`) verifies 100% isolation across all resource
types with every test run.

**Upgrade path:** Migrate to PostgreSQL, add `SET app.tenant_id = :tenant_id` at session
start via a SQLAlchemy event listener, and enable the RLS policies above. The TenantContext
pattern remains in place — RLS becomes defense-in-depth, not a replacement.

---

### Credential Hygiene Rules — Enforced in Every Line of Code

1. `X-API-Key` header value is **never** written to any log line or error response
2. `Authorization` header value is **never** logged
3. `api_key_id` (UUID) is logged instead of key values — operators can trace which key was used
4. Connection strings are masked in API responses (first 20 chars only) after initial save
5. `.env` is in `.gitignore` — only `.env.example` with placeholder values is committed
6. Seed scripts contain no real secrets — `prompts.md` audit log contains no secrets
7. Webhook signing secrets encrypted, not hashed — Fernet key in `.env` only

---

## 5. Screenshots

### Login Page

![Login page — email/password form with v1.0.0 version badge](images/1.png)

Clean, minimal login form. Version badge bottom-center. No credential hints exposed.

---

### Operator Dashboard — Admin View (Full Nav)

![Operator Dashboard as Tenant Admin — showing all three nav items, stat cards, open alerts, ACK buttons, and trend chart](images/2.png)

Stat cards showing 4 open (2 critical), 2 warnings, 3 resolved, 2 active sources.
Recent alerts table with color-coded CRITICAL/WARNING badges and inline ACK buttons.
Trend chart below. Nav shows Dashboard, Admin, API Keys — all three tabs visible for Admin role.

---

### Operator Dashboard — All Statuses View

![Dashboard showing all 10 alerts across open, acknowledged, and resolved statuses](images/3.png)

All-statuses filter showing the full alert lifecycle: 4 open with ACK buttons (top),
3 acknowledged (purple badge, no ACK button), 3 resolved (green badge). Demonstrates
the complete alert state machine in one view.

---

### Admin Panel — Sources Tab

![Tenant Admin panel, Sources tab: two push/JSON sources with Delete button](images/4.png)

Log source list for Acme Corp. Both sources are `push` type (zero-config integration).

### Admin Panel — Add Log Source Modal

![Add Log Source modal with Name, Service Name, Source Type dropdown, File Path / Connection String conditional fields, Poll Interval, Environment, and Latency Field inputs](images/4a.png)

Add Source form. Source Type drives conditional field visibility: selecting `file` reveals the File Path input; selecting a database type reveals the Connection String field (masked, Fernet-encrypted at rest and never returned in API responses).
Shows service name, connector type, log format, poll interval, active status.
`+ Add Source` button top-right. Delete button per source.

---

### Admin Panel — Users Tab

![Tenant Admin panel, Users tab: two users with roles, active status, last login timestamps](images/5.png)

User management view. Shows email, role, active status, and last login timestamp with

### Admin Panel — Add User Modal

![Add User modal with Email, Password, and Role dropdown (Operator / Admin)](images/5a.png)

Add User form. Role is constrained to `tenant_operator` or `tenant_admin` — Tenant Admins cannot promote users to `platform_admin`.
real session times. `+ Add User` and Remove buttons present.

---

### Admin Panel — Retention Policy Tab

![Retention Policy form: Alert Retention 30 days, Log Retention 7 days, Save button](images/6.png)

Per-tenant retention configuration. Alert retention (default 30 days) and log retention
(default 7 days) are independently configurable. Changes persist immediately.

---

### Consumer Portal — Admin View

![Consumer Portal showing acme-corp-test-key with wdog_test_ prefix, alerts:read scope, + Attach webhook, Rotate and Revoke buttons](images/7.png)

API key management. Key prefix (`wdog_test_vm...`) displayed — full value never shown.
Scope, environment badge, webhook attachment status, expiry, and rotation/revocation controls.

---

### Operator Dashboard — Operator View (Restricted Nav)

![Dashboard as ops@acme.example.com with Operator role — only Dashboard and API Keys in nav, no Admin tab](images/8.png)

Same dashboard data as Admin view but with the role-restricted nav: Operator role sees
Dashboard and API Keys only. Admin tab is absent. `ops@acme.example.com [Operator]` in
the top-right confirms correct identity display.

---

### Alert Trend Chart — 24-Hour View

![Alert Trend 24h line chart showing 10 alerts detected from 21:00 through 06:00, flat zero before and after](images/9.png)

Chart.js trend chart showing the seeded anomaly detection window: 10 alerts distributed
across hours 21:00-06:00. Zero-activity baseline before the incident window is clearly
visible. Auto-refreshes every 30s without flash (update-in-place rendering via `chart.update('none')`).

---

### Consumer Portal — Operator View

![Consumer Portal as ops@acme.example.com — same API key management, Operator-restricted nav](images/10.png)

Operator-role consumer portal. Identical key management capability (all authenticated users
can manage their own API keys). Nav correctly shows Dashboard and API Keys only — Admin
tab absent, confirming role-based nav restriction is working correctly.

---

## Quick API Reference

### Data Flow Overview

```
Apps Being Monitored                    Alert Consumers

─────────────────────                   ───────────────

Push logs via /ingest    →  Watchdog  → Poll GET /alerts

File connector (auto)    →  EWMA AI   → Webhook push

DB connector (auto)      →  Detection → Real-time alerts
```

### Group A — Log Ingestion

For applications whose logs Watchdog is monitoring.  
Auth: API Key (`scope: ingest`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ingest` | Push single log entry |
| POST | `/api/v1/ingest/batch` | Push up to 500 entries |

### Group B — Anomaly Consumer APIs

For systems that want to receive detected anomalies.  
Auth: API Key (`scope: alerts:read`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/alerts` | List anomalies (filterable, paginated) |
| GET | `/api/v1/alerts/{id}` | Full anomaly detail + AI enrichment |
| POST | `/api/v1/alerts/{id}/acknowledge` | Mark alert as seen |

### Group C — Webhook Subscriptions

Receive anomalies pushed to your endpoint in real time.  
Auth: API Key (`scope: webhooks:manage`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/admin/keys/{id}/webhook` | Register webhook URL |
| GET | `/api/v1/admin/keys` | List keys + attached webhook URLs |
| DELETE | `/api/v1/admin/keys/{id}/webhook` | Remove webhook |

Delivery: HMAC-SHA256 signed POST to your URL.  
Retry: 3 attempts, backoff 2s / 4s / 8s.  
Headers: `X-Watchdog-Signature`, `X-Watchdog-Delivery-Id`

### Group D — Source Management

For Tenant Admins connecting log sources.  
Auth: JWT (Tenant Admin role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/admin/sources` | Connect a new log source |
| GET | `/api/v1/admin/sources` | List sources + connector status |
| PATCH | `/api/v1/admin/sources/{id}` | Update source config |
| DELETE | `/api/v1/admin/sources/{id}` | Disconnect source |

### Group E — Key & User Management

Auth: JWT (Tenant Admin role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/admin/keys` | Generate API key (shown once) |
| GET | `/api/v1/admin/keys` | List keys (prefix only, never value) |
| POST | `/api/v1/admin/keys/{id}/rotate` | Rotate with 24h grace period |
| DELETE | `/api/v1/admin/keys/{id}` | Revoke immediately |
| POST | `/api/v1/admin/users` | Invite user to tenant |

### Group F — Platform Administration

Auth: JWT (Platform Admin role only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/platform/tenants` | Create tenant account |
| GET | `/api/v1/platform/tenants` | List all tenants |
| PATCH | `/api/v1/platform/tenants/{id}` | Suspend / reactivate |

### Group G — Health

Auth: None required

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | App status, DB, cache, engine |

---

Full request/response schemas, curl examples, and webhook integration guide: see [Section 8 — API Reference](#8-api-reference).  
Interactive API explorer: `http://127.0.0.1:8080/docs`

---

## 6. Roles & Access Control

| Role | Created By | UI Pages | API Endpoints | Cannot Do |
|------|-----------|----------|---------------|-----------|
| **Platform Admin** | Bootstrap (`.env` on first start) | `/platform-admin` | `POST /api/v1/platform/tenants`, `GET/PATCH /api/v1/platform/tenants/{id}`, `GET /api/v1/platform/health` | Access any tenant's data, alerts, sources, or users directly |
| **Tenant Admin** | Platform Admin | `/dashboard`, `/admin`, `/consumer` | All Operator endpoints + source CRUD, user management, retention config, all tenant API keys | Access another tenant's data; create or delete tenants |
| **Tenant Operator** | Tenant Admin | `/dashboard`, `/consumer` | `GET /api/v1/alerts*`, `POST /api/v1/alerts/{id}/acknowledge`, `GET /api/v1/dashboard/*`, own API key management | Access `/admin` panel; manage sources, users, or other tenants' keys |
| **API Consumer** (machine identity) | Any authenticated user (JWT required to create keys) | None — API only | Endpoints matching key scopes: `ingest`, `alerts:read`, `webhooks:manage`, `sources:read` | Exceed key scopes; access any other tenant's data; create users or sources |

**Enforcement mechanics:**

- Role hierarchy enforced by `require_role(Role.X)` FastAPI dependency on every route handler
- API keys checked for scope on every request — even a tenant_admin key is rejected on an
  endpoint requiring a scope not in the key's list
- JWT auth required to create API keys — API keys cannot mint more API keys
- Platform Admin is explicitly excluded from the tenant role hierarchy — cannot access
  tenant-scoped endpoints (correct by design: Platform Admin manages tenants, not their data)

---

## 7. Architectural Decisions & Tradeoffs

Full decision reasoning is documented in `ARCHITECTURE.md`. This table summarizes the 18 key
decisions grouped by area.

### Data Architecture

| # | Decision | Choice Made | Key Tradeoff |
|---|----------|------------|--------------|
| 1 | Primary key format | UUIDs (text) | Prevents enumeration attacks, safe in URLs; slightly larger than integer PKs |
| 2 | Database engine | SQLite (dev) / PostgreSQL (prod) | Zero-config local dev; SQLite has write concurrency limits that PostgreSQL resolves |
| 3 | Raw log storage | Not stored — anomaly alerts with evidence snapshots only | Keeps DB lean and write load minimal; raw logs not recoverable post-detection |
| 4 | Schema migrations | Alembic only, no DDL in application code | All changes versioned and reversible; `create_all()` banned in production paths |
| 5 | Soft deletes | `deleted_at` nullable timestamp on audit tables | Audit data preserved; queries require `WHERE deleted_at IS NULL` filter |

### Security

| # | Decision | Choice Made | Key Tradeoff |
|---|----------|------------|--------------|
| 6 | JWT algorithm | RS256 asymmetric | Public key verifiable without exposing signing key; symmetric HS256 simpler but requires secret sharing |
| 7 | API key storage | SHA-256 hash only, plaintext never persisted | DB breach cannot expose keys; plaintext unrecoverable (rotate to get a new key) |
| 8 | Webhook secret storage | Fernet-encrypted (two-way) | Must be retrieved for HMAC computation — hashing would make signing impossible |
| 9 | Tenant isolation | Application layer (TenantContext) + PostgreSQL RLS upgrade path documented | Application isolation sufficient for MVP; RLS provides defense-in-depth requiring PostgreSQL |
| 10 | API key prefix format | `wdog_live_` / `wdog_test_` | Enables automated secret scanning in git history and CI; slightly longer format |

### Detection Algorithm

| # | Decision | Choice Made | Key Tradeoff |
|---|----------|------------|--------------|
| 11 | Anomaly detection | EWMA with adaptive variance tracking | Fully explainable, zero cold-start, incremental; lacks seasonality (Prophet upgrade path documented) |
| 12 | EWMA state persistence | In-memory dict, persisted every 10 events + graceful shutdown | Avoids DB write per ingest; state lost if process killed non-gracefully |
| 13 | False positive suppression | Warmup period + per-source sensitivity tuning | Configurable without code changes; operators tune thresholds per service |

### Frontend

| # | Decision | Choice Made | Key Tradeoff |
|---|----------|------------|--------------|
| 14 | Rendering model | Jinja2 server-rendering + Alpine.js reactivity | No build pipeline, no second process, role enforcement server-side; less rich than SPA framework |
| 15 | Chart rendering | Chart.js via CDN, update-in-place on refresh | Zero build step; `chart.update('none')` eliminates canvas flash on auto-refresh cycles |
| 16 | Frontend framework | Alpine.js (not React/Vue/Svelte) | 15KB, no npm, readable by any Python engineer; cannot handle large component trees as well as React |

### Infrastructure

| # | Decision | Choice Made | Key Tradeoff |
|---|----------|------------|--------------|
| 17 | Caching | In-process dict + `CacheBackend` ABC | Zero dependencies for MVP; cache lost on restart; `CACHE_BACKEND=redis` activates `RedisCache` |
| 18 | Background scheduling | asyncio tasks in FastAPI lifespan | No external scheduler dependency; tasks die with the process (acceptable for single-process MVP) |

---

## 8. API Reference

This section is a complete developer reference derived directly from the router and
schema source files. Every endpoint, field name, type, constraint, and error code
listed here matches the running code exactly.

---

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   Monitored App          Watchdog                Alert Consumer     │
│   ─────────────          ─────────────────────   ─────────────────  │
│                          ┌─────────────────┐                        │
│  POST /ingest ──────────►│  Log Ingest     │                        │
│  POST /ingest/batch      │  Pipeline       │                        │
│                          │                 │                        │
│  File Connector ────────►│  EWMA Anomaly   │──► GET /alerts         │
│  DB Connector            │  Detection      │    (Group B: pull)     │
│                          │  Engine         │                        │
│  (Group A: push/pull)    │                 │──► Webhook POST        │
│                          └─────────────────┘    (Group B: push)    │
│                                                                     │
│  ─────────────────────────────────────────────────────────────────  │
│  Tenant Admin: /api/v1/admin/* (Group C) — configure sources,      │
│  users, API keys, webhooks, and retention                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Three API groups — each serves a different caller:**

| Group | Who calls it | What it does |
|-------|-------------|--------------|
| **A — Data Ingestion** | The application being monitored | Sends log entries into Watchdog for analysis |
| **B — Anomaly Consumer** | Incident management, alerting tools | Receives detected anomalies (pull or push) |
| **C — Management** | Tenant Admins | Configures sources, users, keys, and retention |

---

### 8.0 Base URL & Authentication

**Base URL:** `http://127.0.0.1:8080`  
**OpenAPI UI:** `http://127.0.0.1:8080/docs`  
**ReDoc:** `http://127.0.0.1:8080/redoc`

#### Authentication methods

Watchdog supports two credential types on every protected endpoint. Use whichever
fits the caller's context:

| Method | Header | Who uses it |
|--------|--------|-------------|
| JWT Bearer | `Authorization: Bearer <access_token>` | Human operators logged in via the UI or `/api/v1/auth/login` |
| API Key | `X-API-Key: <key>` | Machine consumers (CI pipelines, integrations). Scoped to explicit permissions. |

**JWT access token payload** (RS256-signed, 15-minute lifetime):

```json
{
  "sub":       "<user_uuid>",
  "email":     "admin@acme.example.com",
  "tenant_id": "<tenant_uuid>",
  "role":      "tenant_admin",
  "type":      "access",
  "jti":       "<uuid>",
  "iat":       1751000000,
  "exp":       1751000900
}
```

**API key format:** `wdog_live_<43-char-urlsafe-base64>` or `wdog_test_<43-char-urlsafe-base64>`  
The prefix (`live` / `test`) reflects the environment the key was minted for.
Only the first 12 characters (the prefix portion) are ever stored or returned
after creation — the full plaintext is returned exactly once and never retrievable again.

#### Role hierarchy

Roles are enforced on every JWT-authenticated request. API key callers are always
`tenant_operator` role, further restricted to their explicit scopes.

| Role | Level | Can access |
|------|-------|------------|
| `tenant_operator` | 0 | Alerts (read), dashboard, ingest (via API key) |
| `tenant_admin` | 1 | Everything operator can + sources, users, keys, config |
| `platform_admin` | — | Platform-only endpoints (`/api/v1/platform/*`) only |

`platform_admin` is intentionally excluded from the tenant role hierarchy.
A Platform Admin cannot call tenant-scoped endpoints — they must use the
`/api/v1/platform/*` surface.

#### API key scopes

Scopes restrict what an API key may call. JWT users bypass scope checks — their
access is governed by role alone.

| Scope | Permits |
|-------|---------|
| `ingest` | `POST /api/v1/ingest` and `POST /api/v1/ingest/batch` |
| `alerts:read` | `GET /api/v1/alerts` and `GET /api/v1/alerts/{id}` |
| `webhooks:manage` | Webhook attach / detach endpoints |
| `sources:read` | `GET /api/v1/admin/sources` and `GET /api/v1/admin/sources/{id}` |

#### Rate limits

| Surface | Limit |
|---------|-------|
| Auth endpoints (`/api/v1/auth/*`) | 10 requests / minute per IP |
| Ingest endpoints (`/api/v1/ingest*`) | 100 requests / minute per API key |

Rate-limited responses return `HTTP 429` with a `Retry-After` header.

#### Error envelope

All error responses use a consistent JSON structure:

```json
{
  "detail": {
    "code":    "MACHINE_READABLE_CODE",
    "message": "Human-readable description"
  }
}
```

Common error codes across all endpoints:

| Code | Status | Meaning |
|------|--------|---------|
| `NOT_AUTHENTICATED` | 401 | No `Authorization` or `X-API-Key` header present |
| `TOKEN_EXPIRED` | 401 | JWT access token past its `exp` claim |
| `TOKEN_INVALID` | 401 | JWT signature invalid or malformed |
| `KEY_INVALID` | 401 | API key hash not found |
| `KEY_REVOKED` | 401 | API key explicitly revoked or grace period expired |
| `KEY_EXPIRED` | 401 | API key past its `expires_at` date |
| `INSUFFICIENT_ROLE` | 403 | Caller's role is below the required minimum |
| `INSUFFICIENT_SCOPE` | 403 | API key missing required scope |
| `PLATFORM_ADMIN_REQUIRED` | 403 | Endpoint requires `platform_admin` role |

---

### 8.1 Authentication — `/api/v1/auth`

**Rate limit:** 10 requests / minute per IP on all auth endpoints.

---

#### `POST /api/v1/auth/login`

Exchange email + password for a short-lived access token and a long-lived
httpOnly refresh cookie.

**Auth required:** None

**Request body:**

```json
{
  "email":    "admin@acme.example.com",
  "password": "WatchdogDemo1!"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User's email address (case-insensitive) |
| `password` | string | Yes | Plaintext password |

**Response `200 OK`:**

```json
{
  "access_token": "<RS256-signed JWT>",
  "token_type":   "bearer",
  "expires_in":   900
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | RS256 JWT — include as `Authorization: Bearer <value>` |
| `token_type` | string | Always `"bearer"` |
| `expires_in` | integer | Seconds until access token expires (default 900 = 15 min) |

A `Set-Cookie: refresh_token=<value>; HttpOnly; SameSite=Strict; Path=/api/v1/auth`
header is also set. The cookie is not accessible from JavaScript and is used only
by `/api/v1/auth/refresh`.

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `INVALID_CREDENTIALS` | 401 | Wrong email, wrong password, or inactive account. Response is identical for all three — no enumeration possible. |

**curl example (demo tenant):**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"admin@acme.example.com","password":"WatchdogDemo1!"}'
```

---

#### `POST /api/v1/auth/logout`

Revoke the current refresh token and clear the httpOnly cookie.
Safe to call even if no cookie is present or the token is already revoked.

**Auth required:** httpOnly `refresh_token` cookie (optional — no error if absent)

**Response:** `204 No Content`

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/logout \
  -b cookies.txt -c cookies.txt
```

---

#### `POST /api/v1/auth/refresh`

Exchange the httpOnly refresh cookie for a new access token without re-entering
credentials. The refresh cookie itself is NOT rotated — the same cookie remains
valid for its 7-day lifetime or until `/logout` is called.

**Auth required:** httpOnly `refresh_token` cookie

**Response `200 OK`:** Same shape as `/login` response.

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `REFRESH_TOKEN_MISSING` | 401 | No refresh cookie present |
| `REFRESH_TOKEN_INVALID` | 401 | Token revoked, expired, or signature invalid |
| `USER_NOT_FOUND` | 401 | User account deactivated since token was issued |

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/refresh \
  -b cookies.txt
```

---

## Group A — Data Ingestion APIs

> **Caller:** The application whose logs you want Watchdog to monitor.
> These endpoints are called by your running service, not by operators or consumers.
> Use an API key with the `ingest` scope — no JWT, no human interaction required.

---

### 8.2 Log Ingest — `/api/v1/ingest`

**Auth required:** API key with `ingest` scope (`X-API-Key` header).  
JWT authentication is not accepted on ingest endpoints — ingest is machine-to-machine only.  
**Rate limit:** 100 requests / minute per API key.

---

#### `POST /api/v1/ingest`

Push a single log entry for real-time anomaly processing.

**Important:** Raw log entries are **not persisted** to the database. They flow
directly into the EWMA anomaly engine. The `id` in the response is a request-scoped
correlation UUID, not a database primary key.

**Request body:**

```json
{
  "message":     "upstream database connection timeout after 5002ms",
  "level":       "ERROR",
  "occurred_at": "2026-06-28T10:00:00Z",
  "service_name": "payment-service",
  "latency_ms":  5002.0,
  "metadata":    {"region": "us-east-1", "pod": "payment-7f9b4"}
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `message` | string | Yes | — | min length 1 |
| `level` | string | No | `"INFO"` | One of: `ERROR`, `WARNING`, `INFO`, `DEBUG`, `TRACE`, `CRITICAL`, `UNKNOWN` |
| `occurred_at` | datetime (ISO 8601) | No | Server UTC clock | Future timestamps accepted — client is authoritative over event time |
| `service_name` | string | No | `null` | Routed to the source matching this name for the tenant |
| `latency_ms` | float | No | `null` | Must be >= 0. Used by `LATENCY_SPIKE` detection. |
| `metadata` | object | No | `null` | Arbitrary key-value pairs passed through to alert context |

**Response `201 Created`:**

```json
{
  "id":          "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "tenant_id":   "<tenant_uuid>",
  "received_at": "2026-06-28T10:00:00.123456Z",
  "status":      "accepted"
}
```

**curl example (using seeded test key):**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/ingest \
  -H "X-API-Key: wdog_test_vmKcah-ElpmRfQBi1TVu8n6Xgn2T-3vG8HR8gmVh6lE" \
  -H "Content-Type: application/json" \
  -d '{"message":"DB connection pool exhausted","level":"ERROR","service_name":"api","latency_ms":3200}'
```

---

#### `POST /api/v1/ingest/batch`

Push up to 500 log entries in a single request. Batch validation is transactional —
one invalid entry rejects the entire batch with `422`.

**Request body:**

```json
{
  "entries": [
    {"message": "request ok", "level": "INFO", "service_name": "api"},
    {"message": "timeout", "level": "ERROR", "service_name": "api", "latency_ms": 8001}
  ]
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `entries` | array of `LogEntryRequest` | Yes | 1 – 500 entries |

**Response `201 Created`:**

```json
{
  "accepted": 2,
  "status":   "accepted"
}
```

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/ingest/batch \
  -H "X-API-Key: wdog_test_vmKcah-ElpmRfQBi1TVu8n6Xgn2T-3vG8HR8gmVh6lE" \
  -H "Content-Type: application/json" \
  -d '{"entries":[{"message":"health ok","level":"INFO","service_name":"api"},{"message":"503 upstream","level":"ERROR","service_name":"api"}]}'
```

---

## Group B — Anomaly Consumer APIs

> **Caller:** Systems that want to receive Watchdog's detections — incident management
> tools, on-call platforms, custom dashboards, or any service that acts on anomalies.
> Two delivery modes:
>
> - **Pull** — poll `GET /api/v1/alerts` on your schedule
> - **Push** — register a webhook URL; Watchdog will POST signed alert payloads in real time

---

### 8.3 Alerts — `/api/v1/alerts`

**Auth required:** JWT (role: `tenant_operator` or higher) **or** API key with
`alerts:read` scope.  
All queries are automatically scoped to the authenticated tenant — cross-tenant
access is architecturally impossible.

---

#### `GET /api/v1/alerts`

List anomaly alerts with optional filters and stable cursor-based pagination.
Results are sorted by `detected_at DESC, id DESC` (newest first).

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `open`, `acknowledged`, or `resolved` |
| `severity` | string | Filter by severity: `WARNING` or `CRITICAL` |
| `anomaly_type` | string | Filter by type (see Anomaly Type Reference below) |
| `service` | string | Filter by exact `service_name` |
| `since` | ISO 8601 datetime | Only return alerts detected after this timestamp |
| `until` | ISO 8601 datetime | Only return alerts detected before this timestamp |
| `cursor` | string | Opaque pagination cursor from a previous response's `next_cursor` field |
| `limit` | integer | Page size, 1–100, default 20 |

**Response `200 OK`:**

```json
{
  "items": [
    {
      "id":                  "<uuid>",
      "tenant_id":           "<tenant_uuid>",
      "source_id":           "<source_uuid>",
      "detected_at":         "2026-06-28T09:45:00Z",
      "anomaly_type":        "ERROR_RATE_SPIKE",
      "severity":            "CRITICAL",
      "service_name":        "payment-service",
      "environment":         "production",
      "current_value":       0.47,
      "baseline_value":      0.03,
      "upper_bound":         0.12,
      "unit":                "error_rate",
      "window_start":        "2026-06-28T09:40:00Z",
      "window_end":          "2026-06-28T09:45:00Z",
      "sample_count":        300,
      "representative_msgs": "[\"DB timeout\", \"Connection refused\"]",
      "detection_context":   "{\"ewma_alpha\": 0.3, \"sensitivity\": 5.0}",
      "cascade_context":     null,
      "full_payload":        "{...complete v1.0 contract...}",
      "status":              "open",
      "acknowledged_by":     null,
      "acknowledged_at":     null,
      "resolved_at":         null,
      "auto_resolved":       null,
      "created_at":          "2026-06-28T09:45:01Z"
    }
  ],
  "next_cursor":    "eyJkZXRlY3RlZF9hdCI6ICIyMDI2...",
  "total_returned": 20
}
```

**Cursor pagination:** To fetch the next page, pass the `next_cursor` value from
the response as the `cursor` query parameter on the next request. When
`next_cursor` is `null`, you have reached the last page. Cursors encode
`(detected_at, id)` of the last item returned — they are stable under concurrent
inserts.

**curl example:**

```bash
curl "http://127.0.0.1:8080/api/v1/alerts?status=open&severity=CRITICAL&limit=10" \
  -H "Authorization: Bearer <access_token>"
```

**Fetch next page:**

```bash
curl "http://127.0.0.1:8080/api/v1/alerts?status=open&cursor=eyJkZXRlY3RlZF9hdCI6..." \
  -H "Authorization: Bearer <access_token>"
```

---

#### `GET /api/v1/alerts/{alert_id}`

Get a single alert by UUID. Returns `404` if the alert ID belongs to a different
tenant — this is intentional (prevents enumeration across tenants).

**Path parameters:** `alert_id` — UUID string

**Response `200 OK`:** Single `AnomalyAlertResponse` object (same shape as items in the list response).

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `ALERT_NOT_FOUND` | 404 | Alert does not exist or belongs to another tenant |

**curl example:**

```bash
curl http://127.0.0.1:8080/api/v1/alerts/<alert_uuid> \
  -H "Authorization: Bearer <access_token>"
```

---

#### `POST /api/v1/alerts/{alert_id}/acknowledge`

Mark an open alert as acknowledged. Records the acknowledging user's ID and
the acknowledgment timestamp.

**Auth required:** JWT only (API keys cannot acknowledge alerts).  
**Role required:** `tenant_operator` or higher.  
**Idempotent:** Acknowledging an already-acknowledged alert returns `200` with
the existing metadata unchanged. Acknowledging a `resolved` alert returns `409`.

**Request body:** None (no body required)

**Response `200 OK`:**

```json
{
  "id":               "<alert_uuid>",
  "status":           "acknowledged",
  "acknowledged_at":  "2026-06-28T10:01:30Z",
  "acknowledged_by":  "<user_uuid>"
}
```

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `ALERT_NOT_FOUND` | 404 | Alert not found in this tenant |
| `ALERT_RESOLVED` | 409 | Alert is already resolved — cannot be acknowledged |

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/alerts/<alert_uuid>/acknowledge \
  -H "Authorization: Bearer <access_token>"
```

---

#### Anomaly Type Reference

The `anomaly_type` field on every alert is one of the following six values,
corresponding to the six detection algorithms in `services/anomaly_engine.py`:

| Type | Severity range | Description |
|------|---------------|-------------|
| `ERROR_RATE_SPIKE` | WARNING / CRITICAL | Fraction of ERROR/CRITICAL log entries exceeds the EWMA upper bound. WARNING fires at 2.5× std deviation; CRITICAL at 5.0×. |
| `SUSTAINED_ELEVATION` | WARNING / CRITICAL | Error rate remains above the EWMA baseline for more than 10 minutes (WARNING) or 15 minutes (CRITICAL). |
| `SERVICE_SILENCE` | WARNING | No log entries received for more than 2 minutes from a previously active source. |
| `LATENCY_SPIKE` | WARNING / CRITICAL | The `latency_ms` EWMA breaches its upper bound. Same 2.5× / 5.0× sensitivity multipliers as error rate. |
| `NOVEL_ERROR` | WARNING | An error message fingerprint not seen in the past 24 hours is detected. Uses a bounded bloom-filter set (max 500 fingerprints per source). |
| `CASCADE` | CRITICAL | Three or more distinct services in the same tenant spike within a 5-minute correlation window. |

**Key alert fields explained:**

| Field | Description |
|-------|-------------|
| `current_value` | The measured metric at detection time (e.g., error rate fraction `0.47`) |
| `baseline_value` | The EWMA baseline at detection time (e.g., `0.03`) |
| `upper_bound` | The EWMA upper bound that was breached (e.g., `0.12`) |
| `unit` | Metric unit string — `error_rate`, `latency_ms`, `log_volume`, etc. |
| `representative_msgs` | JSON array of up to 5 sample log messages that contributed to the anomaly |
| `detection_context` | JSON object with EWMA parameters used at detection: `ewma_alpha`, `sensitivity`, `warmup_count` |
| `cascade_context` | For `CASCADE` alerts: JSON list of services that were spiking; `null` for all other types |
| `full_payload` | The complete v1.0 alert contract as a JSON string — this is what webhook receivers get |

---

## Group C — Management APIs

> **Caller:** Tenant Admins configuring the Watchdog installation.
> These endpoints set up which log sources to watch, who has access,
> what API keys exist, and how long data is retained.
> All Group C endpoints require JWT authentication with `tenant_admin` role
> (or `tenant_operator` for read-only access where noted).

---

### 8.4 Admin: Log Sources — `/api/v1/admin/sources`

**Auth required:** JWT only.  
List and get: role `tenant_operator` or higher.  
Create, update, delete: role `tenant_admin`.

Connection strings are Fernet-encrypted before storage and are **never returned**
in any response after the initial create — this is a security invariant, not an
oversight.

---

#### `POST /api/v1/admin/sources`

Create a new log source for the authenticated tenant.

**Request body:**

```json
{
  "name":              "payment-api-prod",
  "service_name":      "payment-service",
  "environment":       "production",
  "source_type":       "push",
  "connection_config": null,
  "poll_interval_s":   5,
  "latency_field":     "duration_ms",
  "log_format":        "json"
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | — | Must be unique within the tenant; cannot be blank |
| `service_name` | string | Yes | — | Used to route ingest entries to this source |
| `environment` | string | No | `"production"` | Free-form string (e.g., `production`, `staging`) |
| `source_type` | string | Yes | — | One of: `file`, `postgres`, `mysql`, `sqlite`, `push` |
| `connection_config` | string | No | `null` | Connection string or file path; Fernet-encrypted at rest; never returned |
| `poll_interval_s` | integer | No | `5` | Connector polling interval in seconds (min 1) |
| `latency_field` | string | No | `null` | JSON key in log entries that contains latency in milliseconds |
| `log_format` | string | No | `"json"` | One of: `json`, `logfmt`, `plaintext` |

**Response `201 Created`:**

```json
{
  "id":              "<source_uuid>",
  "tenant_id":       "<tenant_uuid>",
  "name":            "payment-api-prod",
  "service_name":    "payment-service",
  "environment":     "production",
  "source_type":     "push",
  "poll_interval_s": 5,
  "latency_field":   "duration_ms",
  "log_format":      "json",
  "active":          true,
  "created_at":      "2026-06-28T10:05:00Z"
}
```

Note: `connection_config` is **not** present in the response — it is masked immediately after save.

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `SOURCE_NAME_EXISTS` | 409 | A non-deleted source with this name already exists in the tenant |

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/admin/sources \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"api-logs","service_name":"api","environment":"production","source_type":"push","log_format":"json"}'
```

---

#### `GET /api/v1/admin/sources`

List all active (non-deleted) sources for the authenticated tenant, ordered by
`created_at DESC`.

**Response `200 OK`:** Array of `SourceConfigResponse` objects.

---

#### `GET /api/v1/admin/sources/{source_id}`

Get a single source by UUID.

**Error codes:** `SOURCE_NOT_FOUND` (404) if not found or soft-deleted.

---

#### `PATCH /api/v1/admin/sources/{source_id}`

Update mutable source fields. Only fields present in the request body are changed
(partial update).

**Request body (all fields optional):**

```json
{
  "name":            "new-name",
  "poll_interval_s": 10,
  "latency_field":   "resp_ms",
  "active":          false
}
```

**Response `200 OK`:** Updated `SourceConfigResponse`.

---

#### `DELETE /api/v1/admin/sources/{source_id}`

Soft-delete a source (sets `deleted_at` and `active = false`). The source will no
longer appear in list responses or accept ingest routing.

**Response:** `204 No Content`

---

### 8.5 Admin: Users — `/api/v1/admin/users`

**Auth required:** JWT, role `tenant_admin`.  
All operations are scoped to the authenticated tenant — users from other tenants
are invisible.

---

#### `POST /api/v1/admin/users`

Create a new user within the tenant.

**Request body:**

```json
{
  "email":    "operator@acme.example.com",
  "password": "SecurePass1!",
  "role":     "tenant_operator"
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `email` | string | Yes | — | Must contain `@`; stored lowercase |
| `password` | string | Yes | — | Minimum 8 characters; bcrypt cost-12 hashed at rest |
| `role` | string | No | `"tenant_operator"` | One of: `tenant_operator`, `tenant_admin` |

**Response `201 Created`:**

```json
{
  "id":            "<user_uuid>",
  "tenant_id":     "<tenant_uuid>",
  "email":         "operator@acme.example.com",
  "role":          "tenant_operator",
  "active":        true,
  "last_login_at": null,
  "created_at":    "2026-06-28T10:10:00Z"
}
```

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `EMAIL_EXISTS` | 409 | Email already registered (any tenant) |

---

#### `GET /api/v1/admin/users`

List all non-deleted users in the tenant, ordered by `created_at DESC`.

**Response `200 OK`:** Array of `UserResponse` objects.

---

#### `PATCH /api/v1/admin/users/{user_id}`

Update a user's role or active status (partial update).

**Request body (all optional):**

```json
{
  "active": false,
  "role":   "tenant_admin"
}
```

**Security constraints:**
- A Tenant Admin cannot deactivate their own account (`CANNOT_DEACTIVATE_SELF`).
- `role` can only be set to `tenant_operator` or `tenant_admin` — promotion to
  `platform_admin` is not possible through this endpoint.

**Error codes:**

| Code | Status | Trigger |
|------|--------|---------|
| `USER_NOT_FOUND` | 404 | User not found in tenant |
| `CANNOT_DEACTIVATE_SELF` | 400 | Admin attempting to deactivate their own account |

---

#### `DELETE /api/v1/admin/users/{user_id}`

Soft-delete (deactivate) a user. Sets `deleted_at` and `active = false`. The user
can no longer log in or use existing tokens (tokens are validated against `active`
on every request).

**Security constraint:** Cannot delete your own account (`CANNOT_DELETE_SELF`).

**Response:** `204 No Content`

---

### 8.6 Admin: API Keys & Webhooks — `/api/v1/admin/keys`

**Auth required:** JWT only. API keys cannot mint, rotate, or revoke API keys.  
**Role:** `tenant_operator` or higher (operators see only their own keys;
admins see all tenant keys).

The API key plaintext is generated server-side, returned **exactly once** in the
creation or rotation response, and never stored. Only the SHA-256 hash is persisted.

---

#### `POST /api/v1/admin/keys`

Generate a new API key. The `plaintext_key` in the response is the only opportunity
to record it — it cannot be retrieved again.

**Request body:**

```json
{
  "name":        "ci-pipeline",
  "scopes":      ["ingest", "alerts:read"],
  "environment": "live",
  "expires_at":  null
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | — | Cannot be blank |
| `scopes` | array of string | Yes | — | At least 1 scope. Valid values: `ingest`, `alerts:read`, `webhooks:manage`, `sources:read` |
| `environment` | string | No | `"live"` | `live` → prefix `wdog_live_`; `test` → prefix `wdog_test_` |
| `expires_at` | datetime (ISO 8601) | No | `null` | Optional expiry. `null` = never expires. |

**Response `201 Created`:**

```json
{
  "id":           "<key_uuid>",
  "name":         "ci-pipeline",
  "key_prefix":   "wdog_live_vmK",
  "plaintext_key": "wdog_live_vmKcah-ElpmRfQBi1TVu8n6Xgn2T-3vG8HR8gmVh6lE",
  "scopes":       ["ingest", "alerts:read"],
  "environment":  "live",
  "expires_at":   null,
  "created_at":   "2026-06-28T10:15:00Z"
}
```

**Store the `plaintext_key` immediately. It cannot be retrieved again.**

**curl example:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/admin/keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-pipeline","scopes":["ingest","alerts:read"],"environment":"live"}'
```

---

#### `GET /api/v1/admin/keys`

List active (non-revoked) API keys. Operators see only their own keys;
Admins see all tenant keys. Returns `key_prefix` (first 12 chars) and metadata,
never the plaintext key.

**Response `200 OK`:** Array of `KeyResponse` objects:

```json
[
  {
    "id":                   "<key_uuid>",
    "name":                 "ci-pipeline",
    "key_prefix":           "wdog_live_vmK",
    "scopes":               "[\"ingest\",\"alerts:read\"]",
    "environment":          "live",
    "webhook_url":          null,
    "rate_limit_rpm":       100,
    "last_used_at":         "2026-06-28T10:14:00Z",
    "expires_at":           null,
    "grace_period_ends_at": null,
    "revoked_at":           null,
    "created_at":           "2026-06-28T10:15:00Z"
  }
]
```

Note: `scopes` is returned as a JSON string from the DB. Parse it with `JSON.parse()` / `json.loads()`.

---

#### `DELETE /api/v1/admin/keys/{key_id}`

Immediately revoke an API key. Any request using the revoked key returns `401 KEY_REVOKED`.

**Response:** `204 No Content`

---

#### `POST /api/v1/admin/keys/{key_id}/rotate`

Zero-downtime key rotation. A new key is minted with the same scopes and
environment. The old key enters a **24-hour grace period** during which it
continues to authenticate — allowing time to deploy the new key without service
interruption. After the grace period, the old key is effectively revoked.

**Request body:** None

**Response `200 OK`:**

```json
{
  "new_key_id":            "<new_key_uuid>",
  "plaintext_key":         "wdog_live_<new_43-char-value>",
  "key_prefix":            "wdog_live_abc",
  "old_key_id":            "<old_key_uuid>",
  "grace_period_ends_at":  "2026-06-29T10:20:00Z"
}
```

**Store the `plaintext_key` immediately. It cannot be retrieved again.**

---

#### `POST /api/v1/admin/keys/{key_id}/attach-webhook` → `POST /api/v1/admin/keys/{key_id}/webhook`

Attach a webhook delivery URL to an API key. Watchdog will POST signed alert
payloads to this URL whenever the anomaly engine fires an alert for your tenant.

**Request body:**

```json
{
  "webhook_url":     "https://hooks.example.com/watchdog",
  "severity_filter": "CRITICAL",
  "service_filter":  null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `webhook_url` | string | Yes | Must start with `http://` or `https://` |
| `severity_filter` | string | No | If set, only deliver alerts of this severity. `WARNING` or `CRITICAL`. |
| `service_filter` | string | No | If set, only deliver alerts from this `service_name`. |

**Response `200 OK`:**

```json
{
  "api_key_id":      "<key_uuid>",
  "webhook_url":     "https://hooks.example.com/watchdog",
  "webhook_secret":  "<32-byte-urlsafe-token>",
  "severity_filter": "CRITICAL",
  "service_filter":  null
}
```

**Store the `webhook_secret` immediately.** It is Fernet-encrypted in the DB and
cannot be retrieved again. Use it to verify `X-Watchdog-Signature` headers on
incoming deliveries (see §8.7 Webhook Delivery below).

---

#### `DELETE /api/v1/admin/keys/{key_id}/webhook`

Remove the webhook URL from an API key. No further deliveries will be made.

**Response:** `204 No Content`

---

#### Webhook Delivery Contract

When an anomaly alert fires, Watchdog dispatches it as an HTTP POST to every
webhook URL registered by the tenant.

**Delivery headers:**

```
Content-Type: application/json
X-Watchdog-Delivery-Id: <uuid>
X-Watchdog-Signature:   sha256=<hex>
```

**Payload:** The `full_payload` JSON field from the `AnomalyAlertResponse` —
a complete v1.0 alert contract as a UTF-8 JSON string.

**Signature verification** (Python example):

```python
import hmac, hashlib

def verify_signature(payload_bytes: bytes, secret: str, header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)
```

**Retry policy:**
- Maximum 3 delivery attempts per alert per webhook key
- Backoff schedule: 2 s → 4 s → 8 s between retries
- Webhook URL is automatically set to `null` (disabled) after 10 consecutive
  failures across any alerts — re-attach to re-enable delivery
- Retry loop runs every 30 seconds as a background asyncio task

**Expected response:** Any `2xx` status code is treated as success. Non-2xx
or connection errors trigger a retry.

---

### 8.7 Admin: Retention Config — `/api/v1/admin/config`

**Auth required:** JWT, role `tenant_admin`.

---

#### `GET /api/v1/admin/config`

Get the current retention policy for the authenticated tenant.

**Response `200 OK`:**

```json
{
  "tenant_id":          "<tenant_uuid>",
  "retention_days":     30,
  "log_retention_days": 7
}
```

| Field | Description |
|-------|-------------|
| `retention_days` | How many days anomaly alerts are retained before the hourly cleanup job purges them |
| `log_retention_days` | How many days raw log metadata is retained |

---

#### `PATCH /api/v1/admin/config`

Update retention settings (partial update — omit fields to leave them unchanged).

**Request body:**

```json
{
  "retention_days":     60,
  "log_retention_days": 14
}
```

Both fields must be >= 1 if provided.

**Response `200 OK`:** Updated `RetentionConfigResponse`.

**curl example:**

```bash
curl -X PATCH http://127.0.0.1:8080/api/v1/admin/config \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"retention_days":60,"log_retention_days":14}'
```

---

### 8.8 Dashboard — `/api/v1/dashboard`

**Auth required:** JWT, role `tenant_operator` or higher.  
These endpoints back the real-time operator dashboard UI.

---

#### `GET /api/v1/dashboard/summary`

Alert counts by status and severity plus active source count — all scoped to
the authenticated tenant.

**Response `200 OK`:**

```json
{
  "total_alerts":   10,
  "open":           4,
  "resolved":       3,
  "acknowledged":   3,
  "critical_open":  2,
  "warning_open":   2,
  "active_sources": 2
}
```

**curl example:**

```bash
curl http://127.0.0.1:8080/api/v1/dashboard/summary \
  -H "Authorization: Bearer <access_token>"
```

---

#### `GET /api/v1/dashboard/trend`

Per-hour alert counts for the past N hours. Used to render the Alert Trend chart.

**Query parameters:**

| Parameter | Type | Default | Constraints |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | 1–168 (1 hour to 1 week) |

**Response `200 OK`:**

```json
{
  "labels": ["2026-06-28T08:00:00", "2026-06-28T09:00:00", "..."],
  "counts": [3, 7, 2]
}
```

**curl example:**

```bash
curl "http://127.0.0.1:8080/api/v1/dashboard/trend?hours=48" \
  -H "Authorization: Bearer <access_token>"
```

---

### 8.9 Platform Admin — `/api/v1/platform`

**Auth required:** JWT, role `platform_admin` only.  
Tenant Admins and Operators receive `403 PLATFORM_ADMIN_REQUIRED`.
Platform Admins cannot access tenant-scoped endpoints.

---

#### `POST /api/v1/platform/tenants`

Create a new tenant account.

**Request body:**

```json
{
  "name":               "Acme Corp",
  "contact_email":      "admin@acme.example.com",
  "plan":               "starter",
  "max_sources":        10,
  "retention_days":     30,
  "log_retention_days": 7
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | — | Cannot be blank |
| `contact_email` | string | Yes | — | |
| `plan` | string | No | `"starter"` | Free-form plan label |
| `max_sources` | integer | No | `10` | Must be >= 1 |
| `retention_days` | integer | No | `30` | Must be >= 1 |
| `log_retention_days` | integer | No | `7` | Must be >= 1 |

**Response `201 Created`:**

```json
{
  "id":                 "<tenant_uuid>",
  "name":               "Acme Corp",
  "plan":               "starter",
  "contact_email":      "admin@acme.example.com",
  "max_sources":        10,
  "retention_days":     30,
  "log_retention_days": 7,
  "active":             true,
  "created_at":         "2026-06-28T11:00:00Z"
}
```

---

#### `GET /api/v1/platform/tenants`

List all tenants on the platform, ordered by `created_at DESC`.

**Response `200 OK`:** Array of `TenantResponse` objects.

---

#### `GET /api/v1/platform/tenants/{tenant_id}`

Get a single tenant by UUID.

**Error codes:** `TENANT_NOT_FOUND` (404)

---

#### `PATCH /api/v1/platform/tenants/{tenant_id}`

Update tenant properties (partial update).

**Request body (all optional):**

```json
{
  "active":             false,
  "plan":               "enterprise",
  "max_sources":        100,
  "retention_days":     90,
  "log_retention_days": 30
}
```

**Response `200 OK`:** Updated `TenantResponse`.

---

#### `GET /api/v1/platform/health`

Platform-wide aggregate health metrics across all tenants.

**Response `200 OK`:**

```json
{
  "total_tenants":  5,
  "active_tenants": 4,
  "total_alerts":   87,
  "open_alerts":    12,
  "active_sources": 18,
  "active_users":   23
}
```

---

### 8.10 Health Check — `/api/v1/health`

**Auth required:** None — accessible without any credentials.

#### `GET /api/v1/health`

Component-level health check. Always returns `HTTP 200` — load balancers should
inspect the `status` field in the JSON body rather than the HTTP status code.

**Response `200 OK`:**

```json
{
  "status":  "ok",
  "version": "1.0.0",
  "components": {
    "database": {
      "status":     "ok",
      "latency_ms": 0.69
    },
    "cache": {
      "status":     "ok",
      "latency_ms": null
    },
    "anomaly_engine": {
      "status":     "ok",
      "latency_ms": null
    }
  }
}
```

| `status` value | Meaning |
|---------------|---------|
| `ok` | All components healthy |
| `degraded` | Non-critical component (cache or anomaly engine) unavailable; DB is up |
| `down` | Database unreachable — service cannot process requests |

**curl example:**

```bash
curl http://127.0.0.1:8080/api/v1/health
```

---

### 8.11 UI Routes

Server-rendered HTML pages — each requires a valid JWT in `localStorage` (set by
the login page). Unauthorized visits redirect to `/login`.

| Path | Page | Minimum role |
|------|------|-------------|
| `/` | Redirect to `/login` | — |
| `/login` | Login form | None |
| `/dashboard` | Operator Dashboard (alerts, trend chart) | `tenant_operator` |
| `/admin` | Tenant Admin panel (sources, users, retention) | `tenant_admin` |
| `/consumer` | Consumer Portal (API keys, webhooks) | `tenant_operator` |
| `/platform-admin` | Platform Admin (tenant management) | `platform_admin` |
| `/docs` | Swagger UI (auto-generated OpenAPI) | None |
| `/redoc` | ReDoc (auto-generated OpenAPI) | None |

---

### 8.12 Quick Integration Checklist

Follow these steps to wire Watchdog into an existing service in under 10 minutes:

1. **Login and get a JWT**
   ```bash
   TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@acme.example.com","password":"WatchdogDemo1!"}' \
     | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
   ```

2. **Create a log source** (defines which service you're monitoring)
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/admin/sources \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"my-api","service_name":"my-api","source_type":"push","log_format":"json"}'
   ```

3. **Generate an ingest API key**
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/admin/keys \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"my-api-ingest","scopes":["ingest","alerts:read"],"environment":"live"}'
   # Store the plaintext_key — it will not be shown again
   ```

4. **Start sending log entries** from your application
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/ingest \
     -H "X-API-Key: wdog_live_<your_key>" \
     -H "Content-Type: application/json" \
     -d '{"message":"user request processed","level":"INFO","service_name":"my-api","latency_ms":42}'
   ```

5. **Register a webhook** to receive real-time alert push (optional)
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/admin/keys/<key_id>/webhook \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"webhook_url":"https://hooks.example.com/watchdog","severity_filter":"CRITICAL"}'
   # Store the webhook_secret — verify X-Watchdog-Signature on incoming requests
   ```

6. **Poll or subscribe to alerts** from your incident management tool
   ```bash
   curl "http://127.0.0.1:8080/api/v1/alerts?status=open&limit=50" \
     -H "X-API-Key: wdog_live_<your_key>"
   ```

7. **Acknowledge an alert** once the on-call engineer is aware
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/alerts/<alert_id>/acknowledge \
     -H "Authorization: Bearer $TOKEN"
   ```

---

## 9. Setup & Installation

### Prerequisites

- Python 3.11+ — verify with `python --version`
- Git

---

### Step 1 — Clone and enter the project

```
git clone <repo-url>
cd watchdog
```

---

### Step 2 — Install dependencies

```
python -m pip install -r requirements.txt
```

---

### Step 3 — Configure `.env`

Copy the example file:

```
copy .env.example .env
```

Open `.env` and set every variable. Generate the required values as follows:

**RSA key pair for JWT:**
```
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
python -c "import base64; print(base64.b64encode(open('private.pem','rb').read()).decode())"
python -c "import base64; print(base64.b64encode(open('public.pem','rb').read()).decode())"
```
Paste the outputs into `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` respectively.

**Fernet encryption key:**
```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Paste into `FERNET_KEY`.

**Required variables:**

| Variable | Purpose | Example |
|----------|---------|---------|
| `DATABASE_URL` | Database connection | `sqlite:///./watchdog.db` |
| `JWT_PRIVATE_KEY` | RS256 signing key (base64-encoded PEM) | _(generated above)_ |
| `JWT_PUBLIC_KEY` | RS256 verification key (base64-encoded PEM) | _(generated above)_ |
| `FERNET_KEY` | Encryption key for secrets at rest | _(generated above)_ |
| `PLATFORM_ADMIN_EMAIL` | Bootstrap Platform Admin login | `admin@watchdog.local` |
| `PLATFORM_ADMIN_PASSWORD` | Bootstrap Platform Admin password | `YourStrongPassword1!` |

---

### Step 4 — Run database migrations

```
python -m alembic upgrade head
```

Applies all migrations in `migrations/versions/` — creates the full schema including all
indexes. Never run `Base.metadata.create_all()` directly in production.

---

### Step 5 — Seed demo data

```
python scripts/seed_data.py
```

Creates two tenants, four users, four push-connector log sources, and 20 anomaly alerts
across a realistic status mix (4 open, 3 acknowledged, 3 resolved per tenant).
Re-running is safe — existing rows are skipped, existing alerts are wiped and reseeded.

---

### Step 6 — Start the application

```
python -m uvicorn main:app --port 8080
```

With auto-reload for development:

```
python -m uvicorn main:app --reload --port 8080
```

Confirm it started:

```
curl http://127.0.0.1:8080/api/v1/health
```

Expected: `{"status":"ok","version":"1.0.0",...}`

---

### Step 7 — Open the browser

Navigate to `http://127.0.0.1:8080/dashboard` and sign in with any demo credential from
the Quick Start table. The dashboard loads immediately with 4 open alerts and a populated
trend chart.

---

### Running the test suite

```
python -m pytest --tb=short -q
```

With full coverage report:

```
python -m pytest --tb=short -q --cov=. --cov-report=term
```

Expected output: **266 passed, 2 warnings** in approximately 77 seconds. Coverage: **91.73%**.

---

## 10. Known Limitations & Upgrade Paths

---

**SQLite write concurrency limits**

SQLite uses a file-level write lock. Under concurrent ingest from multiple connectors, write
operations serialize. Acceptable for a single-server demo; a bottleneck under high ingest volume.

*Upgrade path:* Set `DATABASE_URL=postgresql+psycopg2://user:pass@host/watchdog`. SQLAlchemy's
abstraction handles the dialect difference transparently. Add PostgreSQL RLS policies
(see `ARCHITECTURE.md`) for database-layer tenant isolation as defense-in-depth.

---

**No seasonality modeling in EWMA**

EWMA adapts to trending baselines but does not model day-of-week or time-of-day patterns.
A service that consistently spikes every Monday morning will trigger false alerts until the
baseline rises to accommodate it.

*Upgrade path:* Replace or augment the EWMA engine with Facebook Prophet for per-source
seasonality modeling. The `AnomalyEngine` class is the single integration point — swapping
the detection backend does not require changes to connectors, alert storage, or the API surface.

---

**In-process cache lost on restart**

`InProcessCache` is a Python dictionary. EWMA state is persisted to the database every 10
events and on graceful shutdown, so a clean restart loses at most 9 in-flight observations.
An unclean kill (OOM, SIGKILL) loses the in-flight detection window.

*Upgrade path:* Set `CACHE_BACKEND=redis` and `REDIS_URL=redis://localhost:6379/0` in `.env`.
The `RedisCache` implementation is already in `services/cache.py` — no application code changes required.

---

**No PostgreSQL Row Level Security**

Tenant isolation is enforced at the application layer (TenantContext pattern, verified by
the cross-tenant isolation eval). Database-layer RLS would add defense-in-depth against
SQL injection or RBAC implementation bugs — not available in SQLite.

*Upgrade path:* See `ARCHITECTURE.md` section 1 for the exact RLS policy DDL and the
SQLAlchemy event listener pattern to set `app.tenant_id` per session.

---

**No email verification on user registration**

User invitations create accounts immediately. A mistyped email creates an unreachable account.

*Upgrade path:* Add `email_verified` boolean to `users`, generate an HMAC-signed verification
token, deliver via an email provider (SendGrid, AWS SES), and block login until verified.

---

**Chart.js frontend**

Jinja2 + Alpine.js is intentionally minimal. For richer operator UX (custom date ranges,
per-service drill-down, multi-tenant analytics) a React or Next.js frontend is appropriate.

*Upgrade path:* The FastAPI API layer is fully decoupled. A Next.js frontend can be pointed
at `/api/v1/` endpoints with zero backend changes. Jinja2 templates can be retired one view
at a time. `CORS_ORIGINS` in `.env` already supports cross-origin requests.

---

**Single-process deployment**

Background jobs run as asyncio tasks within the uvicorn process. Killed process loses
in-flight jobs.

*Upgrade path:* Extract `RetentionService` and `WebhookDispatcher` to Celery tasks or ARQ
workers. Both are already isolated service classes — extraction is a wrapping operation, not
a rewrite.

---

## 11. Prompts Audit Log Reference

`prompts.md` in the project root contains the complete chronological audit log of every
instruction given to Claude Code during the construction of Watchdog — from the initial
foundation module through all 15 modules, every bug fix, and every UI refinement. It
demonstrates the vibe coding workflow in practice: architectural requirements stated before
implementation; security constraints enumerated before any code was written; module-by-module
approval gates with explicit test-count checkpoints enforced at each transition.

Every prompt in the log was written under the discipline of `CLAUDE.md`: no secrets appear
in the audit log (placeholder values only in all examples), no cross-tenant query was ever
proposed, and every module began with an explicit re-read of `FEATURES.md` and
`ARCHITECTURE.md` before the first line of code was produced. The log demonstrates that the
AI was functioning as an Engineer executing specifications, not as an Architect making
unconstrained design decisions.

`CLAUDE.md` is the companion document showing the operational rules under which the system
was built — the Architect/Engineer separation, the non-negotiable security rules enforced
on every line of code, the module build order, and the testing standards. Evaluators
interested in the vibe coding methodology and the prompting discipline behind this system
should read `CLAUDE.md` first, then `prompts.md` as the execution record against those rules.

---

*Watchdog v1.0.0 · Python 3.11 · FastAPI 0.138 · 266 tests · 91.73% coverage*
