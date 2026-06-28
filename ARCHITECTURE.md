# ARCHITECTURE.md — Intelligent Observability & Event Watchdog

## System Overview

Watchdog is a multi-tenant SaaS log monitoring service. Each tenant independently
connects their own log sources, configures anomaly detection thresholds, and receives
alerts — all in complete data isolation from other tenants.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WATCHDOG SERVICE                             │
│                                                                     │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────────────┐  │
│  │   Connectors  │───▶│  Anomaly Engine  │───▶│  Alert Delivery   │  │
│  │              │    │                 │    │                   │  │
│  │ FileConnector│    │ EWMA + 6 types  │    │ REST API (pull)   │  │
│  │ DBConnector  │    │ Per-tenant state│    │ Webhooks (push)   │  │
│  │ PushConnector│    │ In-memory cache │    │ Dashboard (UI)    │  │
│  └──────────────┘    └─────────────────┘    └───────────────────┘  │
│         ▲                                                           │
│         │                                                           │
│  External Log Sources          ┌──────────────────────────────┐    │
│  (per tenant, isolated)        │     Background Jobs           │    │
│  • App log files               │ • Connector polling (async)   │    │
│  • Database log tables         │ • Retention cleanup (hourly)  │    │
│  • Push via /api/v1/ingest     │ • Webhook retry (30s)         │    │
│                                │ • EWMA persistence (10 events)│    │
│                                │ • Key expiry check (hourly)   │    │
│                                └──────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 1. Multi-Tenancy Architecture

### Tenant Isolation Model

Every user-facing table carries a `tenant_id` foreign key. No query ever returns
data across tenant boundaries. Isolation is enforced at the application layer via
the `TenantContext` dependency — a FastAPI dependency injected into every route
handler that extracts and validates the tenant identity from the verified JWT or
API key, then passes it as a typed parameter into every service call.

```python
class TenantContext:
    tenant_id: UUID
    user_id: UUID | None       # None for API key auth
    api_key_id: UUID | None    # None for JWT auth
    role: Role
    scopes: list[str]

async def get_tenant_context(
    request: Request,
    db: Session = Depends(get_db)
) -> TenantContext:
    # Extracts from JWT or X-API-Key header
    # Validates not expired, not revoked
    # Returns TenantContext — never raw user input
    ...
```

No service function ever accepts a raw `tenant_id` from request parameters. It
always comes from the verified `TenantContext`. This eliminates IDOR vulnerabilities
by design.

### Role Hierarchy

```
Platform Admin
  └── manages tenant accounts, platform health, log level

Tenant Admin
  └── manages sources, users within tenant, retention policy
  └── has all Tenant Operator permissions

Tenant Operator
  └── views dashboard, acknowledges alerts, reads API
  └── manages own API keys and webhook subscriptions

API Consumer (machine identity, no UI)
  └── API key with explicit scopes
  └── scopes: ingest | alerts:read | webhooks:manage | sources:read
```

### Upgrade Path: PostgreSQL Row Level Security

Current implementation enforces tenant isolation at the application layer. When
migrating to PostgreSQL for production scale, Row Level Security (RLS) provides
defense-in-depth at the database engine layer:

```sql
-- PostgreSQL only — not implemented in SQLite MVP
ALTER TABLE anomaly_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON anomaly_alerts
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

With RLS, even a SQL injection or application-layer RBAC bug cannot return
cross-tenant data. Documented as post-SQLite migration step.

---

## 2. Database Schema

### Design Principles
- UUIDs as primary keys — prevents enumeration attacks, safe in URLs
- `created_at` on every table with server-side default
- Soft deletes via `deleted_at` (nullable) — never hard-delete audit data
- `tenant_id` FK on every user-facing table
- Indexed on all FK columns and all WHERE/ORDER BY columns
- Alembic for all schema changes — no DDL in application code

### Tables

```sql
-- Platform tenants
CREATE TABLE tenants (
    id                  TEXT PRIMARY KEY,              -- UUID
    name                TEXT NOT NULL,
    plan                TEXT NOT NULL DEFAULT 'starter',
    contact_email       TEXT NOT NULL,
    max_sources         INTEGER NOT NULL DEFAULT 10,
    retention_days      INTEGER NOT NULL DEFAULT 30,
    log_retention_days  INTEGER NOT NULL DEFAULT 7,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP
);

-- Human users (Tenant Admin, Tenant Operator, Platform Admin)
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,                 -- bcrypt cost 12
    role                TEXT NOT NULL,                 -- platform_admin | tenant_admin | tenant_operator
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMP,
    created_by          TEXT REFERENCES users(id),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- JWT refresh tokens (for revocation)
CREATE TABLE refresh_tokens (
    id                  TEXT PRIMARY KEY,              -- UUID
    user_id             TEXT NOT NULL REFERENCES users(id),
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    token_hash          TEXT NOT NULL UNIQUE,          -- SHA-256 of token
    expires_at          TIMESTAMP NOT NULL,
    revoked_at          TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- API keys for programmatic access (machine consumers)
CREATE TABLE api_keys (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    user_id             TEXT NOT NULL REFERENCES users(id),  -- who created it
    name                TEXT NOT NULL,
    key_hash            TEXT NOT NULL UNIQUE,          -- SHA-256(plaintext_key)
    key_prefix          TEXT NOT NULL,                 -- first 12 chars for display (wdog_live_xxxx)
    environment         TEXT NOT NULL DEFAULT 'live',  -- live | test
    scopes              TEXT NOT NULL,                 -- JSON array
    webhook_url         TEXT,                          -- push anomalies here if set
    webhook_secret_enc  TEXT,                          -- Fernet-encrypted HMAC secret
    rate_limit_rpm      INTEGER NOT NULL DEFAULT 100,
    last_used_at        TIMESTAMP,
    expires_at          TIMESTAMP,
    grace_period_ends_at TIMESTAMP,                    -- set during rotation
    superseded_by       TEXT REFERENCES api_keys(id), -- set during rotation
    revoked_at          TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_expiry ON api_keys(expires_at, revoked_at);

-- Configured log sources per tenant
CREATE TABLE log_sources (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    service_name        TEXT NOT NULL,
    environment         TEXT NOT NULL DEFAULT 'production',
    source_type         TEXT NOT NULL,                 -- file | postgres | mysql | sqlite | push
    connection_config_enc TEXT,                        -- Fernet-encrypted JSON (null for push)
    poll_interval_s     INTEGER NOT NULL DEFAULT 5,
    latency_field       TEXT,                          -- optional field name for LATENCY_SPIKE
    log_format          TEXT NOT NULL DEFAULT 'json',  -- json | logfmt | plaintext
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          TEXT NOT NULL REFERENCES users(id),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP
);

CREATE INDEX idx_log_sources_tenant ON log_sources(tenant_id);
CREATE INDEX idx_log_sources_active ON log_sources(tenant_id, active);

-- Connector state per source (cursor / high-water mark)
CREATE TABLE source_state (
    id                  TEXT PRIMARY KEY,              -- UUID
    source_id           TEXT NOT NULL UNIQUE REFERENCES log_sources(id),
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    last_seen_id        TEXT,                          -- DB connector high-water mark
    file_path           TEXT,                          -- file connector current path
    file_inode          INTEGER,                       -- file connector inode
    byte_offset         INTEGER,                       -- file connector cursor
    poll_state          TEXT NOT NULL DEFAULT 'active', -- active | idle | backoff | error
    consecutive_empty   INTEGER NOT NULL DEFAULT 0,
    last_polled_at      TIMESTAMP,
    last_error          TEXT,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- EWMA detection state per source (cached in-memory, persisted periodically)
CREATE TABLE ewma_state (
    id                  TEXT PRIMARY KEY,              -- UUID
    source_id           TEXT NOT NULL UNIQUE REFERENCES log_sources(id),
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    ewma_value          REAL NOT NULL DEFAULT 0.0,
    ewma_variance       REAL NOT NULL DEFAULT 0.0,
    alpha               REAL NOT NULL DEFAULT 0.3,
    sensitivity         REAL NOT NULL DEFAULT 2.5,
    warmup_count        INTEGER NOT NULL DEFAULT 0,
    warmup_required     INTEGER NOT NULL DEFAULT 10,
    error_fingerprints  TEXT NOT NULL DEFAULT '[]',    -- bloom filter state for NOVEL_ERROR
    log_volume_ewma     REAL NOT NULL DEFAULT 0.0,     -- for SERVICE_SILENCE baseline
    last_log_at         TIMESTAMP,                     -- for SERVICE_SILENCE detection
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ewma_state_tenant ON ewma_state(tenant_id);

-- Detected anomaly alerts (no raw log entries stored — evidence embedded here)
CREATE TABLE anomaly_alerts (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    source_id           TEXT NOT NULL REFERENCES log_sources(id),
    detected_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    anomaly_type        TEXT NOT NULL,                 -- ERROR_RATE_SPIKE | SUSTAINED_ELEVATION | etc
    severity            TEXT NOT NULL,                 -- WARNING | CRITICAL
    service_name        TEXT NOT NULL,
    environment         TEXT NOT NULL,
    current_value       REAL NOT NULL,
    baseline_value      REAL NOT NULL,
    upper_bound         REAL NOT NULL,
    unit                TEXT NOT NULL,                 -- errors_per_minute | ms | etc
    window_start        TIMESTAMP NOT NULL,
    window_end          TIMESTAMP NOT NULL,
    sample_count        INTEGER NOT NULL,
    representative_msgs TEXT NOT NULL DEFAULT '[]',    -- JSON: top 3 error messages
    detection_context   TEXT NOT NULL,                 -- JSON: EWMA params at detection
    cascade_context     TEXT,                          -- JSON: only for CASCADE type
    full_payload        TEXT NOT NULL,                 -- JSON: complete v1.0 contract
    status              TEXT NOT NULL DEFAULT 'open',  -- open | acknowledged | resolved
    acknowledged_by     TEXT REFERENCES users(id),
    acknowledged_at     TIMESTAMP,
    resolved_at         TIMESTAMP,
    auto_resolved       BOOLEAN,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_anomaly_alerts_tenant ON anomaly_alerts(tenant_id, detected_at);
CREATE INDEX idx_anomaly_alerts_source ON anomaly_alerts(source_id, detected_at);
CREATE INDEX idx_anomaly_alerts_type ON anomaly_alerts(anomaly_type);
CREATE INDEX idx_anomaly_alerts_severity ON anomaly_alerts(tenant_id, severity, status);
CREATE INDEX idx_anomaly_alerts_service ON anomaly_alerts(tenant_id, service_name, detected_at);
CREATE INDEX idx_anomaly_alerts_retention ON anomaly_alerts(tenant_id, status, created_at);

-- Webhook delivery attempts
CREATE TABLE webhook_events (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    alert_id            TEXT NOT NULL REFERENCES anomaly_alerts(id),
    api_key_id          TEXT NOT NULL REFERENCES api_keys(id),
    attempt_number      INTEGER NOT NULL DEFAULT 1,
    sent_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    target_url          TEXT NOT NULL,
    payload             TEXT NOT NULL,
    delivery_id         TEXT NOT NULL,                 -- X-Watchdog-Delivery-ID value
    response_status     INTEGER,
    response_body       TEXT,
    latency_ms          INTEGER,
    success             BOOLEAN NOT NULL DEFAULT FALSE,
    next_retry_at       TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhook_events_tenant ON webhook_events(tenant_id);
CREATE INDEX idx_webhook_events_alert ON webhook_events(alert_id);
CREATE INDEX idx_webhook_events_retry ON webhook_events(success, next_retry_at);
CREATE INDEX idx_webhook_events_retention ON webhook_events(tenant_id, created_at);

-- Tenant-level and platform-level configuration (key-value)
CREATE TABLE system_config (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT REFERENCES tenants(id),  -- NULL = platform-level config
    key                 TEXT NOT NULL,
    value               TEXT NOT NULL,
    updated_by          TEXT REFERENCES users(id),
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, key)
);

-- Request audit log
CREATE TABLE request_log (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT REFERENCES tenants(id),  -- NULL for unauthenticated
    timestamp           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    method              TEXT NOT NULL,
    path                TEXT NOT NULL,
    status_code         INTEGER NOT NULL,
    latency_ms          INTEGER NOT NULL,
    api_key_id          TEXT REFERENCES api_keys(id),
    user_id             TEXT REFERENCES users(id),
    ip_address          TEXT,
    request_id          TEXT NOT NULL,
    error_detail        TEXT
);

CREATE INDEX idx_request_log_tenant ON request_log(tenant_id, timestamp);
CREATE INDEX idx_request_log_path ON request_log(path, status_code);
CREATE INDEX idx_request_log_retention ON request_log(tenant_id, timestamp);
```

**Note: No `log_entries` table.** Raw log entries from external sources are never
stored in Watchdog's database. They are read, processed through the anomaly engine,
and discarded. Only anomaly alerts with embedded evidence snapshots are persisted.
This keeps the database lean and the write load minimal. See DECISIONS.md Decision 3.

---

## 3. Log Source Connectors

### Plugin Architecture

```python
class LogSourceConnector(ABC):
    @abstractmethod
    async def connect(self, config: SourceConfig) -> None: ...
    @abstractmethod
    async def poll(self) -> list[NormalizedLogEntry]: ...
    @abstractmethod
    async def close(self) -> None: ...
```

Adding a new source type (Kafka, CloudWatch, Loki) = one new file implementing
this interface. Zero changes to existing code.

### FileConnector

Handles rotating log files. Strategy:
- On open: read persisted inode + byte offset from `source_state`
- On each poll: seek to offset, read new lines, update offset in `source_state`
- Rotation detection: if current inode differs from persisted inode, or file size
  is less than last offset, rotation has occurred — drain remaining bytes from old
  file descriptor, open new file from offset 0
- Uses Python `watchdog` library for filesystem events with polling fallback
  (handles NFS mounts where inotify is unavailable)
- Supported formats: JSON-per-line, logfmt, plaintext (regex-parsed)

### DBConnector

High-water mark polling on indexed integer/sequence ID:
```sql
SELECT id, created_at, level, message, [latency_field]
FROM :target_table
WHERE id > :last_seen_id
ORDER BY id ASC
LIMIT 500
```
- `last_seen_id` persisted in `source_state` after each successful batch
- Validates on source setup that target column has an index (warns if not)
- Uses SQLAlchemy Core (not ORM) — no mapping of external tables to our models
- Supports PostgreSQL, MySQL, SQLite external sources
- Connection string decrypted from `connection_config_enc` at connector start,
  held in memory, never re-exposed

### PushConnector

Passive receiver — external apps POST to `/api/v1/ingest` authenticated with a
scoped API key. No polling loop. Entries routed to the anomaly engine directly.

### ConnectorManager

FastAPI lifespan-managed service:
- One asyncio background task per active source across all tenants
- Tenant source limit enforced (from `tenants.max_sources`)
- One connector error does not affect other connectors
- Adaptive polling state machine per connector:
  - ACTIVE: poll at configured interval (default 5s)
  - IDLE: poll every 30s (5 consecutive empty polls)
  - BACKOFF: poll every 60s (3+ consecutive errors)
  - Any new data received → immediately return to ACTIVE
  - Floor: 1s minimum (prevent source hammering regardless of config)

---

## 4. Anomaly Detection Engine

### EWMA Algorithm

```
EWMA_t     = α × x_t + (1 − α) × EWMA_{t-1}
Variance_t = α × (x_t − EWMA_{t-1})² + (1 − α) × Variance_{t-1}
Upper_bound = EWMA_t + sensitivity × √Variance_t
```

Default parameters (all per-source tunable):
- Alpha (α): 0.3
- Sensitivity: 2.5
- Warmup: 10 observations

EWMA state in `ewma_state` table, cached in-process dict. Persisted every 10 events
and on graceful shutdown.

### Six Anomaly Types

| Type | Trigger | Severity | Auto-Resolves |
|------|---------|----------|---------------|
| ERROR_RATE_SPIKE | 1-min error rate > EWMA upper bound | WARNING 2.5×, CRITICAL 5× | Yes, 2 clean windows |
| SUSTAINED_ELEVATION | Error rate above baseline >10 min | WARNING 10min, CRITICAL 15min | Yes, on return to baseline |
| SERVICE_SILENCE | Active service emits 0 logs >2 min | CRITICAL | Yes, on log resumption |
| LATENCY_SPIKE | Latency field breaches EWMA upper bound | WARNING/CRITICAL | Yes, 2 clean windows |
| NOVEL_ERROR | New error pattern not seen in 24h | WARNING | N/A (point-in-time) |
| CASCADE | 3+ services spike within 5-min window | CRITICAL | Yes, when all contributing alerts resolve |

### Anomaly Output Contract (v1.0)

All anomaly types normalized to this JSON shape for API and webhook delivery:

```json
{
  "anomaly_id": "uuid",
  "schema_version": "1.0",
  "detected_at": "2026-01-01T12:00:00Z",
  "anomaly_type": "ERROR_RATE_SPIKE",
  "severity": "CRITICAL",
  "service": {
    "name": "payment-service",
    "environment": "production",
    "source_type": "file",
    "source_id": "uuid"
  },
  "evidence": {
    "current_value": 42.3,
    "baseline_value": 8.1,
    "upper_bound": 16.2,
    "unit": "errors_per_minute",
    "window_start": "2026-01-01T11:55:00Z",
    "window_end": "2026-01-01T12:00:00Z",
    "sample_count": 847,
    "representative_messages": [
      "ConnectionRefusedError: payment gateway timeout",
      "ValueError: invalid card token format",
      "HTTPError: 503 from upstream"
    ]
  },
  "detection_context": {
    "algorithm": "EWMA",
    "ewma_value": 8.1,
    "ewma_variance": 4.2,
    "alpha": 0.3,
    "sensitivity_multiplier": 2.5,
    "warmup_complete": true,
    "observations_count": 2847
  },
  "cascade_context": null,
  "resolution": {
    "resolved_at": null,
    "duration_seconds": null,
    "auto_resolved": null
  },
  "links": {
    "self": "/api/v1/alerts/uuid",
    "service_history": "/api/v1/alerts?service=payment-service&limit=10",
    "acknowledge": "/api/v1/alerts/uuid/acknowledge"
  }
}
```

---

## 5. API Key Lifecycle

### Generation
1. User requests key via consumer portal (name, scopes, optional expiry)
2. `secrets.token_urlsafe(32)` generates 32 bytes of cryptographic entropy
3. Key formatted: `wdog_live_<token>` (production) or `wdog_test_<token>` (test)
4. SHA-256 hash computed and stored in `api_keys.key_hash`
5. First 12 chars stored in `api_keys.key_prefix` for UI display
6. Full plaintext returned exactly once in response — never stored, never retrievable

### Authentication Flow (per request)
1. Extract `X-API-Key` header value
2. Compute SHA-256 of header value
3. Lookup hash in `api_keys` table (cache hit likely — 60s TTL in-process cache)
4. Verify: not revoked, not expired, grace period not expired
5. Verify: requested endpoint scope in key's scope list
6. Verify: rate limit not exceeded (sliding window counter)
7. Extract `tenant_id` from key record → inject into TenantContext
8. Log `api_key_id` (UUID) — never the key value

### Rotation (Zero-Downtime)
1. User calls `POST /api/v1/admin/keys/{id}/rotate`
2. New key generated (same scopes as original)
3. New plaintext returned once
4. Original key: `grace_period_ends_at` set to now + 24h, `superseded_by` = new key ID
5. After 24h: background job marks original key `revoked_at`
6. Consumer updates their systems during grace period with zero downtime

### Secret Storage Tiers
```
Tier 1 — Never stored:     API key plaintext
Tier 2 — Hashed (one-way): User passwords (bcrypt), API key hashes (SHA-256),
                            refresh token hashes (SHA-256)
Tier 3 — Encrypted (Fernet): Webhook signing secrets, DB connection strings
                              Must be retrieved for use. Key in .env only.
```

---

## 6. Webhook Delivery

### Registration
- API key owner registers webhook URL + optional filters (severity, service)
- Watchdog generates webhook signing secret via `secrets.token_urlsafe(32)`
- Secret shown once, stored Fernet-encrypted in `api_keys.webhook_secret_enc`
- Why encrypted not hashed: we must retrieve it to compute HMAC on each delivery

### Delivery Flow
```
Anomaly detected
  → Build full v1.0 JSON payload
  → Retrieve + decrypt webhook_secret_enc
  → Compute HMAC-SHA256(payload_bytes, secret)
  → POST to webhook_url with headers:
      Content-Type: application/json
      X-Watchdog-Signature: sha256=<hex>
      X-Watchdog-Delivery-ID: <uuid>
      X-Watchdog-Event: anomaly.detected
  → Log attempt to webhook_events
  → On failure: retry 3× with exponential backoff (2s, 4s, 8s)
  → After 10 consecutive failures: auto-disable webhook, flag in UI
```

### Consumer Verification
```python
import hmac, hashlib

def verify_webhook(payload: bytes, secret: str, signature_header: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)
```

---

## 7. Caching Strategy

### CacheBackend Abstraction

```python
class CacheBackend(ABC):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None: ...
    async def delete(self, key: str) -> None: ...

class InProcessCache(CacheBackend): ...  # default, zero deps
class RedisCache(CacheBackend): ...      # CACHE_BACKEND=redis in .env
```

### Cache Usage

| Item | TTL | Rationale |
|------|-----|-----------|
| EWMA state per source | Write-through, flush every 10 events | Avoid DB write per ingest |
| API key validation | 60s | Avoid hash lookup on every request |
| Dashboard aggregation | 5s | Dashboard auto-refreshes every 10s |
| Source config per connector | 30s | Read every poll cycle |
| Tenant config | 120s | Rate limits, retention settings |

---

## 8. Retention and Cleanup

### Retention Job (runs hourly via asyncio background task)

```sql
-- Resolved/acknowledged alerts older than retention threshold
DELETE FROM anomaly_alerts
WHERE tenant_id = :tenant_id
  AND status IN ('resolved', 'acknowledged')
  AND created_at < datetime('now', '-' || :retention_days || ' days');

-- Webhook events on same schedule
DELETE FROM webhook_events
WHERE tenant_id = :tenant_id
  AND created_at < datetime('now', '-' || :retention_days || ' days');

-- Request log on log_retention_days schedule
DELETE FROM request_log
WHERE tenant_id = :tenant_id
  AND timestamp < datetime('now', '-' || :log_retention_days || ' days');
```

**Open alerts are never auto-deleted** regardless of age — an anomaly that has been
open for 35 days is a problem that needs human attention, not silent removal.

Retention settings stored in `tenants.retention_days` (default 30) and
`tenants.log_retention_days` (default 7). Configurable by Tenant Admin.

---

## 9. API Versioning

### URL Path Versioning
```python
# main.py — adding v2 is one line, v1 untouched
app.include_router(v1_router, prefix="/api/v1")
app.include_router(v2_router, prefix="/api/v2")  # future
```

### Schema Namespacing
`models/schemas/v1/` — v2 breaking changes live in `models/schemas/v2/`
without touching v1 models. Existing consumers never break.

### Version Headers
All responses include:
```
API-Version: 1.0
```
When sunsetting (future):
```
Deprecation: true
Sunset: Sat, 01 Jan 2027 00:00:00 GMT
Link: </api/v2/alerts>; rel="successor-version"
```

---

## 10. Security Architecture

### Input Validation
- Pydantic models on every request body — 422 on any malformed input
- No raw SQL — SQLAlchemy ORM/Core only
- No shell commands — subprocess never used
- No secrets accepted as query parameters (only headers)

### Transport Security
- Rate limiting: `slowapi` on ingest (100/min default) and auth (10/min) endpoints
- CORS: explicit tenant-configured allowlist, never wildcard
- JWT: RS256 asymmetric, 15-min access token, 7-day httpOnly/Secure/SameSite=Strict cookie
- No stack traces in API responses — logged internally with request_id, clean message returned

### Credential Hygiene Enforced in Code
- `X-API-Key` header value never appears in any log line or error response
- `Authorization` header value never logged
- Connection strings masked (show only first 20 chars) in any API response
- `.env` in `.gitignore`, `.env.example` with placeholders committed
- API key prefix format (`wdog_live_` / `wdog_test_`) enables automated secret
  scanning in git history and CI/CD pipelines (GitHub secret scanning, truffleHog)
- Seed scripts use placeholder credentials only — no real secrets in `prompts.md`

### Observability (Self-Monitoring)
- Structured JSON logging: `json-log-formatter`
- Fields: timestamp, request_id, tenant_id, method, path, status_code, latency_ms
- Sensitive fields explicitly excluded via logging filter
- Log level runtime-configurable: Platform Admin UI or `LOG_LEVEL` env var
- Default level: WARNING (production) — anomalies, errors, connector failures only
- Log rotation: 10MB per file, 3 backups

### Health Endpoint
`GET /api/v1/health` (no auth)
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "db_connected": true,
  "active_sources_count": 42,
  "total_alerts_today": 7,
  "cache_hit_rate": 0.94,
  "log_level": "WARNING"
}
```

---

## 11. UI Architecture

### Rendering Model

All HTML is server-rendered by FastAPI using Jinja2 templates. There is no separate
frontend server, no npm project, no build pipeline. Everything is served by FastAPI
on one port. This keeps the architecture simple, the deployment trivial, and the
role-based access control entirely server-side.

```
Browser request
  → FastAPI route handler
  → TenantContext validates auth + role
  → Jinja2 template rendered with tenant-scoped data
  → HTML response sent to browser
  → Alpine.js handles client-side reactivity
  → Chart.js renders trend charts from /api/v1/dashboard/data
```

### Technology Choices

**Jinja2** — Python-native server-side templating. First-class FastAPI support via
`fastapi.templating.Jinja2Templates`. Template inheritance via `{% extends %}` keeps
layouts DRY across the four views. Role-based rendering enforced server-side —
if a Tenant Operator requests the admin panel, FastAPI returns 403 before the
template is even rendered.

**Alpine.js (via CDN, ~15KB)** — Handles client-side reactivity without a build step
or separate codebase. Written by the Tailwind CSS team, TypeScript-authored with full
type definitions. Used for:
- Dashboard auto-refresh: `x-init="setInterval(() => refreshAlerts(), 10000)"`
- Alert acknowledgment: optimistic UI state update on button click
- Form validation feedback: inline error display without page reload
- Collapsible sections in admin panel
- Webhook delivery history expand/collapse

Alpine.js is an attribute-based framework — behavior is declared in HTML, not in
separate JS files. A Python engineer reading the templates can understand exactly
what is happening without knowing Alpine.js.

**Chart.js (via CDN)** — Renders the error rate trend charts on the Operator
Dashboard. Fetches data from `/api/v1/dashboard/data` (JSON, cached 5s) and
re-renders on each auto-refresh cycle. No server-side chart rendering — charts
are the one genuinely client-side component.

### Four Views and Their Rendering Strategy

**Operator Dashboard** (`/dashboard`)
- Server renders: service status grid, open alert count, tenant context
- Alpine.js: auto-refresh every 10s (fetches `/api/v1/dashboard/data`, swaps alert feed)
- Chart.js: error rate line chart per service, last 1 hour
- Accessible to: Tenant Operator, Tenant Admin

**Admin Panel** (`/admin`)
- Server renders: source list, user list, retention config forms
- Alpine.js: form validation feedback, confirmation dialogs before delete
- Accessible to: Tenant Admin only (403 redirect for Operator)

**Consumer Portal** (`/consumer`)
- Server renders: API key list (prefix + metadata, never value), webhook list,
  delivery history table
- Alpine.js: copy-to-clipboard on key generation (one-time display), rotation
  confirmation dialog
- Accessible to: all authenticated users

**Platform Admin** (`/platform`)
- Server renders: tenant list, platform health metrics
- Alpine.js: suspend/reactivate tenant confirmation dialog, log level selector
- Accessible to: Platform Admin only

### Why Not a Python-Native Frontend Framework

Three Python-native UI options were evaluated: Reflex (compiles to React), Flet
(Flutter for Python), and Solara (React-based). All three require a second server
process running alongside FastAPI, introduce build pipelines not under our control,
and are early-stage with documentation gaps. For a time-constrained build, the risk
of fighting framework edge cases outweighs the benefit of pure-Python UI code.

Jinja2 is itself part of the Python ecosystem (Pallets project, same team as Flask).
The frontend layer is thin by design — the product's value is in the backend:
anomaly detection, multi-tenant isolation, connector architecture, and the API
contract. See DECISIONS.md Decision 18 for full rationale.

### Post-MVP Upgrade Path

The FastAPI API layer is fully decoupled from the UI. If a richer frontend is needed
post-MVP, a Next.js or React frontend can be pointed at the existing `/api/v1/`
endpoints with zero backend changes. The Jinja2 templates can be retired
incrementally, one view at a time.

---

## 12. Eval Targets

| Eval | Target | Method |
|------|--------|--------|
| Anomaly precision | > 0.85 | 250 labeled windows (200 normal, 50 spike) |
| Anomaly recall | > 0.90 | Same labeled dataset |
| False positive rate | < 0.05 | 1000 normal-distribution events |
| Connector poll lag p95 | < 500ms | 100 timed trials |
| NOVEL_ERROR accuracy | > 0.95 | Known new vs known repeated messages |
| Cross-tenant isolation | 0 leaks | Exhaustive fixture: Tenant A queries with Tenant B credentials |
