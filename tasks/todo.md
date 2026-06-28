# tasks/todo.md — Watchdog Implementation Checklist

Auto-maintained by Claude. Updated after each module completion.
Read this at the start of every session to know where we are.

---

## Status Legend
```
[ ] Not started
[~] In progress
[x] Complete (tests passing, architect approved)
[!] Blocked — see notes
```

---

## Module 1 — Foundation ✓
**Goal:** Project skeleton, config, database, first migration, test infrastructure

- [x] `requirements.txt` with pinned versions
- [x] `.env.example` with all config keys, descriptions, and placeholder values
- [x] `.gitignore` — includes .env, *.db, __pycache__, .pytest_cache
- [x] `config.py` — pydantic-settings, all config from .env, fails fast on missing required vars
- [x] `database.py` — SQLAlchemy engine, session factory, Base, `get_db` dependency
- [x] `alembic.ini` + `migrations/env.py`
- [x] `migrations/versions/001_initial_schema.py` — all tables, all indexes
- [x] `pytest.ini` — test config, coverage threshold 80%
- [x] `tests/conftest.py` — file-based test DB with Alembic migration, two test tenants, test client fixture

**Tests required:**
- [x] DB connects and all tables exist after migration
- [x] Migration runs twice without error (idempotent)
- [x] Config fails fast with clear error on missing required env var
- [x] Config loads correctly from valid .env
- [x] `get_db` yields session and closes on exit (context manager correct)
- [x] Two-tenant fixture: Tenant A data not visible to Tenant B (isolation baseline)

**Architect approval:** [ ]
**Notes:**
- Python 3.14.4 on this machine — pinned requirements.txt to versions with Python 3.14 wheels.
- Lesson: migrations/env.py must not override a caller-supplied sqlalchemy.url; added sentinel check vs alembic.ini default to prevent test URL being clobbered by settings.DATABASE_URL.

---

## Module 2 — Security Layer ✓
**Goal:** JWT auth, RBAC, TenantContext, API key hashing, key generation

- [x] `models/db.py` — User, RefreshToken, ApiKey, Tenant ORM models
- [x] `models/schemas/v1/auth.py` — LoginRequest, TokenResponse, UserResponse
- [x] `security.py`:
  - [x] bcrypt password hashing + verification (cost 12)
  - [x] RS256 JWT encode/decode (access token 15min, refresh 7d)
  - [x] SHA-256 API key hashing (for lookup)
  - [x] Fernet encryption/decryption (for webhook secrets, connection strings)
  - [x] TenantContext dependency — extracts verified tenant from JWT or X-API-Key
  - [x] Scope validation per endpoint
  - [x] Role validation per endpoint (Platform Admin intentionally excluded from tenant hierarchy)
- [x] `scripts/generate_api_key.py` — CLI: mint, hash, register key for a tenant

**Security tests required:**
- [x] Valid credentials → JWT issued (29 tests total, all passing)
- [x] Invalid credentials → 401, no token
- [x] Expired access token → 401
- [x] Valid refresh token → new access token issued
- [x] Used/revoked refresh token → 401
- [x] Valid API key → TenantContext populated with correct tenant_id
- [x] Invalid API key (wrong hash) → 401, code: KEY_INVALID
- [x] Revoked API key → 401, code: KEY_REVOKED
- [x] Expired API key → 401, code: KEY_EXPIRED
- [x] API key for Tenant A rejected on Tenant B endpoint → 403 or 404
- [x] Scope: key with alerts:read cannot POST to /ingest → 403
- [x] Scope: Tenant Operator cannot access Tenant Admin endpoint → 403
- [x] Platform Admin cannot access Tenant A data as Tenant B → 403
- [x] Fernet: encrypt then decrypt returns original value
- [x] Fernet: tampered ciphertext raises exception
- [x] X-API-Key header value absent from all log output

**Architect approval:** [ ]
**Notes:**
- PLATFORM_ADMIN is excluded from tenant role hierarchy by design — they use /platform/* endpoints.
- jti (UUID) added to both token types to guarantee unique DB hashes even under fast sequential calls.
- conftest.py updated to generate real RSA key pair for tests (placeholder strings fail RS256).

---

## Module 3 — Auth Endpoints ✓
**Goal:** Login, logout, refresh, bootstrap Platform Admin account

- [x] `routers/v1/auth.py` — POST /api/v1/auth/login, /logout, /refresh
- [x] `routers/v1/platform/tenants.py` — POST /api/v1/platform/tenants (Platform Admin)
- [x] `middleware.py` — X-Request-ID injection, JSON structured logging,
      latency measurement, sensitive header redaction, request_log persistence
- [x] `limiter.py` — shared slowapi Limiter singleton
- [x] `models/schemas/v1/admin.py` — CreateTenantRequest, TenantResponse

**Tests required:**
- [x] Login: valid → 200, access token, httpOnly refresh cookie (20 tests, all passing)
- [x] Login: invalid password → 401
- [x] Login: unknown email → 401 (same response as wrong password, no enumeration)
- [x] Login: rate limit 10/min enforced
- [x] Logout: refresh token revoked
- [x] Refresh: valid cookie → new access token
- [x] Refresh: revoked cookie → 401
- [x] Platform Admin: create tenant → 201
- [x] Platform Admin: non-platform-admin cannot create tenants → 403
- [x] Middleware: X-Request-ID present on all responses
- [x] Middleware: request logged to request_log
- [x] Middleware: X-API-Key value NOT in any log field

**Architect approval:** [ ]
**Notes:**
- Platform Admin bootstrapped in lifespan via _bootstrap_platform_admin() (idempotent).
- Platform system tenant uses fixed UUID 00000000-0000-0000-0000-000000000001.
- Login uses dummy bcrypt hash for unknown emails to resist timing-based enumeration.
- middleware._request_log_session_factory is the shared "test DB factory" override; used
  by both middleware and _bootstrap_platform_admin in tests so all writes go to test DB.
- RequestLog ORM model brought forward from Module 10 (table already existed in migration).

---

## Module 4 — Connectors ✓
**Goal:** Plugin connector architecture, all three source types, ConnectorManager

- [x] `models/db.py` additions — LogSource, SourceState ORM models
- [x] `models/schemas/v1/admin.py` — SourceConfigRequest, SourceConfigResponse
- [x] `connectors/base.py` — LogSourceConnector ABC + NormalizedLogEntry dataclass
- [x] `connectors/push_connector.py` — passive, no polling loop
- [x] `connectors/file_connector.py`:
  - [x] Read new lines from byte offset (binary mode for Windows portability)
  - [x] Persist cursor (inode + offset) to source_state after each poll
  - [x] Detect rotation (size-shrink primary, inode-change secondary/POSIX-only)
  - [x] Drain remaining bytes from old file on rotation before opening new
  - [x] Parse JSON-per-line, logfmt, plaintext formats
- [x] `connectors/db_connector.py`:
  - [x] High-water mark: SELECT WHERE id > last_seen_id LIMIT 500
  - [x] Advance last_seen_id after successful batch
  - [x] All sync SQLAlchemy calls wrapped in asyncio.to_thread()
- [x] `services/connector_manager.py`:
  - [x] Start background asyncio task per active source at lifespan startup
  - [x] Enforce tenant max_sources limit via add_source(max_sources=N)
  - [x] Adaptive polling state machine (ACTIVE / IDLE / BACKOFF)
  - [x] One connector error does not crash other connectors (per-slot state)
  - [x] Graceful shutdown: cancel all tasks, close connectors

**Tests required:**
- [x] FileConnector: reads lines appended to temp file
- [x] FileConnector: ignores already-read lines on second poll (cursor correct)
- [x] FileConnector: detects rotation (size-shrink) and follows new file
- [x] FileConnector: drains remaining bytes from old file before following new
- [x] FileConnector: resumes from persisted offset after simulated restart
- [x] FileConnector: parses JSON-per-line format
- [x] FileConnector: parses logfmt format
- [x] DBConnector: returns only rows with id > last_seen_id
- [x] DBConnector: advances high-water mark after successful poll
- [x] DBConnector: handles empty result set (returns [], does not advance mark)
- [x] DBConnector: handles source DB connection failure gracefully (raises ValueError)
- [x] ConnectorManager: starts task per active source
- [x] ConnectorManager: respects tenant max_sources limit
- [x] ConnectorManager: ACTIVE → IDLE after 5 empty polls
- [x] ConnectorManager: IDLE → ACTIVE immediately on new data
- [x] ConnectorManager: ACTIVE → BACKOFF after 3 consecutive errors
- [x] ConnectorManager: one connector error does not affect other connectors
- [x] Cross-tenant: Connector for Tenant A never returns data from Tenant B source

**Tests:** 18 unit passing / 78 cumulative passing
**Architect approval:** [ ]
**Decisions:**
- Rotation detection: size-shrink primary (cross-platform), inode-change secondary (POSIX only, skipped when st_ino == 0 on Windows)
- FileConnector opens in binary mode ("rb") to guarantee portable byte-level seeking after cursor restore
- asyncio.to_thread() wraps all synchronous SQLAlchemy Core calls in DBConnector
- DBConnector tests use file-based SQLite (in-memory is connection-scoped, can't share across engine instances)
- asyncio.gather() with AsyncMock hangs: isolation tests use sequential execution instead
- CONNECTOR_OBSERVER=polling added to .env.example for cross-platform watchdog config
**Limitations:**
- _dispatch() in ConnectorManager is a stub; wired to anomaly engine in Module 6
- DBConnector only tested against SQLite; Postgres/MySQL drivers not installed in dev env

---

## Module 5 — Log Ingestion (Push Path) ✓
**Goal:** Push ingest endpoint, log service, rate limiting

- [x] `models/schemas/v1/ingest.py` — LogEntryRequest (with full validation),
      LogEntryResponse, BatchIngestRequest, BatchIngestResponse
- [x] `services/log_service.py` — parse, validate, route to anomaly engine (no DB write for raw entries)
- [x] `routers/v1/ingest.py` — POST /api/v1/ingest and /api/v1/ingest/batch
- [x] Rate limiting: 100/min per API key via `slowapi`, custom 429 handler with Retry-After

**Tests required:**
- [x] Valid single entry → 201 + LogEntryResponse, no log_entries DB row created
- [x] Valid batch (100 entries) → 201, all processed
- [x] Missing required field (message) → 422 with field detail
- [x] Invalid level value → 422
- [x] Missing API key → 401
- [x] API key with wrong scope (alerts:read) → 403
- [x] Rate limit: 101st request in 1 min → 429 with Retry-After header
- [x] Large payload (10KB message) → handled, not truncated
- [x] Entry with future timestamp → accepted (occurred_at from payload)
- [x] Batch with one invalid entry → 422, none processed (transactional)

**Built:** LogService is stateless and attached to app.state. Raw entries flow to the anomaly engine stub (no DB write). LogEntryResponse.id is a correlation UUID, not a DB PK.
**Tests:** 10 unit/integration / 2 security passing (88/88 cumulative, 89% coverage)
**Decisions:** `default_factory` for occurred_at (Pydantic v2 validators don't run on default values); custom 429 handler (slowapi `headers_enabled=True` conflicts with starlette middleware response wrapping); `request_log` excluded from no-write assertion (middleware audit log is expected).
**Limitations:** `_route_to_engine()` is a stub — wired to real AnomalyEngine in Module 6.

**Architect approval:** [ ]
**Notes:**

---

## Module 6 — Anomaly Engine ✓
**Goal:** EWMA state management, all 6 anomaly types, caching, auto-resolution

- [x] `models/db.py` additions — EwmaState, AnomalyAlert ORM models
- [x] `services/cache.py` — CacheBackend ABC, InProcessCache implementation
- [x] `services/anomaly_engine.py`:
  - [x] Load EWMA state from cache (fallback to DB on cache miss)
  - [x] Capture pre-update ewma/variance BEFORE state mutation (Lesson 8 fix)
  - [x] Update EWMA + variance on each event batch
  - [x] Persist state to DB every 10 events and on graceful shutdown (flush())
  - [x] ERROR_RATE_SPIKE detection + severity mapping (checks EWMA_{t-1})
  - [x] SUSTAINED_ELEVATION detection (10min WARNING, 15min CRITICAL)
  - [x] SERVICE_SILENCE detection (volume baseline + 2-min silence window, auto-resolve)
  - [x] LATENCY_SPIKE detection (conditional on latency_ms present; pre-update EWMA)
  - [x] NOVEL_ERROR detection (SHA-256 fingerprint, 24h TTL, r"\d+" normalization)
  - [x] CASCADE detection (3+ services spiking within 5-min window; _cascade_fired dedup)
  - [x] Auto-resolution after 2 clean windows (ERROR_RATE_SPIKE, LATENCY_SPIKE)
  - [x] Full v1.0 anomaly JSON contract (full_payload, cascade_context, evidence)
  - [x] Persist alert to anomaly_alerts with tenant_id on every record
- [x] `services/log_service.py` — set_engine() wire-up; db passed through from ingest endpoint
- [x] `main.py` — AnomalyEngine + InProcessCache attached to app.state in lifespan; flush on shutdown

**Tests: 53 unit/integration/security passing (141/141 cumulative)**

All 6 detectors covered. Key tests:
  - Warmup blocks all detectors for first 10 observations
  - ERROR_RATE_SPIKE WARNING/CRITICAL thresholds, auto-resolve, payload shape
  - SUSTAINED_ELEVATION WARNING at 10min, CRITICAL at 15min, auto-clears
  - SERVICE_SILENCE fires + auto-resolves; no fire without volume baseline
  - LATENCY_SPIKE WARNING/CRITICAL, no-op without latency_ms data
  - NOVEL_ERROR: numeric normalization, TTL expiry, level filter
  - CASCADE: 3-service threshold, dedup within window, 5-min window boundary
  - Cross-tenant isolation: CASCADE, tenant_id on every alert, separate EWMA cache keys
  - EWMA persistence every PERSIST_EVERY events, cold-start DB load

**Evals: 6/6 passing**
  eval_anomaly_precision_recall.py:
    ERROR_RATE_SPIKE  Precision=1.000  Recall=1.000  FPR=0.000  (targets: >0.85 / >0.90 / <0.05) ✓
    LATENCY_SPIKE     Precision=1.000  Recall=1.000  FPR=0.000  ✓
    SUSTAINED_ELEVATION recall=1.000   FPR=0.000  ✓
  eval_false_positive_rate.py:
    ERROR_RATE_SPIKE   FPR=0.0000  ✓
    LATENCY_SPIKE      FPR=0.0000  ✓
    SERVICE_SILENCE    FPR=0.0000  ✓
    SUSTAINED_ELEVATION FPR=0.0000  ✓
    CASCADE            FPR=0.0000  ✓

**Decisions:**
  - Pre-update snapshot: prev_ewma/prev_variance captured before _update_ewma() so spike
    detectors compare against EWMA_{t-1}, not EWMA_t (which has absorbed the spike).
  - Numeric normalization: r"\d+" (not \b\d+\b) so embedded digits in tokens like "5s" normalize.
  - CASCADE de-dup: _cascade_fired dict keyed by tenant_id (not source_id) — one CASCADE
    per tenant per 5-min window; SQLite insertion-order satisfies "earliest spike" without ORDER BY.
  - SERVICE_SILENCE auto-resolves immediately on the same ingest call that detected it (logs resumed).
  - EWMA state FK silently skipped for push sources (source_id not in log_sources).

**Limitations:**
  - latency_ewma / latency_variance not persisted to DB (no schema column) — resets on restart.
  - CASCADE alert references first seen alert_id per service (unordered); add ORDER BY detected_at
    when migrating to PostgreSQL (tasks/lessons.md Decision).

**Architect approval:** [ ]

---

## Module 7 — Webhook System
**Goal:** Alert delivery, HMAC signing, retry, simulated consumer endpoint

- [ ] `models/db.py` additions — WebhookEvent ORM model
- [ ] `services/webhook_dispatcher.py`:
  - [ ] Retrieve and decrypt webhook_secret_enc (Fernet)
  - [ ] Build full v1.0 anomaly payload
  - [ ] Compute HMAC-SHA256 signature
  - [ ] POST with headers: X-Watchdog-Signature, X-Watchdog-Delivery-ID, X-Watchdog-Event
  - [ ] Log attempt to webhook_events
  - [ ] Retry: 3 attempts, exponential backoff (2s, 4s, 8s)
  - [ ] Auto-disable after 10 consecutive failures, flag in source_state
- [ ] `routers/v1/webhook.py` — POST /api/v1/webhook/receive (simulated consumer)
- [ ] Background retry task: runs every 30s, retries pending failed deliveries

**Tests required:**
- [ ] Successful delivery: webhook_events record, success=True, correct headers
- [ ] HMAC: computed signature matches manual verification
- [ ] HMAC: tampered payload rejected by verification (compare_digest)
- [ ] X-Watchdog-Delivery-ID: unique UUID per attempt
- [ ] Failed delivery (5xx): 3 retries logged, success=False on all
- [ ] Failed delivery: backoff intervals correct (mock time)
- [ ] After 10 consecutive failures: webhook auto-disabled
- [ ] Webhook receive: logs payload, returns 200
- [ ] Webhook receive: verifies HMAC signature on received payload
- [ ] Webhook secret: decrypted correctly from Fernet-encrypted DB value
- [ ] Tenant isolation: Tenant A webhook only receives Tenant A anomalies

**Architect approval:** [ ]
**Notes:**

---

## Module 8 — Alerts API
**Goal:** External consumer REST API for anomaly output

- [ ] `models/schemas/v1/alerts.py` — AnomalyAlertResponse, AnomalyListResponse,
      AcknowledgeRequest, full v1.0 contract in response
- [ ] `routers/v1/alerts.py`:
  - [ ] GET /api/v1/alerts (paginated by cursor, filterable)
  - [ ] GET /api/v1/alerts/{id}
  - [ ] POST /api/v1/alerts/{id}/acknowledge

**Tests required:**
- [ ] List: returns paginated results with next_cursor
- [ ] List: cursor pagination stable under concurrent inserts
- [ ] Filter service=payment-service: only that service returned
- [ ] Filter severity=CRITICAL: only CRITICAL returned
- [ ] Filter status=open: only open alerts returned
- [ ] Filter date range: correct window applied
- [ ] Get by ID: returns full v1.0 contract JSON
- [ ] Get by ID: 404 on unknown ID
- [ ] Get by ID: 404 (not 403) on another tenant's alert ID (no information leak)
- [ ] Acknowledge: status → acknowledged, acknowledged_by + timestamp set
- [ ] Acknowledge: Tenant Operator can acknowledge
- [ ] Acknowledge: API key with alerts:read cannot acknowledge → 403
- [ ] Tenant isolation: Tenant A cannot list or get Tenant B alerts

**Architect approval:** [ ]
**Notes:**

---

## Module 9 — Admin APIs
**Goal:** Source CRUD, user management, API key self-service, webhook management

- [ ] `routers/v1/admin/sources.py` — GET/POST /sources, GET/PATCH/DELETE /sources/{id}
- [ ] `routers/v1/admin/users.py` — GET/POST /users, PATCH/DELETE /users/{id}
- [ ] `routers/v1/admin/keys.py`:
  - [ ] POST /keys — generate new API key (plaintext returned once)
  - [ ] GET /keys — list own keys (prefix, scopes, last_used, expiry — no value)
  - [ ] POST /keys/{id}/rotate — rotation with 24h grace period
  - [ ] DELETE /keys/{id} — immediate revocation
- [ ] `routers/v1/admin/webhooks.py` — GET/POST /webhooks, PATCH/DELETE /webhooks/{id}
- [ ] `routers/v1/admin/config.py` — PATCH /config (retention_days, log_retention_days)
- [ ] Source connection string: Fernet-encrypted on save, never returned after save

**Tests required:**
- [ ] Create source: valid config → 201, connector starts in ConnectorManager
- [ ] Create source: connection string encrypted at rest (not plaintext in DB)
- [ ] Create source: connection string not returned in GET response (masked)
- [ ] Create source: max_sources limit enforced → 429
- [ ] Update source: poll interval change takes effect
- [ ] Delete source: soft delete, connector stops
- [ ] Create user: Tenant Admin only, assigns role within own tenant
- [ ] Create user: cannot assign Platform Admin role → 403
- [ ] Generate key: plaintext returned once, hash stored in DB, not retrievable again
- [ ] Generate key: key_prefix stored correctly (first 12 chars)
- [ ] List keys: no plaintext values in response, prefix shown
- [ ] Rotate key: new plaintext returned once, old key in grace period
- [ ] Rotate key: old key still works during grace period
- [ ] Rotate key: old key rejected after grace period expires
- [ ] Revoke key: immediately rejected on next request
- [ ] Register webhook: secret shown once, encrypted in DB
- [ ] Update webhook: URL update takes effect on next delivery
- [ ] Config update: retention_days change persisted, applied on next cleanup run
- [ ] All admin endpoints: Tenant Operator → 403
- [ ] Cross-tenant: Tenant A Admin cannot manage Tenant B sources/users/keys

**Architect approval:** [ ]
**Notes:**

---

## Module 10 — Retention Service
**Goal:** Hourly cleanup, system_config, app log level runtime control

- [ ] `models/db.py` additions — SystemConfig ORM model
- [ ] `services/retention_service.py`:
  - [ ] Delete resolved/acknowledged anomaly_alerts older than retention_days
  - [ ] Delete webhook_events older than retention_days
  - [ ] Delete request_log older than log_retention_days
  - [ ] Never delete open alerts regardless of age
  - [ ] Run hourly as asyncio background task in lifespan
- [ ] `routers/v1/platform/health.py` — PATCH /api/v1/platform/config/log-level
      (runtime log level change, Platform Admin only)

**Tests required:**
- [ ] Retention: resolved alerts older than threshold deleted
- [ ] Retention: acknowledged alerts older than threshold deleted
- [ ] Retention: OPEN alerts NOT deleted regardless of age
- [ ] Retention: webhook_events cleaned on same schedule
- [ ] Retention: request_log cleaned on log_retention_days schedule
- [ ] Retention: idempotent (run twice, same result)
- [ ] Retention: Tenant A retention setting does not affect Tenant B data
- [ ] Log level: PATCH updates level, subsequent log output at new level
- [ ] Log level: only Platform Admin can change, Tenant Admin → 403

**Architect approval:** [ ]
**Notes:**

---

## Module 11 — Health + Versioning
**Goal:** Health endpoint, API-Version header, deprecation middleware, CHANGELOG

- [ ] `routers/v1/health.py` — GET /api/v1/health (no auth)
- [ ] Health response: status, version, uptime_seconds, db_connected,
      active_sources_count, total_alerts_today, cache_hit_rate, log_level
- [ ] `middleware.py` addition: `API-Version: 1.0` header on all responses
- [ ] `CHANGELOG.md` — v1.0.0 entry with feature summary

**Tests required:**
- [ ] Health: 200, all required fields present
- [ ] Health: db_connected=false handled gracefully when DB unavailable
- [ ] Health: uptime_seconds increases across calls
- [ ] Health: accessible without authentication
- [ ] API-Version header: present on all responses including error responses
- [ ] API-Version header: present on 404 and 422 responses

**Architect approval:** [ ]
**Notes:**

---

## Module 12 — Dashboards & UI
**Goal:** Operator dashboard, Admin panel, Consumer portal, Platform Admin UI

- [ ] `static/dashboard.html` — Chart.js error rate trends, alert feed, service grid,
      acknowledge inline, auto-refresh 10s, filter by service/severity
- [ ] `static/admin.html` — source CRUD, user management, retention config, API key list
- [ ] `static/consumer.html` — key generation, rotation, revocation, webhook management,
      delivery history
- [ ] `static/platform.html` — tenant list, platform health, log level control
- [ ] `routers/v1/dashboard.py` — GET /dashboard (HTML), GET /api/v1/dashboard/data (JSON)
- [ ] Dashboard data API: cached 5s, returns trend data + open alerts per tenant

**Tests required:**
- [ ] Dashboard: 200, Content-Type text/html, Chart.js CDN referenced
- [ ] Dashboard data: correct schema, tenant-scoped
- [ ] Dashboard data: two calls within 5s → cache hit (DB query count unchanged)
- [ ] Dashboard: accessible to Tenant Operator and Tenant Admin
- [ ] Dashboard: API Consumer (key auth only) cannot access → 401/403
- [ ] Admin panel: accessible to Tenant Admin, not Tenant Operator → 403
- [ ] Consumer portal: accessible to all authenticated users

**Architect approval:** [ ]
**Notes:**

---

## Module 13 — Platform Admin
**Goal:** Tenant management, platform-wide health, per-tenant visibility

- [ ] `routers/v1/platform/tenants.py`:
  - [ ] GET /api/v1/platform/tenants — list all tenants
  - [ ] POST /api/v1/platform/tenants — create tenant
  - [ ] PATCH /api/v1/platform/tenants/{id} — suspend/reactivate, update plan
- [ ] `routers/v1/platform/health.py`:
  - [ ] GET /api/v1/platform/health — platform-wide metrics
  - [ ] PATCH /api/v1/platform/config/log-level

**Tests required:**
- [ ] List tenants: Platform Admin only → 403 for all other roles
- [ ] Create tenant: creates tenant record + initial Platform Admin user
- [ ] Suspend tenant: all tenant users → 401 on next request
- [ ] Platform health: accurate active_tenants, total_sources, total_alerts_today
- [ ] Log level change: takes effect immediately, reflected in /api/v1/health

**Architect approval:** [ ]
**Notes:**

---

## Module 14 — Seed Data + README
**Goal:** Demo-ready multi-tenant data, complete documentation

- [ ] `scripts/seed_data.py`:
  - [ ] 2 demo tenants (Acme Corp, Beta Systems)
  - [ ] 3 services per tenant (payment-service, auth-service, api-gateway)
  - [ ] 500 log entries per tenant, spanning last 2 hours
  - [ ] 3 ERROR_RATE_SPIKE events at documented timestamps
  - [ ] 1 SUSTAINED_ELEVATION event (15 min duration)
  - [ ] 1 SERVICE_SILENCE event (auth-service, 3 min)
  - [ ] 1 CASCADE event (all 3 services within 2-min window)
  - [ ] Idempotent: run twice = same data, no duplicates
- [ ] `README.md`:
  - [ ] Setup in <5 steps (clone → .env → alembic → seed → uvicorn)
  - [ ] ASCII architecture diagram
  - [ ] Curl examples for every endpoint
  - [ ] Webhook signature verification examples (Python, Node.js, Go)
  - [ ] Known limitations section (no raw log search, SQLite write limits, no seasonality)
  - [ ] PostgreSQL upgrade path instructions
  - [ ] Secret scanning note (wdog_live_ prefix)

**Tests required:**
- [ ] Seed script runs clean, exit 0
- [ ] Seed script run twice: identical row counts
- [ ] After seed: /api/v1/alerts returns ≥5 anomalies per tenant
- [ ] After seed: dashboard shows trend data for all 3 services

**Architect approval:** [ ]
**Notes:**

---

## Module 15 — Evals
**Goal:** Numeric quality measurement for anomaly detection

- [ ] `tests/evals/eval_anomaly_precision_recall.py`
  - Labeled dataset: 200 normal windows + 50 spike windows
  - Measure precision: TP / (TP + FP) — target > 0.85
  - Measure recall: TP / (TP + FN) — target > 0.90
- [ ] `tests/evals/eval_false_positive_rate.py`
  - 1000 events from normal distribution (no injected spikes)
  - Count spurious anomaly alerts — target < 50 (FPR < 0.05)
- [ ] `tests/evals/eval_connector_lag.py`
  - 100 timed trials: write log entry → measure time to detection
  - Compute p50, p95, p99 — target p95 < 500ms
- [ ] `tests/evals/eval_cross_tenant_isolation.py`
  - Exhaustive: every alert endpoint queried with every combination of
    tenant credentials
  - Target: 0 cross-tenant data leaks

**Architect approval:** [ ]
**Notes:**

---

## Final Submission Checklist

- [ ] All 15 modules complete and architect-approved
- [ ] All unit tests passing: `pytest tests/ -v`
- [ ] All evals passing: `pytest tests/evals/ -v`
- [ ] Coverage ≥ 80%: `pytest --cov=. --cov-report=term`
- [ ] `prompts.md` — complete audit log, no secrets present
- [ ] `README.md` — setup + curl examples complete
- [ ] `FEATURES.md` — feature list current and accurate
- [ ] `DECISIONS.md` — all major decisions documented
- [ ] Public GitHub repository pushed
- [ ] Seed data loaded, demo anomalies visible in dashboard
- [ ] Tagle.ai Tag captured and included in submission package
- [ ] AI-generated presentation deck (Markdown or PPT)
