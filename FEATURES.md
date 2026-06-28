# FEATURES.md — Intelligent Observability & Event Watchdog
## Complete Product Feature List

This document defines every feature the product supports, organized by capability
area. It is the source of truth for what gets built. The database schema, API
surface, and UI all derive from this list — not the other way around.

---

## Product Model

Watchdog is a **multi-tenant SaaS observability service**. Multiple independent
engineering teams (tenants) each connect their own log sources, configure their own
anomaly detection thresholds, receive their own alerts, and manage their own API
keys — all in complete isolation from one another. One Watchdog deployment serves
many tenants.

MVP scope: invite-only tenant creation (Platform Admin creates tenant accounts).
Post-MVP: public self-signup with email verification.

---

## 1. Tenant & Account Management

### 1.1 Platform Administration (Platform Admin only)
- Create tenant accounts (name, plan tier, contact email)
- Suspend or reactivate tenant accounts
- View platform-wide health: active tenants, total sources monitored, alerts today
- Configure platform-level defaults: max sources per tenant, default retention days
- Manage platform Admin accounts

### 1.2 Tenant User Management (Tenant Admin)
- Invite users to their tenant by email (Tenant Admin and Tenant Operator roles)
- Deactivate users within their tenant
- Reset user passwords
- View user activity log within their tenant

### 1.3 Authentication
- Email + password login for all human users (JWT: 15-min access token, 7-day
  httpOnly refresh cookie)
- Logout (refresh token revocation)
- Token refresh without re-login
- Password reset via email (post-MVP: email delivery; MVP: token returned in response)

---

## 2. Log Source Configuration (Tenant Admin)

Each tenant independently configures the external log sources they want to monitor.
All source configuration is fully isolated per tenant.

### 2.1 Source Types Supported

**File-based sources**
- Connect to application log files on accessible filesystems
- Automatic file rotation detection (inode tracking)
- Cursor persistence (byte offset) — survives Watchdog restarts without re-reading
- Configurable file encoding (UTF-8 default)
- Support for common log line formats: plain text, JSON-per-line, logfmt

**Database-based sources**
- Connect to external PostgreSQL, MySQL, or SQLite databases
- High-water mark polling on indexed integer/sequence ID column
- Configurable target table and column names
- Connection string stored encrypted at rest (Fernet), never exposed after save
- Validation on setup: warns if target column is not indexed

**Push-based sources**
- Apps POST log entries directly to tenant's `/api/v1/ingest` endpoint
- Authenticated via scoped API key
- No connector configuration required — zero-friction integration for greenfield apps

### 2.2 Source Management
- Create, update, pause, resume, delete log sources
- Per-source configurable poll interval (1s–300s, adaptive by default)
- Per-source optional latency field name (enables LATENCY_SPIKE detection)
- Per-source EWMA tuning: alpha (0.1–0.9), sensitivity multiplier (1.5–5.0),
  warmup period (5–50 observations)
- Per-source maintenance window configuration (silence detection suppressed during window)
- Source health status: active / idle / backoff / error
- Last polled timestamp and last error message visible in UI

### 2.3 Source Credential Security
- DB connection strings encrypted at rest (Fernet symmetric encryption)
- Encryption key stored in platform .env, never in database
- Connection strings never returned in API responses after initial save
- Connection test on setup (validates credentials before saving)

---

## 3. Anomaly Detection Engine

### 3.1 Detection Algorithm
- Exponentially Weighted Moving Average (EWMA) with adaptive variance tracking
- Per-source EWMA state maintained in memory, persisted to DB every 10 events
  and on graceful shutdown
- Warmup period before any alerts fire (configurable, default 10 observations)
- All EWMA parameters tunable per source without redeployment

### 3.2 Anomaly Types Detected

**ERROR_RATE_SPIKE**
- Triggers when 1-minute error rate exceeds EWMA upper bound (mean + N×stddev)
- Severity: WARNING at 2.5×, CRITICAL at 5×
- Auto-resolves when error rate returns below threshold for 2 consecutive windows

**SUSTAINED_ELEVATION**
- Triggers when error rate remains above EWMA baseline for >10 consecutive minutes
- Distinct from spike: does not resolve quickly, signals systemic failure
- Severity: WARNING at 10min, CRITICAL at 15min

**SERVICE_SILENCE**
- Triggers when a previously active service emits zero logs for >2 minutes
- Baseline: rolling 30-minute log volume average
- Suppressed during configured maintenance windows
- Severity: CRITICAL (silence usually means crash or network partition)

**LATENCY_SPIKE**
- Triggers when log entries' latency field shows EWMA upper bound breach
- Only active when source config specifies a latency field name
- Same EWMA algorithm applied to latency distribution
- Severity: WARNING/CRITICAL same thresholds as error rate

**NOVEL_ERROR**
- Triggers when an error message pattern appears for the first time in 24 hours
- Message normalization: numeric tokens stripped before fingerprinting
- Bloom filter per source with 24-hour TTL
- Severity: WARNING (leading indicator, precedes volume spikes)

**CASCADE**
- Triggers when ERROR_RATE_SPIKE detected across 3+ services within 5-minute window
- References all contributing service anomaly IDs in payload
- Signals infrastructure-level failure (shared DB, network partition)
- Severity: CRITICAL always

### 3.3 Detection Quality
- Evals suite measuring precision (>0.85), recall (>0.90), FPR (<0.05)
- Detection lag measurement: p95 < 500ms from log write to alert generation

---

## 4. Alert Management

### 4.1 Alert Lifecycle
- Every detected anomaly creates an alert record with full evidence snapshot
- Alert statuses: open → acknowledged → resolved
- Auto-resolution: Watchdog marks alerts resolved when anomaly condition clears
- Manual acknowledgment by Tenant Operator or Tenant Admin

### 4.2 Alert Evidence Stored Per Alert
- Anomaly type and severity
- Detected at timestamp
- Service name, environment, source type
- Current value, EWMA baseline, threshold used
- Analysis window start and end
- Sample count (log entries analysed in window)
- Top 3 representative error messages
- Full EWMA parameters at time of detection (for auditability)
- For CASCADE: list of contributing service names and anomaly IDs

### 4.3 Alert Querying (API)
- List alerts with filters: service, severity, anomaly_type, status, date range
- Cursor-based pagination (stable under concurrent inserts)
- Get alert by ID (returns full evidence payload)
- Acknowledge alert (Operator+)

### 4.4 Alert Retention
- Configurable retention period per tenant (default: 30 days)
- Retention setting managed by Tenant Admin in admin panel
- Auto-deletion job runs hourly: deletes resolved/acknowledged alerts older than
  retention threshold
- Open alerts are never auto-deleted regardless of age
- Webhook events table purged on same retention schedule
- App's own operational logs: configurable retention, default 7 days

---

## 5. API Key Management (Self-Service)

All tenant users (Tenant Admin and Tenant Operator) can manage their own API keys
for programmatic access to Watchdog. No Admin involvement required after account
setup.

### 5.1 Key Generation
- Generate API keys from the consumer portal (no Admin required)
- Key format: `wdog_live_<32-byte-random>` (production), `wdog_test_<32-byte-random>` (test)
- Prefixed format enables automated secret scanning in CI/CD pipelines and git history
- Plaintext returned exactly once at generation — never retrievable again
- SHA-256 hash stored in DB — plaintext never persisted anywhere

### 5.2 Key Scopes
- `ingest` — push log entries to /api/v1/ingest
- `alerts:read` — read anomaly alerts via API
- `webhooks:manage` — register/update webhook subscriptions
- `sources:read` — read own source configuration (no write)
- Scopes assigned at key creation, not changeable post-creation (rotate instead)

### 5.3 Key Lifecycle
- View all own keys: name, scopes, last used timestamp, expiry — never the value
- Set optional expiry date at creation
- Rotate key: generates new key, old key enters 24-hour grace period then auto-revokes
  (enables zero-downtime rotation for consumer systems)
- Immediately revoke key (bypasses grace period)
- Keys are tenant-scoped: a key generated by Tenant A can never access Tenant B data

### 5.4 Key Security
- SHA-256 hash used for lookup — O(1), no timing attack surface
- `X-API-Key` header value never logged — only `api_key_id` (UUID) appears in logs
- Rate limits configurable per key (default: 100 req/min)
- Revoked and expired keys return 401 with `KEY_REVOKED` or `KEY_EXPIRED` error code

---

## 6. Webhook Subscriptions (External Consumer Push)

External consumers should not have to poll our API. They register a webhook endpoint
and Watchdog pushes anomaly alerts to them in real time.

### 6.1 Webhook Registration
- Any user with `webhooks:manage` scope can register a webhook
- Register: target URL, optional severity filter (only push CRITICAL, etc.),
  optional service filter (only push alerts for payment-service, etc.)
- Watchdog generates a per-webhook signing secret at registration
- Signing secret shown once, stored encrypted (Fernet) — not hashed, because we
  need to retrieve it to compute HMAC signatures

### 6.2 Webhook Delivery
- Anomaly alert POSTed to registered URL immediately on detection
- Full anomaly JSON contract v1.0 in request body
- HMAC-SHA256 signature in `X-Watchdog-Signature: sha256=<hex>` header
- `X-Watchdog-Delivery-ID` header: unique UUID per delivery attempt
- Content-Type: application/json

### 6.3 Reliability
- Retry on failure: 3 attempts, exponential backoff (2s, 4s, 8s)
- All delivery attempts logged to webhook_events table
- Delivery history visible in consumer portal (last 100 deliveries per webhook)
- Webhook auto-disabled after 10 consecutive failures (with notification in UI)
- Manual re-enable available in consumer portal

### 6.4 Consumer Signature Verification
- Documented in README with Python, Node.js, and Go code examples
- Consumer must use `hmac.compare_digest` (timing-safe) not string equality

---

## 7. Dashboards & UI

### 7.1 Operator Dashboard (Tenant Operator + Admin)
- Error rate trend per service (line chart, last 1 hour, Chart.js)
- Active alerts feed with severity badges, service name, detected time
- Service status grid: green (healthy) / amber (warning) / red (critical) / grey (silent)
- Alert acknowledgment button inline in feed
- Auto-refresh every 10 seconds (no page reload)
- Filter by service, severity, time range

### 7.2 Admin Panel (Tenant Admin)
- Log source configuration: add, edit, pause, delete sources
- Per-source EWMA parameter tuning
- User management: invite, deactivate, view activity
- Retention policy configuration
- API key management (own keys + view all tenant keys)
- Webhook management (all webhooks in tenant)

### 7.3 Consumer Portal (all authenticated users)
- Self-service API key generation, rotation, revocation
- Webhook subscription management
- Webhook delivery history
- Own API usage stats (requests today, rate limit headroom)

### 7.4 Platform Admin UI (Platform Admin only)
- Tenant account management
- Platform health overview
- Per-tenant source count and alert volume
- Log level configuration (runtime, no restart required)

---

## 8. Observability (The App Monitors Itself)

### 8.1 Health Endpoint
`GET /api/v1/health` (no auth required)
Returns: status, version, uptime_seconds, db_connected, active_sources_count,
total_alerts_today, cache_hit_rate, log_level

### 8.2 Structured Logging
- JSON-formatted log output (json-log-formatter)
- Fields: timestamp, request_id, tenant_id, method, path, status_code, latency_ms
- Sensitive headers (X-API-Key, Authorization) never logged — api_key_id logged instead
- Log level configurable at runtime via Platform Admin UI and LOG_LEVEL env var
- Default level: WARNING (production) — only anomalies, errors, connector failures
- Log rotation: 10MB per file, 3 backups retained

### 8.3 Request Audit Log
- Every API request logged to request_log table with tenant_id, api_key_id, latency
- Retention: same as anomaly retention setting
- Queryable by Platform Admin for abuse investigation

---

## 9. Security Features

### 9.1 Secret Storage Tiers (never conflated)
- **Tier 1 — Never stored:** API key plaintext. Generated, returned once, forgotten.
- **Tier 2 — Hashed (one-way, bcrypt/SHA-256):** User passwords (bcrypt cost 12),
  API key lookup hashes (SHA-256). We verify, never retrieve.
- **Tier 3 — Encrypted (two-way, Fernet):** Webhook signing secrets, DB connector
  connection strings. Must be retrieved for use. Encryption key in .env only.

### 9.2 Transport & Input Security
- All endpoints require authentication except /api/v1/health and /api/v1/auth/login
- Pydantic validation on every request body — 422 on malformed input
- Rate limiting on ingest and auth endpoints (slowapi)
- CORS: explicit allowlist, never wildcard
- No stack traces in API error responses (logged internally, clean message returned)
- JWT: RS256 asymmetric signing, 15-min access token, 7-day httpOnly refresh cookie

### 9.3 Tenant Data Isolation
- tenant_id on every user-facing table
- TenantContext FastAPI dependency injects verified tenant_id into every service call
- No cross-tenant data leakage possible via application layer
- Documented upgrade path to PostgreSQL RLS for DB-layer defense-in-depth

### 9.4 Credential Hygiene
- .env file in .gitignore — never committed
- .env.example with placeholder values and comments — committed
- No secrets in source code, seed scripts, or prompts.md audit log
- API key prefix format (wdog_live_ / wdog_test_) enables automated secret scanning
- Connection strings never returned in API responses after initial save

---

## 10. API Contract

### 10.1 Versioning
- All endpoints under /api/v1/ prefix
- Router-level versioning: adding /api/v2 is one line in main.py
- Schema-level versioning: models/schemas/v1/ namespace
- API-Version: 1.0 header on all responses
- Deprecation headers when sunsetting: Deprecation: true, Sunset: <date>

### 10.2 Standards
- OpenAPI docs at /docs (Swagger UI) and /redoc
- Pydantic request + response models on every endpoint
- Consistent error envelope on all 4xx/5xx responses
- Cursor-based pagination on all list endpoints

### 10.3 Anomaly Output Contract
- Versioned JSON schema (schema_version: "1.0")
- Stable contract — external consumers depend on it
- Same shape delivered via both REST API and webhook
- Full specification in ARCHITECTURE.md

---

## 11. Background Jobs

- **Connector polling:** asyncio background task per active source, managed by
  FastAPI lifespan. Adaptive interval. Isolated per tenant — one broken connector
  does not affect others.
- **Retention cleanup:** runs hourly, deletes resolved/acknowledged alerts and
  webhook events older than tenant's configured retention period. Open alerts exempt.
- **Webhook retry:** runs every 30 seconds, retries failed webhook deliveries
  with exponential backoff. Auto-disables webhook after 10 consecutive failures.
- **EWMA persistence:** writes in-memory EWMA state to DB every 10 events and on
  graceful shutdown. Survives restarts without losing detection context.
- **API key expiry:** runs hourly, marks expired keys as revoked. Grace period
  keys auto-revoked after 24 hours.

---

## 12. Developer Experience

- Complete README: setup in <5 minutes, curl examples for every endpoint
- `scripts/seed_data.py`: generates realistic multi-tenant demo data with known
  anomaly events at documented timestamps
- `scripts/generate_api_key.py`: CLI tool to mint and register API keys for testing
- Full OpenAPI spec auto-generated, importable into Postman/Insomnia
- Webhook signature verification examples in Python, Node.js, Go
- `.env.example` documents every config variable with description and default

---

## Feature → Database Table Mapping

| Feature | Tables Used |
|---------|-------------|
| Multi-tenant isolation | tenants, + tenant_id FK on all tables |
| User auth + RBAC | users, refresh_tokens |
| Source configuration | log_sources |
| Connector state/cursors | source_state |
| EWMA detection state | ewma_state |
| Anomaly alerts | anomaly_alerts |
| Webhook delivery | api_keys (webhook_url, webhook_secret), webhook_events |
| API key management | api_keys |
| Self-service key rotation | api_keys (grace_period_expires_at, superseded_by) |
| Retention cleanup | anomaly_alerts, webhook_events (deleted_at / created_at) |
| Request audit | request_log |
| System configuration | system_config |
| App self-monitoring | request_log, /api/v1/health (runtime computed) |
