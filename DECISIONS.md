# DECISIONS.md — Architecture Reasoning & Tradeoffs

**Project:** Intelligent Observability & Event Watchdog
**Purpose:** Every significant architectural decision made during design is recorded
here — the alternatives considered, the reasoning behind the choice, and the honest
tradeoffs accepted. This document demonstrates that the architecture was arrived at
deliberately, not by default.

---

## Decision 1: Product Model — Single-Tenant Tool vs Multi-Tenant SaaS

### Context

A log monitoring service can be built as a self-hosted single-team tool (one fixed
set of log sources, one team of operators) or as a multi-tenant SaaS where multiple
independent engineering teams each configure their own sources and see only their
own data.

### Options Considered

**Option A: Single-tenant tool**
Simpler data model — no tenant_id on tables, no cross-tenant isolation concerns.
Faster to build.

Limitation: fundamentally limits the product's value proposition. A monitoring
service used by only one team is an internal tool. A monitoring service used by
many teams is a product.

**Option B: Multi-tenant SaaS from day one**
Each tenant independently configures sources, manages users, generates API keys,
and sees only their own anomalies and alerts. Data isolation enforced at every
layer.

Cost: higher initial complexity. Every table carries tenant_id. Every query filters
on it. The authentication system must produce a verified TenantContext, not just a
user identity.

### Decision: Option B (Multi-tenant SaaS)

Multi-tenancy is the right architectural foundation because retrofitting it later
is a schema migration, a security audit, and a rewrite of every query — simultaneously.
Adding tenant_id to every table upfront costs one sprint. Adding it later costs a
production incident.

MVP scope narrows the surface area: invite-only tenant creation (Platform Admin
creates accounts). Public self-signup is a router and a UI page on top of the
existing multi-tenant foundation — not an architectural change.

**Tradeoff accepted:** Every service call carries and filters on tenant_id. Every
test fixture needs two tenants (to verify isolation). Higher initial complexity
accepted because the alternative is a design debt that compounds with every feature.

---

## Decision 2: Tenant Data Isolation — Application Layer vs Database RLS

### Context

With multiple tenants sharing one database, preventing Tenant A from seeing Tenant
B's data is critical. Two layers where this can be enforced:

### Options Considered

**Option A: Application-layer isolation only**
Every service function receives a verified TenantContext and filters all queries
with `WHERE tenant_id = :tid`. Simple to implement, works on SQLite.

Risk: a bug in the application layer (missed WHERE clause, IDOR vulnerability) can
expose cross-tenant data. Application bugs happen.

**Option B: PostgreSQL Row Level Security (RLS)**
Database engine enforces isolation at the query level, regardless of application
code:
```sql
CREATE POLICY tenant_isolation ON anomaly_alerts
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```
Even if the application sends a query without a tenant filter, the DB silently
scopes it. Defense-in-depth against application bugs.

Limitation: SQLite has no RLS support. Requires PostgreSQL.

**Option C: Application layer now, RLS as documented upgrade path**

### Decision: Option C

We implement rigorous application-layer isolation via TenantContext — a FastAPI
dependency that extracts verified tenant_id from the JWT or API key and injects it
as a typed parameter into every service call. No service function ever accepts
raw tenant_id from request input.

We explicitly document PostgreSQL RLS as the defense-in-depth layer to add when
migrating off SQLite for production scale. The schema is already PostgreSQL-compatible
(UUIDs, indexed tenant_id on every table) — enabling RLS post-migration is an ALTER
TABLE and policy creation, not a schema change.

**Tradeoff accepted:** In the SQLite MVP, a hypothetical application bug could cause
a cross-tenant data leak. Mitigated by the TenantContext design (no raw input path),
comprehensive cross-tenant isolation tests in the test suite, and the documented
upgrade path to RLS.

---

## Decision 3: Raw Log Storage — Store vs Discard

### Context

The system reads log entries from external sources. Should it store those entries
in its own database?

### Options Considered

**Option A: Store all ingested log entries**
Enables log search, historical replay, audit trail of raw data.

Critical problem: a monitored service emitting 1,000 log lines per minute across
10 services generates 14.4 million rows per day. At that volume, the log_entries
table becomes the dominant performance concern within days. Storage costs grow
linearly with monitoring scope. We become a log storage service — which is not
what we are.

**Option B: Store nothing — process and discard**
Read log entries, run through anomaly engine, update EWMA state, generate alert
if warranted, discard the raw entries.

The EWMA algorithm is stateless with respect to raw entries — it only needs the
current error rate and the running weighted average. We do not need to store the
entries to maintain detection accuracy.

**Option C: Store anomalies only, with embedded evidence**
Persist only the anomaly alert records, with enough evidence embedded in each
record (error rate, EWMA values, representative error messages, window timestamps)
for an operator to understand what happened without needing raw log access.

### Decision: Option C (anomalies only, evidence embedded)

This is the architecturally correct position. Watchdog is an anomaly detection
service, not a log storage service. The distinction matters:
- Our value is in detection, not storage
- Our DB stays lean (writes are proportional to anomaly count, not log volume)
- The embedded evidence in each anomaly record is sufficient for triage
- Operators who need raw log access already have it — via the original log source

**Tradeoff accepted:** No raw log search or replay capability. Operators who need
to investigate an alert must go to the original log source. This is explicitly
documented in the README as a known limitation and a deliberate design choice.

---

## Decision 4: Log Source Strategy — Connector Architecture

### Context

How should Watchdog connect to external log sources, and what source types should
it support?

### Options Considered

**Option A: Push only**
External apps POST to /api/v1/ingest. Simple, no polling infrastructure. Works
perfectly for new applications that can be modified.

Limitation: requires changes to every monitored application. Cannot monitor legacy
systems or third-party applications without code changes.

**Option B: File polling only**
Read application log files directly. Works with any application.

Limitation: requires filesystem access. Cannot monitor services on remote hosts
without mounting volumes. Does not handle structured DB-backed logs well.

**Option C: Database polling only**
Read from external log tables via SQL.

Limitation: not all applications log to databases. Forces structured logging
discipline that legacy applications may not have.

**Option D: Plugin connector architecture (all three)**
Abstract base class with file, database, and push implementations. New source types
(Kafka, CloudWatch, Loki) are new files implementing the interface — zero changes
to existing code.

### Decision: Option D

Real infrastructure is heterogeneous. A single company may have nginx writing to
files, a Django app writing to Postgres, and a new microservice that can adopt push.
The plugin architecture costs one abstraction layer and buys unlimited extensibility.

**Tradeoff accepted:** Three connector implementations to build, test, and maintain
versus one. Mitigated by the shared base class and shared test patterns.

---

## Decision 5: File Connector — Polling vs Filesystem Events vs Hybrid

### Context

For file-based log sources, how do we detect new lines efficiently?

### Options Considered

**Option A: Interval polling**
Open file, seek to last byte offset, read new lines, close. Simple, portable.

Limitation: detection latency = poll interval. At 5s intervals, a spike takes up
to 5s to be detected.

**Option B: inotify / FSEvents (OS filesystem events)**
OS notifies instantly when file is modified. Near-zero latency.

Limitation: inotify watch limits (default 8,192 on Linux). Does not work over NFS
mounts — common in containerized environments with mounted log volumes.

**Option C: Hybrid via `watchdog` library**
Abstracts inotify/FSEvents/kqueue across platforms. Automatic fallback to polling
when event-based watching fails (NFS, Docker volumes).

### Decision: Option C

The `watchdog` library provides the right abstraction without requiring us to
implement platform-specific filesystem event handling. Near-zero latency on local
filesystems, graceful degradation on network mounts.

**Tradeoff accepted:** External dependency (~2MB). Accepted — the alternative is
implementing and maintaining OS-specific event APIs ourselves.

---

## Decision 6: DB Connector — High-Water Mark vs Timestamp Polling

### Context

For database log sources, how do we efficiently retrieve only new rows?

### Options Considered

**Option A: Timestamp-based polling**
```sql
SELECT * FROM logs WHERE created_at > :last_checked_at
```
Simple. Works on any table with a timestamp column.

Critical problem: not safe at boundaries. Two rows can have identical millisecond
timestamps. Clock skew between application server and DB server can cause missed
rows. Without an index on `created_at`, this is a full table scan on every poll.

**Option B: High-water mark on indexed integer ID**
```sql
SELECT * FROM logs WHERE id > :last_seen_id ORDER BY id ASC LIMIT 500
```
O(log n) with B-tree index. Strictly monotonic — no missed rows, no duplicates,
no clock skew. Advances the high-water mark only after successful processing.

**Option C: Change Data Capture (CDC)**
Postgres logical replication, MySQL binlog. True streaming.

Limitation: requires replication permissions that application owners rarely grant
to monitoring tools. High operational complexity for setup and maintenance.

### Decision: Option B (High-Water Mark)

The high-water mark pattern is used by Debezium, Kafka Connect JDBC Source, and
AWS Database Migration Service for exactly these correctness properties. It requires
only read permissions on the source table and an indexed integer ID column.

We validate the index on source setup and warn if missing.

**Tradeoff accepted:** Requires an indexed integer/sequence ID. If the source table
uses UUIDs without a sequence column, we fall back to timestamp with documented
boundary caveats.

---

## Decision 7: Polling Frequency — Fixed vs Adaptive

### Context

How frequently should connectors poll their sources?

### Options Considered

**Option A: Fixed interval**
Admin sets 5s, connector polls every 5s regardless of activity.

Problem: idle sources (quiet at 3am) polled just as aggressively as active ones.
Multiplied across many tenants and sources this wastes source system resources.

**Option B: Fully dynamic**
Poll as fast as there is data.

Problem: a burst of activity could cause us to hammer a production database.
Unpredictable load on source systems.

**Option C: Adaptive with floor and ceiling**
- ACTIVE: poll at configured interval (default 5s)
- IDLE: poll every 30s after 5 consecutive empty polls
- BACKOFF: poll every 60s after 3+ consecutive errors
- Return to ACTIVE immediately on any new data
- Hard floor: 1s (prevents source hammering regardless of admin config)

### Decision: Option C

Adaptive polling is the right balance between responsiveness and being a good
infrastructure citizen. The 1s floor is a safety guardrail — no admin misconfiguration
should be able to DDOS a production database.

**Tradeoff accepted:** More complex state machine per connector. Tested explicitly.

---

## Decision 8: Anomaly Detection Algorithm — EWMA

### Context

The challenge specifies "AI logic" for anomaly detection. Several algorithms were
evaluated.

### Options Considered

| Algorithm | Key Strength | Key Weakness | Verdict |
|-----------|-------------|--------------|---------|
| Static threshold | Zero complexity | Manual per-service tuning, misses relative spikes | Rejected |
| Simple rolling average | Easy to understand | Treats old data equally, lags on spikes | Rejected |
| Z-score (static baseline) | Familiar statistics | Assumes stationarity, false positives on traffic growth | Rejected |
| EWMA with adaptive variance | Adapts to drift, O(1), explainable, proven in production | No seasonality modeling | **Selected** |
| LSTM / neural network | Handles complex patterns | Needs training data, not explainable, overkill | Rejected |
| Prophet (Facebook) | Handles seasonality | External dependency, needs historical data, slow | Post-MVP upgrade path |

### Decision: EWMA with Adaptive Variance

EWMA is the algorithm behind AWS CloudWatch Anomaly Detection, Netflix Atlas, and
Google SRE spike detection. It is statistically rigorous, O(1) per event (no window
to maintain), adapts automatically to long-term drift, and produces an immediately
explainable output: "current rate is X, weighted baseline is Y, threshold is Z."

We extend vanilla EWMA by tracking EWMA of variance (Welford's online algorithm
adapted for exponential weighting). This gives adaptive upper/lower bounds rather
than a fixed multiplier on the mean alone, reducing false positives during naturally
high-variance periods.

**Tradeoff accepted:** No seasonality modeling. A service with naturally higher error
rates on Friday afternoons will generate initial alerts until EWMA adapts. Noted in
README as known limitation. Prophet integration is the documented upgrade path.

---

## Decision 9: Anomaly Taxonomy — Six Types

### Context

Most observability tools detect only error rate spikes. We chose to detect six
distinct anomaly types.

### Rationale Per Type

**ERROR_RATE_SPIKE** — the obvious one. Sudden burst, usually transient.

**SUSTAINED_ELEVATION** — spike and sustained elevation have different root causes
(transient failure vs systemic degradation) and require different responses. A spike
that resolves in 30 seconds should not page on-call. Sustained elevation for 15
minutes absolutely should. Treating them as the same alert type forces operators
to manually observe duration — error-prone under pressure.

**SERVICE_SILENCE** — absence of logs is itself a signal. A crashed service emits
no errors — which means an error-rate-only system sees nothing wrong while the
service is completely down. Silence detection catches what error detection misses.

**LATENCY_SPIKE** — error rate and latency are orthogonal failure dimensions. A
service can have a normal error rate while taking 10 seconds to respond. Separate
detection signal, separate alert type.

**NOVEL_ERROR** — a new exception type is a leading indicator. It often precedes
a volume spike. Detecting it early enables investigation before the error rate climbs.
The bloom filter approach is O(1) space and O(1) time per check.

**CASCADE** — multiple simultaneous service anomalies indicate infrastructure-level
failure. Surfacing them as isolated per-service alerts creates noise and obscures
the shared root cause. A CASCADE alert immediately tells the operator: "this is
not a payment-service problem, this is a database problem."

**Tradeoff accepted:** Six detection algorithms to implement, test, and tune. Each
has distinct false-positive characteristics. Accepted because the taxonomy maps
directly to real SRE failure modes.

---

## Decision 10: Raw Log Storage — Not Storing Ingested Logs

*(Covered fully in Decision 3. Cross-referenced here for completeness.)*

We do not store raw log entries. Anomaly records embed sufficient evidence (error
rate, EWMA values, representative messages, window bounds) for triage. This keeps
write volume proportional to anomaly count rather than log volume.

---

## Decision 11: API Key Storage — Hash vs Encrypt vs Plaintext

### Context

API keys are secrets. How they are stored determines the blast radius of a database
breach.

### Options Considered

**Option A: Store plaintext**
Simple lookup. Catastrophic breach impact — all keys immediately compromised if DB
is exfiltrated.

**Option B: Hash with bcrypt**
Bcrypt is slow by design (for password protection). At 12 rounds, verifying one key
takes ~250ms. A system verifying 100 API keys per second would spend 25 seconds per
second on bcrypt — 25x the available CPU.

**Option C: Hash with SHA-256**
SHA-256 is fast (microseconds) and deterministic — computing SHA-256 of the same
input always gives the same output, so lookup is O(1). Not suitable for passwords
(no salt, too fast for offline brute force), but correct for API keys because API
keys are already high-entropy (`secrets.token_urlsafe(32)` = 256 bits). Brute
forcing a 256-bit random value is computationally infeasible regardless of hash speed.

### Decision: SHA-256 for API keys, bcrypt for passwords

The distinction: passwords are low-entropy human-chosen secrets — bcrypt's slowness
provides meaningful brute-force resistance. API keys are cryptographically random
256-bit values — no brute-force resistance is needed beyond the entropy of the key
itself. SHA-256 provides tamper detection with O(1) lookup.

**Tradeoff accepted:** If the same key value somehow appeared in two systems using
SHA-256 (not bcrypt), the same hash would appear in both DBs. For random 256-bit
keys, this is a non-concern.

---

## Decision 12: Webhook Secret Storage — Encrypted Not Hashed

### Context

Webhook signing secrets must be stored. Unlike API keys, we need to retrieve the
plaintext to compute HMAC signatures on outgoing webhook deliveries.

### Options Considered

**Option A: Hash (one-way)**
Cannot retrieve original — cannot compute HMAC. Ruled out immediately.

**Option B: Store plaintext**
Simple. Full breach exposure if DB is exfiltrated.

**Option C: Fernet symmetric encryption**
- Key stored in .env (never in DB)
- Secret stored encrypted in DB
- Decrypted in memory at delivery time, not held longer than needed
- Key rotation: re-encrypt all secrets with new key (offline script)
- DB breach without .env = encrypted values only, unusable

### Decision: Fernet encryption

The threat model: DB exfiltration (SQL injection, backup exposure) should not
expose webhook secrets. Fernet provides this guarantee as long as the encryption
key in .env is not also exfiltrated. This is the industry-standard approach for
secrets that must be retrieved (Stripe, Twilio, GitHub all use equivalent patterns).

Same approach applied to DB connector connection strings.

**Tradeoff accepted:** Encryption key in .env is a single point of failure. Mitigated
by: .env never committed to git, .env file permissions restricted to app process
user, documented rotation procedure.

---

## Decision 13: API Key Format — Prefixed Keys

### Context

API keys will inevitably end up in places they should not: git commits, log files,
Slack messages, CI/CD pipeline outputs. How do we make accidental exposure detectable?

### Decision: Prefixed Key Format

Keys formatted as `wdog_live_<32-byte-random>` (production) and
`wdog_test_<32-byte-random>` (test/development).

Benefits:
- GitHub secret scanning, truffleHog, and other automated scanners can detect
  Watchdog keys by prefix and alert before they are used
- `wdog_test_` keys are visually distinct from `wdog_live_` keys — reduces risk of
  using production keys in test environments
- The prefix makes Watchdog keys identifiable in support and security investigations
  without needing to decode the key value

Precedent: Stripe (sk_live_ / sk_test_), Twilio, SendGrid, Anthropic, GitHub (ghp_),
npm (npm_) all use this pattern for exactly these reasons.

**Tradeoff accepted:** Slightly shorter effective entropy per character (prefix
characters are fixed). Negligible — the random suffix is still 256 bits.

---

## Decision 14: Caching — In-Process vs Redis vs No Cache

### Context

Two caching needs: EWMA state (avoid DB write per ingest event) and dashboard
aggregation queries (avoid re-running aggregate SQL on every 10s auto-refresh).

### Options Considered

**Option A: No cache**
Every ingest event writes to DB. Every dashboard refresh runs aggregate SQL.
Simple, correct, but potentially slow under sustained load.

**Option B: Redis**
Industry standard, persistent across restarts, supports multi-instance deployments.

Limitation: external dependency that must be running. Adds operational complexity
for evaluators. At single-instance scale the distributed properties of Redis are unused.

**Option C: In-process dict with write-through, Redis-swappable abstraction**
Zero external dependencies. Sub-microsecond read. CacheBackend abstraction allows
Redis swap via `CACHE_BACKEND=redis` config change.

### Decision: Option C

The CacheBackend abstraction signals the right architectural intent without forcing
Redis as a dependency at this scale. Redis is the correct evolution when the service
needs to run multiple instances — and the abstraction makes that a one-line config
change, not a refactor.

**Tradeoff accepted:** In-process cache lost on restart. EWMA state recovers from
last DB persist (worst case: lose N events of EWMA history, handled gracefully by
the warmup mechanism).

---

## Decision 15: Database — SQLite vs PostgreSQL

### Context

Challenge specifies free-tier database. SQLite and PostgreSQL are both viable.

### Decision: SQLite with PostgreSQL upgrade path

SQLite: zero external dependencies, single file, ships with Python, identical
SQLAlchemy interface as PostgreSQL. Switching is a connection string change in
.env plus `alembic upgrade head`. The schema is PostgreSQL-compatible (UUIDs,
proper indexes, no SQLite-specific syntax).

Known SQLite limitations: no RLS support, write concurrency limits under high
sustained load, no native JSON operators (stored as TEXT, parsed in Python).
All documented as known limitations with the PostgreSQL upgrade path.

**Tradeoff accepted:** Cannot horizontally scale Watchdog with SQLite as the backend.
Not a concern at MVP scope — explicitly noted for production readiness.

---

## Decision 16: API Versioning — URL Path vs Header-Based

### Context

The anomaly output JSON contract will be consumed by external systems. Breaking
changes to this contract break those consumers. How do we version?

### Options Considered

**Option A: No versioning (/api/alerts)**
Every schema change breaks all consumers. Rejected.

**Option B: Header-based (Accept: application/vnd.watchdog.v1+json)**
REST-purist approach. Clean URLs. Harder to test, harder to share as a URL, less
discoverable.

**Option C: URL path versioning (/api/v1/)**
Self-describing URLs. Easy to test with curl. Easy to proxy at infrastructure level.
Adding v2 = one line in main.py, v1 untouched.

Precedent: Stripe, Twilio, GitHub, Anthropic all use URL path versioning.

### Decision: Option C (URL path versioning)

The overwhelming industry precedent and operational simplicity make this the clear
choice. Schema models are namespaced by version (models/schemas/v1/) so v2 changes
never touch v1 models.

---

## Decision 17: Authentication — JWT vs Session Cookies vs API Keys (Single vs Split)

### Context

Two distinct user types: human operators via UI, machine consumers via API.

### Decision: JWT for humans, scoped API keys for machines

JWT: RS256 asymmetric (private key signs, public key verifies — enables future
microservice token verification without distributing signing key). 15-min access
token. 7-day refresh token in httpOnly/Secure/SameSite=Strict cookie. Refresh
token stored as SHA-256 hash (same rationale as API keys).

API keys: scoped, prefixed, SHA-256 hashed, per-tenant. Rotation with grace period.

One auth system for humans, one for machines. The split maps to the actual security
needs: humans need session management and token expiry UX; machines need stable,
rotatable credentials with scope constraints.

**Tradeoff accepted:** Two auth systems to implement and test. Complexity bounded —
both are well-understood patterns with library support.

---

## Decision 18: Frontend — Python-Native Framework vs Jinja2 + Alpine.js

### Context

The UI has genuine complexity: four distinct views (Operator Dashboard, Admin Panel,
Consumer Portal, Platform Admin), live auto-refreshing charts, CRUD forms with
validation, role-based access control, and paginated tables. Plain HTML/JavaScript
would be fragile and unmaintainable. The question is what framework to use.

### Options Considered

**Next.js (React + TypeScript)**
Industry-leading for complex UIs. Full TypeScript, component model, file-based
routing, server-side rendering.

Limitation for this context: introduces a Node.js runtime alongside Python/FastAPI.
Two servers to start, two dependency trees, CORS configuration between them, more
complex deployment. In a 16-hour judged build, the operational overhead is
significant risk for judging criteria that are primarily about the backend.

Post-submission upgrade path: the decoupled FastAPI API layer means Next.js can
be dropped in later with zero backend changes. Not the right call for MVP.

**Python-Native Frameworks (Reflex, Flet, Solara, NiceGUI)**

All evaluated. The Python community's answer to "frontend in Python" is real and
growing — Reflex compiles to React, Flet uses Flutter, Solara is React-based,
NiceGUI integrates with FastAPI directly.

Honest assessment: all are early-stage (2022-2023). All either require a second
server process or a build pipeline not under our control. Documentation gaps are
real. For a time-constrained judged submission, fighting framework edge cases is
unacceptable risk.

The Python community's actual production norm for web UI alongside FastAPI is
Jinja2 server-side templates — not these newer frameworks.

**Streamlit / Dash**
Excellent for data exploration apps. Not appropriate for multi-page applications
with authentication flows, CRUD admin panels, and strict role-based routing.
Both run their own servers, separate from FastAPI.

**Jinja2 + Alpine.js + Chart.js**

Jinja2: Python-native server-side templating (Pallets project, same team as Flask).
First-class FastAPI support. Template inheritance keeps layouts DRY. Role-based
rendering enforced server-side — 403 before the template renders for unauthorized
roles. Jinja2 is part of the Python ecosystem in every meaningful sense.

Alpine.js: 15KB, TypeScript-authored with full type definitions, delivered via CDN.
No build step, no npm, no separate codebase. Attribute-based — behavior declared
in HTML, readable by any Python engineer without framework knowledge. Handles all
client-side reactivity: auto-refresh, form state, inline interactions.

Chart.js: CDN-delivered, handles the one genuinely client-side component (trend
charts). Fetches from `/api/v1/dashboard/data` JSON endpoint.

### Decision: Jinja2 + Alpine.js + Chart.js

This stack is the right tool for each layer:
- FastAPI owns the request lifecycle and auth
- Jinja2 (Python ecosystem) owns HTML rendering and role-based view control
- Alpine.js owns client-side reactivity without a build step or second server
- Chart.js owns data visualization

Everything served on one port. No npm. No Node.js runtime. No CORS configuration.
The entire UI is a consumer of the same `/api/v1/` API that external consumers use
— which reinforces the API-first architecture rather than undermining it.

The frontend is intentionally thin. The product's value is in the backend: anomaly
detection, multi-tenant isolation, connector architecture, and the API contract.
The UI exists to make those capabilities accessible, not to be impressive in itself.

**Tradeoff accepted:** Alpine.js is JavaScript, not Python. Acknowledged openly.
The alternative (a Python-native framework) introduces more operational risk than
it eliminates. Jinja2 keeps the templating layer firmly in the Python ecosystem.
A richer TypeScript frontend (Next.js) is the documented post-MVP upgrade path,
requiring zero backend changes.

---

## Summary Decision Table

| # | Decision | Choice | Key Reason | Tradeoff |
|---|----------|--------|------------|----------|
| 1 | Product model | Multi-tenant SaaS | Retrofitting later = schema migration + security audit | Higher initial complexity |
| 2 | Data isolation | App layer + RLS upgrade path | SQLite has no RLS; TenantContext by design | No DB-layer safety net in MVP |
| 3 | Log storage | Anomalies only, evidence embedded | Write volume proportional to anomalies not log lines | No raw log search/replay |
| 4 | Connector architecture | Plugin ABC, 3 implementations | Heterogeneous real environments | 3× test surface |
| 5 | File detection | Hybrid events + polling fallback | Near-zero latency, NFS-safe | watchdog dependency |
| 6 | DB polling | High-water mark on indexed ID | O(log n), no clock skew, no missed rows | Requires integer PK/sequence |
| 7 | Poll frequency | Adaptive with floor/ceiling | Source-respectful, fast when active | State machine complexity |
| 8 | Detection algorithm | EWMA with adaptive variance | Proven, O(1), explainable, drift-adaptive | No seasonality modeling |
| 9 | Anomaly types | 6 types | Maps to real SRE failure modes | 6 algorithms to implement |
| 10 | API key storage | SHA-256 hash | O(1) lookup, key entropy makes brute force infeasible | One-way: plaintext unrecoverable |
| 11 | Webhook secret storage | Fernet encryption | Must retrieve to compute HMAC | Encryption key = single point of failure |
| 12 | Key format | Prefixed (wdog_live_ / wdog_test_) | Enables automated secret scanning | Slightly shorter effective random space |
| 13 | Caching | In-process + Redis abstraction | Zero deps default, Redis-ready | Cache lost on restart |
| 14 | Database | SQLite + PostgreSQL upgrade path | Zero deps, same SQLAlchemy interface | No RLS, write concurrency limits |
| 15 | API versioning | URL path (/api/v1/) | Industry precedent, self-describing | Version baked into URLs |
| 16 | Authentication | JWT (humans) + scoped keys (machines) | Right tool per context | Two auth systems |
| 17 | Tenant isolation enforcement | TenantContext dependency injection | No raw tenant_id from request input | App-layer only (no RLS) |
| 18 | Frontend | Jinja2 + Alpine.js + Chart.js | Python-ecosystem templating, no second server, no build step | Alpine.js is JS not Python; Next.js is post-MVP upgrade path |
