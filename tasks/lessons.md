# tasks/lessons.md — Error Patterns & Prevention Rules

Auto-maintained by Claude. Updated after every correction. Read at session start.

---

## Lesson 4
**Mistake:** `_bootstrap_platform_admin()` and `middleware._persist_request_log()` called `database.SessionLocal()` directly. In tests, `SessionLocal` is bound to the production `sqlite:///:memory:` (no schema). Both functions silently used the wrong DB.

**Root cause:** Any code that creates sessions outside of the FastAPI `get_db` dependency cannot benefit from the test fixture's `dependency_overrides[get_db]`. Direct `SessionLocal()` calls bypass the override entirely.

**Rule:** Internal functions that need a DB session (middleware, lifespan bootstrap) must accept an optional `session_factory` parameter and be passed the test factory via a module-level override (e.g. `middleware._request_log_session_factory`). Never assume `SessionLocal` points to the active test DB.

---

## Lesson 5
**Mistake:** `if user is None or not verify_password(...)` short-circuits the bcrypt call when the email is unknown. This makes the response ~300ms faster for unknown emails than wrong passwords, leaking user existence via timing.

**Root cause:** Python's short-circuit evaluation on `or` skips `verify_password` when the left operand is True.

**Rule:** In authentication flows, always run the password hash comparison — even for unknown users. Use a pre-computed dummy hash: `candidate = user.password_hash if user else _DUMMY_HASH; verify_password(plain, candidate)`. Then check `if not result or user is None: raise 401`.

---

## Lesson 2
**Mistake:** `create_refresh_token` had no `jti` claim. Two calls within the same second produced identical JWT payloads → identical SHA-256 hashes → UNIQUE constraint failure on `refresh_tokens.token_hash`.

**Root cause:** JWT payload uniqueness depends on time-varying fields. `iat`/`exp` have second-level precision in PyJWT; two calls in the same second produce the same bytes.

**Rule:** Always include `jti: str(uuid.uuid4())` in every JWT — access and refresh — to guarantee structural uniqueness regardless of call timing.

---

## Lesson 3
**Mistake:** Test fixture stored SQLAlchemy ORM objects (`user_op_a`, etc.) in a module-scoped dict. After a session error in one test, SQLAlchemy marked all objects as expired. Subsequent tests that accessed `user.role` triggered lazy-loads on a broken session, cascading failures across all remaining tests in the module.

**Root cause:** Default `expire_on_commit=True` means every committed ORM object's attributes are invalidated until the next DB refresh. A broken session makes that refresh impossible.

**Rule:** Module-scoped test sessions that supply ORM data to multiple tests must use `expire_on_commit=False` so attributes remain accessible without a live DB round-trip after commit.

---

## Lesson 6
**Mistake:** `FileConnector` opened files in text mode (`"r"`) and tracked byte offset as `len(chunk.encode("utf-8"))`. On Windows, Python text mode translates `\r\n` → `\n` during reads, so the stored byte count is smaller than the true on-disk byte position by one byte per line. Seeking to that offset on a second connector instance landed mid-JSON-line.

**Root cause:** Text-mode `seek(N)` on Python/Windows is only reliable for values from `tell()`. Arbitrary byte integers diverge from the true position due to `\r\n` translation.

**Rule:** Always open files in BINARY mode (`"rb"`) when tracking byte-level seek positions. Decode the bytes after reading. `splitlines()` handles `\r\n` correctly, so format parsing is unaffected.

---

## Lesson 7
**Mistake:** `asyncio.gather(bad_loop, good_loop)` with `asyncio.sleep` patched as `AsyncMock` caused the bad loop to run in a tight, non-yielding loop. `AsyncMock` coroutines complete synchronously without suspending the event loop, so the good loop never got scheduled, and the test hung.

**Root cause:** In CPython asyncio, a task switch only happens at `await` points that actually suspend (real I/O, `asyncio.sleep(>0)`). `AsyncMock` returns immediately without suspension.

**Rule:** Never use `asyncio.gather` to run two loops that both rely on mocked-instant sleep. Drive state-machine isolation tests sequentially on separate objects. Sequential execution with independent state objects proves isolation by construction, and never hangs.

---

## Lesson 8
**Mistake:** `_check_error_rate_spike` and `_check_latency_spike` compared the current observation against the EWMA upper bound using the POST-update `state.ewma_value` and `state.ewma_variance` (after `_update_ewma()` had already absorbed the spike into the state).

**Root cause:** `_update_ewma()` modifies `state` in-place. `ingest()` called `_update_ewma()` first, then passed `state` to the check functions, which read the already-mutated `ewma_value` and `ewma_variance`. This is mathematically proven to make spike detection permanently impossible: after absorbing a spike of deviation `d` with `var_prev=0`, the condition `(1−α)×d > K×sqrt(α)×d` reduces to `0.7 > 1.37` — always false. Stage A review approved the update formula but did not verify which snapshot the check function reads.

**Rule:** Always capture pre-update baseline values BEFORE any in-place state mutation. Anomaly detection compares the current observation against `EWMA_{t-1}` (the established baseline), never against `EWMA_t` which has already absorbed the observation. Pattern:
```python
prev_ewma = state.ewma_value          # snapshot BEFORE mutation
prev_var  = state.ewma_variance
self._update_ewma(state, observed)    # mutates state
self._check_spike(observed, prev_ewma, prev_var)   # uses snapshot
```

---

## Decision: CASCADE deduplication uses first alert_id per service from unordered query result
**Decision:** The CASCADE detector deduplicates recent ERROR_RATE_SPIKE rows by `service_name`, keeping the first `alert_id` encountered from the unordered query result.

**Behavior:** SQLite returns rows in insertion order (effectively chronological), so in practice the earliest spike per service is selected. However, this is not guaranteed by the SQL standard. On PostgreSQL, add `ORDER BY detected_at ASC` to the contributing-spikes query to make "earliest spike per service" explicit and portable.

**Risk:** Low for MVP — SQLite insertion-order behaviour is consistent in practice. Document as a PostgreSQL migration note: when switching engines, add the ORDER BY clause to `_check_cascade` to preserve deterministic alert_id selection.

**How to apply:** Any future query that relies on "first row per group" semantics must use an explicit ORDER BY when targeting PostgreSQL. Never rely on implicit row ordering for correctness.

---

## Decision: cache key format ewma:{tenant_id}:{source_id}
**Decision:** EWMA state cache keys use the format `ewma:{tenant_id}:{source_id}`, with tenant_id as the first segment after the prefix.

**Reason:** A source_id value containing ":" (e.g., a crafted UUID-like string) could otherwise produce a key that collides with another tenant's key under a naive `ewma:{source_id}` scheme. Placing tenant_id first makes it structurally impossible: any prefix match on `ewma:{tenant_id}:` is already scoped to one tenant, so appending an arbitrary source_id cannot cross that boundary.

**How to apply:** Every cache key that includes both a tenant_id and a sub-entity identifier must put tenant_id first. This is belt-and-suspenders alongside the DB WHERE tenant_id filter — if either layer is bypassed, the other still prevents cross-tenant data leakage.

---

## Decision: encode-back byte offset vs fh.tell() in FileConnector
**Decision:** Use `len(chunk.encode("utf-8", errors="replace"))` to advance `_byte_offset` rather than `self._fh.tell()`.

**Reason:** `tell()` on a text-mode file in Python returns an opaque platform cookie, not a true byte offset. The cookie is only valid for `seek()` calls on the same open file handle. After rotation, a new file handle is opened — the old cookie is meaningless and cannot be used to seek into the new descriptor. encode-back gives a true byte count usable on any new handle opened at any point.

**Edge case:** If a line contains multi-byte UTF-8 characters and the codec partially decoded them across a read boundary, encode-back could drift from the true on-disk byte position. This cannot occur here because `read()` with no argument always reads from the current position to EOF — there are no partial-read boundaries mid-character.

---

## Lesson 1
**Mistake:** `migrations/env.py` called `alembic_config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)` unconditionally, clobbering the test URL that conftest.py had already set via `cfg.set_main_option("sqlalchemy.url", test_db_url)` before calling `alembic.command.upgrade()`.

**Root cause:** Alembic's env.py runs inside the upgrade call, after the caller has set the URL. Overriding it with `settings.DATABASE_URL` (which was `sqlite:///:memory:` in the test environment) caused all migrations to run in-memory — tables disappeared instantly, and the file-based test engine saw an empty schema.

**Rule:** In `migrations/env.py`, only override the Alembic URL from app settings if the URL is still the alembic.ini default value. If the caller has already set a custom URL (e.g., a test database path), never overwrite it.
