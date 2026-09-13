# RemoteSignLab audit log

## Architecture

Security events are stored in `security_audit_events` and written by
`app.services.audit_service.write_audit_event`. Routes never calculate chain
hashes themselves.

Two write modes are available:

- `add_audit_event` adds the event to the business transaction. It is
  therefore committed or rolled back with the operation it describes.
- `record_audit_event` opens an independent transaction to preserve a denial
  or failure after the business transaction is rolled back. An audit-log
  failure is logged on the server but never masks the primary error returned
  to the client.

Events created before migration `a84f2c1d9e70` are preserved without
modification. They remain readable, with `previous_hash` and `event_hash`
set to `NULL`.

## Event schema

An event can describe:

- when: `created_at`;
- who: `actor_type`, `actor_id`, `user_id`, `device_id`;
- what: `category`, `event_type`;
- target object: `document_id`, `signature_request_id`, `signature_id`,
  `session_id`;
- outcome: `outcome`;
- reason: `failure_code`, `detail`, `details`;
- HTTP context: `http_method`, `http_path`, `http_status`, `source_ip`,
  `user_agent`;
- correlation: `correlation_id`;
- chain proof: `previous_hash`, `event_hash`.

Context fields are optional. Allowed actor types are `USER`, `ADMIN`,
`DEVICE`, and `SYSTEM`. Normalized outcomes are `SUCCESS`, `FAILURE`,
and `DENIED`. `actor_type` identifies the nature of the actor;
`user_id` remains the affected business user and does not turn a DEVICE
event into a USER event.

Correlation prioritizes business identifiers. When the document is known and
no explicit correlation identifier is supplied, `document_id` is used as
`correlation_id`. This value is generated or selected on the server and
never participates in an authorization decision.

## Taxonomy

Categories: `AUTH`, `DOCUMENT`, `CONSENT`, `SIGNATURE_REQUEST`,
`DEVICE_AUTH`, `SIGNATURE`, `PADES`, `TSA`, `ADMIN`, `SECURITY`.

Workflow events currently produced:

- account: `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`, `USER_LOGOUT`,
  `ADMIN_LOGIN_SUCCESS`, `ADMIN_LOGIN_FAILED`, `ADMIN_LOGOUT`;
- document and consent: `DOCUMENT_UPLOADED`, `DOCUMENT_ASSIGNED`,
  `DOCUMENT_VIEWED`, `CONSENT_RECORDED`,
  `SIGNED_DOCUMENT_DOWNLOADED`;
- request: `SIGNATURE_REQUEST_CREATED`, `SIGNATURE_REQUEST_CLAIMED`,
  `SIGNATURE_REQUEST_FAILED`, `SIGNATURE_REQUEST_EXPIRED`;
- device: `DEVICE_CHALLENGE_CREATED`, `DEVICE_CHALLENGE_REJECTED`,
  `DEVICE_AUTH_SUCCESS`, `DEVICE_AUTH_FAILED`, `HMAC_REJECTED`,
  `NONCE_REPLAY_REJECTED`, `RATE_LIMIT_BLOCKED`;
- signature: `SIGNATURE_STARTED`, `SIGNATURE_SUCCESS`,
  `SIGNATURE_FAILED`;
- PDF and timestamp: `PADES_CREATED`, `PADES_VALIDATION_SUCCESS`,
  `PADES_VALIDATION_FAILED`, `TSA_TIMESTAMP_SUCCESS`,
  `TSA_TIMESTAMP_FAILED`;
- verification: `SIGNATURE_VERIFY_REQUESTED`,
  `SIGNATURE_VERIFY_SUCCESS`, `SIGNATURE_VERIFY_FAILED`.

Empty `/next` polls intentionally do not produce an event every three
seconds: rejected authentication and actual claims are audited without
turning the audit log into a redundant network trace.

`failure_code` values are short uppercase technical identifiers made of
`A-Z`, `0-9`, and `_` (3 to 64 characters), for example
`INVALID_HMAC`, `NONCE_REPLAY`, `RFID_MISMATCH`,
`FINGERPRINT_MISMATCH`, `CONSENT_MISSING`, `CONSENT_MISMATCH`,
`DOCUMENT_HASH_MISMATCH`, `REQUEST_STATE_INVALID`, `DEVICE_MISMATCH`,
`TSA_UNAVAILABLE`, `TSA_VALIDATION_FAILED`, `PADES_CREATION_FAILED`,
`PADES_VALIDATION_FAILED`, or `SIGNED_DOCUMENT_MISSING`.

## Sanitization

`details` is sanitized recursively before storage and again before
read/export. Depth, item count, and string length are bounded. A denylist
removes passwords, password hashes, DEVICE/HMAC/ADMIN secrets, SoftHSM PINs,
private keys, session tokens, cookies, Authorization headers, CSRF tokens,
and TSA/CA private keys. The historical `detail` field also masks
recognizable sensitive assignments and Bearer tokens.

The IP address comes from the client socket exposed by FastAPI. The service
does not trust `X-Forwarded-For` without explicit trusted-proxy
configuration.

## Integrity chain

Each new event starts with `previous_hash` equal to 64 zeroes when no sealed
event precedes it, or with the preceding `event_hash` otherwise.
`event_hash` is the SHA-256 digest of the UTF-8 bytes of a canonical JSON
object.

The covered fields are exactly:

`id`, `category`, `event_type`, `actor_type`, `actor_id`, `user_id`,
`device_id`, `session_id`, `document_id`, `signature_request_id`,
`signature_id`, `outcome`, `failure_code`, `correlation_id`,
`http_method`, `http_path`, `http_status`, `source_ip`, `user_agent`,
`detail`, `details`, `created_at`, `previous_hash`.

Canonicalization uses:

- sorted JSON keys;
- `,` and `:` separators without spaces;
- UTF-8 without forced escaping of Unicode characters;
- UUIDs in canonical string form;
- dates converted to UTC as `YYYY-MM-DDTHH:MM:SS.ffffffZ`;
- native JSON nulls, booleans, and integers;
- no Python `repr()` and no final newline.

`event_hash` itself is excluded from the content being hashed. Verification
uses `hmac.compare_digest`.

On PostgreSQL, `pg_advisory_xact_lock(6004502579051058500)` serializes only
appends to the end of the chain until the transaction ends. The value
corresponds to the hexadecimal mnemonic `STGHMAUD` and is reserved for this
purpose. The lock prevents two concurrent writes from reusing the same
`previous_hash`. A process lock is used only as a fallback for SQLite tests;
PostgreSQL remains the production mechanism.

`GET /ui/api/audit/integrity` reads the database without modifying it and
distinguishes:

- `historical_unsealed_events`: unsealed historical events;
- `chained_events`: events belonging to the chain;
- `events_checked`: events recalculated before the first error;
- `first_invalid_event_id`: first invalid link.

Hash chaining provides tamper evidence, not absolute immutability. An
administrator able to rewrite the entire database and recalculate the full
chain can defeat it. A stronger guarantee would require periodic external
anchoring or WORM storage.

## ADMIN API and interface

These routes require the interface ADMIN session and provide no write
operation:

- `GET /ui/api/audit`: paginated list sorted by
  `created_at DESC, id DESC`, with `limit` from 1 to 200;
- `GET /ui/api/audit/{event_id}`: sanitized details;
- `GET /ui/api/audit/integrity`: chain verification;
- `GET /ui/api/audit/export.csv`: filtered export, up to 5,000 rows.

Common filters: `from`, `to`, `category`, `event_type`, `actor_type`,
`user_id`, `device_id`, `document_id`, `signature_request_id`,
`signature_id`, `outcome`, `failure_code`, `correlation_id`, plus
`limit` and `offset`.

The export neutralizes text cells beginning with `=`, `+`, `-`, `*`,
or `@` by prefixing an apostrophe to reduce spreadsheet formula-injection
risk.

Existing indexes on date, event type, user/device/document/signature IDs, and
outcome are retained. The migration adds indexes for the most important new
filters: category, actor type, signature request, and correlation. Fields
with low selectivity or used mainly for detail views are not indexed
mechanically.

## Operational limitations

- Old events remain readable but are explicitly unsealed.
- The migration performs no invented cryptographic backfill.
- A success event attached to the business transaction disappears if that
  transaction is rolled back; a denial or failure uses the independent write.
- Simultaneous PostgreSQL unavailability may prevent a failure from being
  preserved; the business error remains primary and a server error is then
  emitted in application logs.
- Retention policy, external anchoring, and export to SIEM/WORM remain possible
  future hardening measures.
