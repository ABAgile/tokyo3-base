# base - application basic building blocks

[![Release](https://img.shields.io/github/v/release/abagile/tokyo3-base?sort=semver&logo=Go&color=%23007D9C)](https://github.com/abagile/tokyo3-base/releases)
[![Test](https://github.com/abagile/tokyo3-base/actions/workflows/test.yml/badge.svg)](https://github.com/abagile/tokyo3-base/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abagile/tokyo3-base.svg)](https://pkg.go.dev/github.com/abagile/tokyo3-base)
[![Go Report Card](https://goreportcard.com/badge/github.com/abagile/tokyo3-base)](https://goreportcard.com/report/github.com/abagile/tokyo3-base)
[![codecov](https://codecov.io/gh/abagile/tokyo3-base/branch/main/graph/badge.svg)](https://codecov.io/gh/abagile/tokyo3-base)

**Requires Go 1.26+**

```
go get github.com/abagile/tokyo3-base
```

---
## db/ — PostgreSQL / pgx utilities

### Pool construction

```go
func NewPgxPool(connStr string, opts ...DatabaseConfigOption) (*pgxpool.Pool, error)
```

Creates a `pgxpool.Pool` from a connection string. Options are applied to the parsed config before the pool is created.

```go
type DatabaseConfigOption func(*pgxpool.Config)
```

Functional option type for `NewPgxPool`.

### Options

```go
func WithDecimalRegister() DatabaseConfigOption
```

Registers [`govalues/decimal`](https://github.com/govalues/decimal) with the pgx type map on every new connection, enabling transparent encode/decode of `decimal.Decimal` for PostgreSQL `numeric` columns.

```go
pool, err := NewPgxPool(connStr, WithDecimalRegister())
```

### Connection string sanitization

```go
func SantizeDbConn(connStr string) string
```

Strips `user=` and `password=` key-value pairs from a DSN and collapses surrounding whitespace. Safe for logging.

```go
SantizeDbConn("host=localhost user=admin password=secret dbname=app")
// → "host=localhost dbname=app"
```

### Placeholder conversion

```go
func ConvertPgPlaceholders(sql string, args ...any) (string, []any, error)
```

Converts PostgreSQL-style positional placeholders (`$1`, `$2`, …) to `?` placeholders, reordering `args` to match. Useful when targeting drivers that use `?` syntax (e.g. MySQL, SQLite) while authoring queries in PostgreSQL style.

```go
sql, args, err := ConvertPgPlaceholders(
    "SELECT * FROM orders WHERE user_id = $1 AND status = $2",
    userID, status,
)
// sql  → "SELECT * FROM orders WHERE user_id = ? AND status = ?"
// args → []any{userID, status}
```

Returns an error if a placeholder index is out of range or malformed. Positional args may be repeated (`$1` used twice maps the same argument into both positions).

### Struct copy with dereferencing

```go
func CopyDeref[T any, U any](src T, dst *U) (*U, error)
```

Copies fields from `src` to `dst` by name, with three conversion rules applied in order:

| Source type | Destination type | Behaviour |
|---|---|---|
| `[]byte` | `string` | Converts bytes to string |
| `*T` | `T` | Dereferences pointer; zeroes dst field if nil |
| `T` | `T` | Direct assignment if types are assignable |

Fields with no matching name in `src`, unexported fields, and fields whose types don't satisfy any rule are silently skipped. `src` may itself be a pointer — it is dereferenced before field matching begins.

```go
type Row struct {
    Name  []byte
    Score *int
    Tag   string
}
type Model struct {
    Name  string
    Score int
    Tag   string
}

score := 42
row := Row{Name: []byte("alice"), Score: &score, Tag: "vip"}
model, err := CopyDeref(row, &Model{})
// model → Model{Name: "alice", Score: 42, Tag: "vip"}
```

---

## applog/ — Application logging helpers

The logging layer is **entirely `log/slog`-based at every call site**.
[`github.com/phuslu/log`](https://github.com/phuslu/log) is used internally as the
output engine for its multi-writer pipeline and low-allocation JSON output, but that
is an internal detail — application code never imports it.

### Design split

| Layer | Type | Interface |
|---|---|---|
| App logger construction | `AppLogger` | returns `*slog.Logger` + `*slog.LevelVar` |
| Writer composition | `WithStdout`, `WithAsyncNats` | `WriterOption` |
| Log-call sites | `*slog.Logger` | standard `log/slog` |
| Message annotation | `AttrsHandler` | `slog.Handler` — wraps any handler |
| Stack capture | `StackFrame` | plain `string` — no logger dependency |

### `AppLogger` — structured app logger with composable writers

```go
func AppLogger(app string, writerOpts ...WriterOption) (*slog.Logger, *slog.LevelVar)
```

Constructs a `*slog.Logger` that emits JSON. With no writer options, output goes to
stdout. Compose writers explicitly via `WriterOption`:

```go
logger, lv := AppLogger("myapp", WithStdout())                   // stdout only
logger, lv := AppLogger("myapp", WithAsyncNats(nc))              // NATS only
logger, lv := AppLogger("myapp", WithStdout(), WithAsyncNats(nc)) // both
```

The returned `*slog.LevelVar` controls the minimum log level at runtime (default:
`Info`). It is safe for concurrent use:

```go
lv.Set(slog.LevelDebug) // takes effect immediately, no restart needed
```

Add fixed context fields with standard slog:

```go
logger = logger.With("site", "tokyo", "module", "api")
```

#### Writer options

| Option | Description |
|---|---|
| `WithStdout()` | Synchronous stdout writer |
| `WithAsyncNats(nc)` | Async NATS writer; publishes to `app_log.<app>`, 200-entry buffer, discards on full |

### `AttrsHandler` / `NewAttrsLogger` — human-readable message annotation

`AttrsHandler` is a `slog.Handler` wrapper that appends structured attributes to
the log message in readable form alongside forwarding them as structured fields to
the inner handler. Wrap any `slog.Handler`:

```go
logger := NewAttrsLogger(slog.NewJSONHandler(os.Stdout, nil))
logger.With(slog.String("site", "tokyo")).
    Info("request handled", slog.Int("status", 200), slog.String("path", "/api/v1"))
// msg: "request handled |>> site: [tokyo], status: [200], path: [/api/v1]"
// structured fields: site=tokyo status=200 path=/api/v1
```

Attrs with a `_` key prefix are excluded from the message annotation but still
forwarded to the inner handler as structured fields — useful for machine-readable
metadata that would clutter human output:

```go
logger.Info("query finished",
    slog.Duration("elapsed", d),
    slog.String("_trace_id", traceID),  // in structured output only
)
```

Group prefixes (from `logger.WithGroup`) apply to structured fields only, not to
the message annotation, matching standard slog semantics.

### Why slog has no `Fatal` or `Panic` level

This is a deliberate design decision documented in the [slog proposal](https://github.com/golang/go/issues/56345).
The core argument is that `Fatal` and `Panic` are **control flow**, not log levels:

- `Fatal` calls `os.Exit` — a side effect that belongs to the application, not a logging abstraction. A library that calls `os.Exit` removes the caller's ability to clean up, flush buffers, or handle the exit itself.
- `Panic` calls `panic()` — if that's what you mean, call `panic` directly. Hiding it inside a log call obscures the control-flow intent from both the reader and the runtime.

Both also break composability: a `slog.Handler` that silently drops records (common in tests) would suppress the exit or panic — a surprising and hard-to-debug outcome.

Go already provides `os.Exit`, `log.Fatal` (stdlib), and `panic` as first-class constructs. The slog authors treated `Fatal`/`Panic` log levels as legacy baggage from older libraries that conflated "record this event" with "terminate the process", and chose not to carry that pattern into the new standard.

The idiomatic replacement is explicit and testable:

```go
logger.Error("unrecoverable state", slog.Any("err", err))
os.Exit(1)
```

### `StackFrame` — filtered stack capture

```go
func StackFrame(skip int, targetPkgs ...string) string
```

Returns a formatted stack trace as a plain string. `skip=0` starts at the direct
caller of `StackFrame`. Pass package prefixes to include only relevant frames; omit
to capture the full stack:

```go
// full stack from caller
StackFrame(0)

// only frames in your own packages
StackFrame(0, "github.com/acme/myapp", "github.com/acme/shared")

```
---
## api/ — HTTP client utilities

Thin option-driven wrapper over [go-resty/resty](https://github.com/go-resty/resty/v2) with bearer-token management, structured request logging, and context-scoped log annotation.

### Client construction

```go
func NewRestClient(baseURL string, opts ...RestyClientOption) *RestyClient
```

```go
rc := api.NewRestClient("https://api.example.com",
    api.CO.WithTimeout(10 * time.Second),
    api.CO.WithHeader("Accept", "application/json"),
    api.CO.WithRequestLogger(logger),
)
```

#### Client options (`CO`)

| Option | Description |
|---|---|
| `CO.WithBaseUrl(url)` | Overrides the base URL after construction |
| `CO.WithTimeout(d)` | Request timeout |
| `CO.WithRetryCount(n)` | Number of retries on transient errors |
| `CO.WithHeader(k, v)` | Sets a default request header |
| `CO.WithHeaders(map)` | Sets multiple default request headers |
| `CO.WithAuthToken(token)` | Sets `Authorization: Bearer <token>` on every request |
| `CO.WithBasicAuth(u, p)` | Sets `Authorization: Basic …` on every request |
| `CO.WithTransport(rt)` | Replaces the underlying `http.RoundTripper` (custom TLS, proxies, test mocks) |
| `CO.WithDebug(bool)` | Enables resty debug output |
| `CO.WithRequestLogger(logger)` | Attaches structured request/response logging (see below) |

### Request execution

```go
func (rc *RestyClient) R(ctx context.Context, method, path string, result any, opts ...RestyRequestOption) error
```

Executes a request and unmarshals the response body into `result` on success. Returns `*ApiError` on HTTP error status.

```go
var out MyResponse
err := rc.R(ctx, http.MethodGet, "/v1/orders/{id}", &out,
    api.RO.WithPathParam("id", orderID),
    api.RO.WithQueryParam("expand", "items"),
)
var apiErr *api.ApiError
if errors.As(err, &apiErr) {
    // apiErr.StatusCode holds the HTTP status
}
```

#### Request options (`RO`)

| Option | Description |
|---|---|
| `RO.WithQueryParam(k, v)` | Adds a query parameter |
| `RO.WithQueryParams(map)` | Adds multiple query parameters |
| `RO.WithPathParam(k, v)` | Substitutes a `{k}` placeholder in the path |
| `RO.WithPathParams(map)` | Substitutes multiple path placeholders |
| `RO.WithBody(v)` | Sets the request body (JSON-encoded) |
| `RO.WithHeader(k, v)` | Sets a per-request header |
| `RO.WithHeaders(map)` | Sets multiple per-request headers |
| `RO.WithAuthToken(token)` | Overrides auth token for this request only |
| `RO.WithBasicAuth(u, p)` | Overrides basic auth for this request only |
| `RO.WithDebug(bool)` | Enables resty debug for this request only |

### Bearer token management

```go
type BearerTokenManager struct { ... }
type BearerTokenRefresher func(context.Context) (string, time.Time, error)
```

Thread-safe token cache with automatic refresh. Calls `Refresher` when the token is within 5 minutes of expiry (default buffer). Override per call via context:

```go
tm := &api.BearerTokenManager{
    Refresher: func(ctx context.Context) (string, time.Time, error) {
        return fetchTokenFromIDP(ctx) // returns token, expiresAt, err
    },
}

// use default 5-min buffer
token, err := tm.GetToken(ctx)

// override buffer — refresh 10 min before expiry
ctx = api.WithTokenRefreshBuffer(ctx, -10*time.Minute)
token, err = tm.GetToken(ctx)
```

### Request logging

`CO.WithRequestLogger` attaches a `*slog.Logger` that emits one `OUTGOING_REQUEST` line before each call and one `INCOMING_RESPONSE` line after. `Authorization` and `Cookie` headers are redacted automatically.

#### Context log attributes

Arbitrary key-value pairs stored in the context are appended to both log lines — no changes to client configuration required:

```go
ctx = api.WithLogAttr(ctx, "plan_no", "P-123")
ctx = api.WithLogAttrs(ctx, map[string]string{"tref": "T-456", "tenant": "acme"})

// OUTGOING_REQUEST: GET /orders |>> plan_no: [P-123] tenant: [acme] tref: [T-456]
// INCOMING_RESPONSE: GET /orders 200 |>> plan_no: [P-123] tenant: [acme] tref: [T-456]
```

Each `WithLogAttr` / `WithLogAttrs` call produces a new context; the parent is never mutated. Keys are sorted alphabetically in the log output.

```go
func SanitizeHeaders(h map[string][]string) map[string][]string
```

Redacts `Authorization` and `Cookie` values (case-insensitive). Used internally by the logger; also available for custom middleware.

---
## api/google — Google Maps / Places client

Typed client for the [Geocoding API](https://developers.google.com/maps/documentation/geocoding) and [Places Text Search API](https://developers.google.com/maps/documentation/places/web-service/text-search).

### Address lookup

```go
svc := google.NewGeocodeService(apiKey, api.CO.WithTimeout(5*time.Second))
// or
svc := google.NewPlacesService(apiKey, api.CO.WithTimeout(5*time.Second))

results, err := svc.GetResults(ctx, "Shinjuku, Tokyo")
// results[0].Address → "1 Chome Shinjuku, Shinjuku City, Tokyo 160-0022, Japan"
// results[0].City    → "Shinjuku"
```

Both constructors return `google.Addresser`, making the backend interchangeable and easy to mock in tests:

```go
type Addresser interface {
    GetResults(ctx context.Context, address string) ([]AddressResult, error)
}
```

City is extracted by priority: `locality` is preferred over `administrative_area_level_1`. `AddressComponent.Name()` transparently unifies the field-name difference between the two APIs (`long_name` in Geocoding, `longText` in Places).

---

## crypto/ — AES-256-GCM and envelope encryption

A subpackage covering symmetric encryption primitives plus an
envelope-encryption pattern layered on a `KeyProvider` interface, so the
master key can live wherever the deployment requires (in process, sealed
file, behind a KMS).

```go
import bcrypto "github.com/abagile/tokyo3-base/crypto"
```

Aliasing avoids the stdlib `crypto` collision — pick any name you prefer.

### Direct AEAD primitives

```go
func Seal(key, plaintext  []byte) ([]byte, error)
func Open(key, ciphertext []byte) ([]byte, error)
```

`Seal` encrypts under a 16/24/32-byte AES key using AES-GCM with a fresh
96-bit random nonce and returns `nonce || ciphertext+tag`. `Open` is the
inverse. Reach for these when you already have a key and just need to
seal/unseal short blobs (cookies, session tokens, signed-but-encrypted
payloads).

> **Nonce-reuse limit**: with random 96-bit nonces a single key is
> collision-safe up to ~2³² messages (NIST SP 800-38D). Rotate keys
> before exceeding that, or switch to a deterministic counter nonce.

### Random material and key encoding

```go
func RandomBytes(n int)               ([]byte, error)
func GenerateKEK()                    (string, error)   // 32-byte AES-256 key, hex-encoded
func ParseKEK(hexKey string)          ([]byte, error)   // inverse of GenerateKEK
```

`RandomBytes` is the single source of cryptographically random bytes used
internally for keys, DEKs, and nonces. `GenerateKEK` / `ParseKEK` cover
the common "32-byte AES key as a 64-char hex string" exchange format used
by env vars and config files; despite the KEK naming, the bytes are just
an AES-256 key suitable for any role.

### KeyProvider and envelope encryption

For collections of secrets — or any time you want to rotate the master
key without re-encrypting every value — use envelope encryption: each
value is encrypted under its own random Data Encryption Key (DEK), and
the DEK is wrapped under a longer-lived master key via a `KeyProvider`.
Rotating the master only requires re-wrapping DEKs; the underlying
ciphertexts stay valid.

```go
type KeyProvider interface {
    Wrap  (ctx context.Context, dek         []byte) ([]byte, error)
    Unwrap(ctx context.Context, wrappedDEK  []byte) ([]byte, error)
}

func NewLocalKeyProvider(masterKey []byte) *LocalKeyProvider

func EncryptEnvelope(ctx context.Context, kp KeyProvider, plaintext []byte) (encryptedValue, wrappedDEK []byte, err error)
func DecryptEnvelope(ctx context.Context, kp KeyProvider, wrappedDEK, encryptedValue []byte) ([]byte, error)
func Rewrap        (ctx context.Context, oldKP, newKP KeyProvider, wrappedDEK []byte) ([]byte, error)
```

`LocalKeyProvider` wraps DEKs with an in-memory AES-256 master key —
suitable for development and single-server deployments. For production,
implement `KeyProvider` against AWS KMS, GCP KMS, HashiCorp Vault Transit,
or any HSM-backed service; the rest of the API is unchanged.

```go
hex, _ := bcrypto.GenerateKEK()
key, _ := bcrypto.ParseKEK(hex)
kp     := bcrypto.NewLocalKeyProvider(key)

ct, wrappedDEK, _ := bcrypto.EncryptEnvelope(ctx, kp, []byte("postgres://…"))
pt,             _ := bcrypto.DecryptEnvelope(ctx, kp, wrappedDEK, ct)
```

Rotating the master key without re-encrypting any values:

```go
newKP := bcrypto.NewLocalKeyProvider(newKey)
newWrapped, _ := bcrypto.Rewrap(ctx, kp, newKP, wrappedDEK)
// persist newWrapped alongside ct; ct stays as-is.
```

### KeyProviderCache — per-id intermediate-key cache

```go
type KeyProviderCache struct { /* ... */ }

func NewKeyProviderCache(master KeyProvider, ttl time.Duration) *KeyProviderCache
func (c *KeyProviderCache) ForKey(ctx context.Context, keyID string, wrappedKey []byte) (KeyProvider, error)
func (c *KeyProviderCache) Invalidate(keyID string)
```

For deployments with a tree of envelope keys — the master wraps N
intermediate keys, each of which wraps many DEKs — `KeyProviderCache`
unwraps each intermediate at most once per `ttl` and hands the resulting
KeyProvider out for subsequent operations. Concurrent cold misses for
the same `keyID` are coalesced into one `master.Unwrap` via
`golang.org/x/sync/singleflight`, so a thundering herd at startup or
post-TTL costs one master call, not N. Pass `nil` as `wrappedKey` to get
the master back directly — handy for callers that mix migrated and
unmigrated rows.

```go
cache := bcrypto.NewKeyProviderCache(masterKP, 5*time.Minute)

// On every secret operation: cheap cache hit after the first call per key.
kp, err := cache.ForKey(ctx, projectID, wrappedProjectKey)
if err != nil { /* ... */ }
ct, wrappedDEK, _ := bcrypto.EncryptEnvelope(ctx, kp, plaintext)

// After rotating the underlying key:
cache.Invalidate(projectID)
```

---

## nats/ — NATS dial helper

A one-line wrapper around the boilerplate every NATS-connecting binary
spells out by hand: load optional mTLS material via `tls.FromFiles`,
attach `nats.Secure` when the TLS config is non-nil, then `nats.Connect`.

```go
import (
    "github.com/abagile/tokyo3-base/nats"
    "github.com/nats-io/nats.go"
)

func Dial(url, certFile, keyFile, caFile string, opts ...nats.Option) (*nats.Conn, error)
```

`certFile`/`keyFile`/`caFile` are forwarded to `tls.FromFiles` — pass
all three (or all empty) together; empty paths produce a plaintext
connection (development only).

The variadic `opts ...nats.Option` lets callers tune timeouts, drain
behaviour, retry policy, reconnect handlers, etc. without bloating the
signature. They're applied **after** the implicit `nats.Secure` so the
caller's TLS opinion (if any) wins for everything other than the cert
material itself.

```go
nc, err := nats.Dial(
    os.Getenv("VAULT_NATS_URL"),
    os.Getenv("VAULT_NATS_CERT"),
    os.Getenv("VAULT_NATS_KEY"),
    os.Getenv("VAULT_NATS_CA"),
    nats.Timeout(1*time.Second),         // fail fast if the broker is unreachable
    nats.DrainTimeout(500*time.Millisecond), // bound shutdown drain
)
```

Pairs with `journal/jetstream` (which dials internally via the same
shape) and with `WithAsyncNats` from `log.go` (which takes an
externally-owned `*nats.Conn`).

---

## tls/ — TLS config and self-signed cert helpers

Helpers for the boring parts of running a TLS server or client without
inventing your own PKI: hot-reload a cert/key pair on rotation, build
`*tls.Config` from PEM files or strings, and ship a self-signed dev
fallback that covers `localhost`, `*.localhost`, and loopback IPs.

```go
import "github.com/abagile/tokyo3-base/tls"
```

### CertLoader — hot-reload cert/key on disk change

```go
type CertLoader struct { /* ... */ }

func NewCertLoader(certFile, keyFile string) *CertLoader
func (c *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error)
```

`GetCertificate` is shaped to slot directly into `tls.Config.GetCertificate`.
On every handshake the loader stat-checks the cert file; if the mtime has
advanced since the last load it reloads the pair and serves the new cert
from then on. Concurrent stale callers are coalesced through a
double-checked write lock. When a reload fails (e.g. cert written, key
not yet during a rotation) the previously cached cert is returned so
in-flight handshakes are unaffected.

```go
loader := tls.NewCertLoader("/etc/tls/server.crt", "/etc/tls/server.key")
srv := &http.Server{
    Addr:      ":443",
    TLSConfig: &tls.Config{GetCertificate: loader.GetCertificate},
}
srv.ListenAndServeTLS("", "")  // empty paths — cert comes from GetCertificate
```

Pairs naturally with cert-manager, ACME tooling, SPIFFE/SPIRE in disk
mode, or any rotation tool that overwrites the cert/key files in place.

### SelfSignedCert — ephemeral dev fallback

```go
func SelfSignedCert() (tls.Certificate, error)
```

Generates an ECDSA P-256 self-signed cert valid for one year. SANs cover
`localhost`, `*.localhost` (single-label subdomains like `api.localhost`),
`127.0.0.1`, and `::1`. Use as the TLS fallback when no cert/key files
are configured — clients need `--insecure` (curl) or trust-store import
(browsers), but `https://localhost` and `https://anything.localhost`
resolve cleanly.

### Building `*tls.Config`

```go
func CertPoolFromPEM(pemData []byte)                 (*x509.CertPool, error)
func FromFiles      (certFile, keyFile, caFile string) (*tls.Config,  error)
func FromPEM        (certPEM,  keyPEM,  caPEM  string) (*tls.Config,  error)
```

`FromFiles` and `FromPEM` are symmetrical: one takes paths, the other
takes already-loaded PEM strings. Both return `(nil, nil)` when given no
inputs, so call sites can switch transparently between TLS and plaintext.
`certFile` / `keyFile` (or `certPEM` / `keyPEM`) must be set together; the
CA input is optional and populates `RootCAs` when provided.

```go
// mTLS client config from disk
cfg, err := tls.FromFiles(
    "/etc/tls/client.crt",
    "/etc/tls/client.key",
    "/etc/tls/ca.crt",
)
if err != nil { /* ... */ }
http.DefaultClient.Transport = &http.Transport{TLSClientConfig: cfg}
```

`CertPoolFromPEM` is the lower-level building block when you already have
PEM bytes and just want a `*x509.CertPool` for `RootCAs` / `ClientCAs`.

---

## journal/ — Append-only durable event sink

A write-only, append-only, ordered, **fail-closed** publish primitive — the
shape that fits audit trails, event-sourcing stores, financial ledgers,
change-data-capture, and anywhere "this event happened, never lose it"
matters.

```go
import (
    "github.com/abagile/tokyo3-base/journal"
    "github.com/abagile/tokyo3-base/journal/jetstream"
)
```

### Reliability contract

`Sink.Append` publishes synchronously and returns the publish error to the
caller. Implementations must not silently drop or swallow failures —
callers rely on `Append`'s error to decide whether the originating
operation may be considered complete. This is the property that makes a
journal usable as compliance evidence or as the source of truth for an
event-sourced system.

> **Don't reach for a journal to implement application logs**. Operational
> logs are a different reliability tier (lossy, fire-and-forget,
> backpressure-tolerant). Use `applog.AppLogger` with `WithAsyncNats` for
> that. Mixing the two contracts under one interface erodes both.

### Interface

```go
type Sink interface {
    Append(ctx context.Context, payload []byte) error
    Close() error
}

type Noop struct{} // discards every payload; for tests / disabled-in-dev
```

The interface is byte-oriented; callers marshal their own payload format
(JSON, protobuf, length-prefixed binary, …). Implementations live in
sub-packages so each transport's SDK weight is opt-in.

### Typed events with `EncodedSink[T]`

```go
type EncodedSink[T any] struct { /* ... */ }

func NewEncodedSink[T any](inner Sink, encode func(T) ([]byte, error)) *EncodedSink[T]
func NewJSONSink   [T any](inner Sink) *EncodedSink[T]   // convenience: encode = json.Marshal
```

Most consumers have a typed event struct (audit entry, domain event, CDC
record, ledger transaction) and a wire format. `EncodedSink[T]` wraps a
byte-level `Sink` with a typed `Append(ctx, v T) error` that runs the
configured encoder before publishing — saving every consumer from
re-implementing the same marshal-then-Append shim.

```go
type AuditEntry struct {
    ID, Action, ActorID string
    OccurredAt          time.Time
}

inner, _ := jetstream.New(jetstream.Config{URL: "...", Subject: "..."})
sink := journal.NewJSONSink[AuditEntry](inner)

// Per write:
err := sink.Append(ctx, AuditEntry{ID: "e-1", Action: "secret.set", /* ... */})
```

For non-JSON formats, supply your own encoder:

```go
sink := journal.NewEncodedSink(inner, func(e AuditEntry) ([]byte, error) {
    return proto.Marshal(toProto(e))
})
```

Encode failures surface as the return of `Append` and the inner Sink is
not called; inner publish failures surface verbatim — the fail-closed
contract is preserved end-to-end.

### `journal/jetstream` — NATS JetStream implementation

```go
cfg := jetstream.Config{
    URL:     "tls://nats:4222",
    Subject: "vault.audit.events",     // must be covered by an existing JetStream stream
    TLS:     tlsCfg,                   // optional; nil for plaintext (dev only)
}
sink, err := jetstream.New(cfg)
if err != nil { /* ... */ }
defer sink.Close()

// Per write:
payload, _ := json.Marshal(event)
if err := sink.Append(ctx, payload); err != nil {
    // fail the originating operation — the event is NOT in the journal
    return fmt.Errorf("append: %w", err)
}
```

`Append` blocks on the JetStream server-ack, so the caller observes any
publish error before returning. The publisher's NATS credential needs only
PUBLISH on the configured subject — no stream-management rights, since the
package does not provision streams. Provision streams out-of-band (a
sidecar container running `nats stream add`, an operator-managed stream, or
a one-shot init job).

