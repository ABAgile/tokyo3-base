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
## db.go — PostgreSQL / pgx utilities

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

## log.go — Logging helpers

The logging layer is designed to be **implementation-agnostic at the call site**: all
application code works against the standard `log/slog` interface.
[`github.com/phuslu/log`](https://github.com/phuslu/log) is used as the underlying
engine specifically for its flexible multi-writer pipeline and low-allocation
structured output, but that choice is an internal detail — swapping it out would
require no changes to application code.

### Design split

| Layer | Type | Interface |
|---|---|---|
| App logger construction | `AppLogger`, `LoggerWithContext` | phuslu `log.Logger` — used at startup only |
| Log-call sites | `NewAttrsLogger` → `*slog.Logger` | standard `log/slog` |
| Message annotation | `AttrsHandler` | `slog.Handler` — wraps any handler |
| Stack capture | `StackFrame` | plain `string` — no logger dependency |

### `AppLogger` — structured app logger with optional NATS fanout

```go
func AppLogger(app string, nc *nats.Conn, opts ...AppLoggerOption) log.Logger
```

Constructs a phuslu logger that writes JSON to stdout. When `nc` is non-nil a
second writer fans out asynchronously to the NATS subject `app_log.<app>` (buffered
at 200 entries, discards on full). Pass `nil` for a stdout-only logger.

```go
logger := AppLogger("myapp", nc,
    WithSite("tokyo"),
    WithModule("api"),
    WithLevel(slog.LevelDebug),
)
```

#### Options

| Option | Description |
|---|---|
| `WithSite(site string)` | Adds `site` field to every log entry |
| `WithModule(module string)` | Adds `module` field to every log entry |
| `WithLevel(level)` | Sets minimum log level; accepts both `slog.Level` and `log.Level` — defaults to `InfoLevel` |

`WithLevel` accepts either scheme transparently:

```go
WithLevel(slog.LevelWarn)   // slog constant — no phuslu import needed
WithLevel(log.DebugLevel)   // phuslu constant — full range including Trace/Fatal/Panic
```

slog has no `Fatal` or `Panic` levels by design (see below); those remain
accessible via the phuslu constant directly when genuinely needed.

### `LoggerWithContext` — derive a child logger with additional context fields

```go
func LoggerWithContext(l *log.Logger, opts ...AppLoggerOption) *log.Logger
```

Returns a new logger that shares the parent's writer and level but carries
additional context fields. Uses the same `AppLoggerOption` set as `AppLogger`:

```go
requestLogger := LoggerWithContext(&logger, WithModule("payment"))
```

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

`Fatal` and `Panic` levels remain available through phuslu's `log.FatalLevel` and
`log.PanicLevel` via `WithLevel` for cases where drop-in compatibility with existing
infrastructure requires them.

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

