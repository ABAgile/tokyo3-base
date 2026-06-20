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

## Packages

- [api/ — HTTP client utilities](#api--http-client-utilities)
  - [api/google — Google Maps / Places client](#apigoogle--google-maps--places-client)
- [applog/ — Application logging helpers](#applog--application-logging-helpers)
- [auth/ — auth primitives namespace](#auth--auth-primitives-namespace)
- [cli/ — daemon startup composition](#cli--daemon-startup-composition)
- [clientip/ — spoof-resistant client IP extraction](#clientip--spoof-resistant-client-ip-extraction)
- [crypto/ — AES-256-GCM and envelope encryption](#crypto--aes-256-gcm-and-envelope-encryption)
- [db/ — PostgreSQL / pgx utilities](#db--postgresql--pgx-utilities)
- [debug/ — opt-in diagnostics server](#debug--opt-in-diagnostics-server)
- [envutil/ — cmd/ main.go boilerplate helpers](#envutil--cmd-maingo-boilerplate-helpers)
- [guard/ — panic recovery for background work](#guard--panic-recovery-for-background-work)
- [httpauth/ — HTTP auth middleware](#httpauth--http-auth-middleware)
- [journal/ — Append-only durable event journal](#journal--append-only-durable-event-journal)
- [nats/ — NATS dial helper](#nats--nats-dial-helper)
- [oidc/ — OIDC ID-token verification](#oidc--oidc-id-token-verification)
- [ratelimit/ — per-source-IP HTTP rate limiter](#ratelimit--per-source-ip-http-rate-limiter)
- [run/ — component lifecycle coordination](#run--component-lifecycle-coordination)
- [tls/ — stateless TLS helpers](#tls--stateless-tls-helpers)
  - [tls/reloader — hot-reload loaders + multi-pool orchestrator](#tlsreloader--hot-reload-loaders--multi-pool-orchestrator)
- [version/ — build version resolution](#version--build-version-resolution)

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

Executes a request and unmarshals the response body into `result` on success. Returns `*ApiError` on HTTP error status; the response body is decoded with `encoding/json` directly (no Content-Type heuristics) so test mocks that omit `Content-Type: application/json` work unchanged.

```go
var out MyResponse
err := rc.R(ctx, http.MethodGet, "/v1/orders/{id}", &out,
    api.RO.WithPathParam("id", orderID),
    api.RO.WithQueryParam("expand", "items"),
)
var apiErr *api.ApiError
if errors.As(err, &apiErr) {
    // apiErr.StatusCode holds the HTTP status;
    // apiErr.Body holds the raw response body verbatim (capped at 64 KiB).
}
```

#### `ApiError` shape

```go
type ApiError struct {
    StatusCode int
    Body       []byte
}
```

`Error()` surfaces the body inline (truncated at 512 chars; full bytes
available via the field) so server-side error messages reach operator logs
without a second roundtrip:

```
api error: status 403: {"error":"policy denied for groups [eng]"}
```

JSON-decode failures on success-path responses surface as
`"api call failed: decode response: <err>"` so callers can distinguish them
from transport errors.

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

### api/google — Google Maps / Places client

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

[↑ Back to top](#packages)

---

## applog/ — Application logging helpers

The logging layer is **entirely `log/slog`-based at every call site**.
[`github.com/phuslu/log`](https://github.com/phuslu/log) is used internally as the
output engine for its multi-writer pipeline and low-allocation JSON output, but that
is an internal detail — application code never imports it.

### Design split

| Layer | Type | Interface |
|---|---|---|
| App logger construction | `AppLogger`, `AppLoggerWithNATS` | returns `*slog.Logger` + `*slog.LevelVar` (+ drain for NATS) |
| Writer composition | `WithStdout`, `WithAsyncNats` | `WriterOption` |
| Log-call sites | `*slog.Logger` | standard `log/slog` |
| Message annotation | `AttrsHandler` | `slog.Handler` — wraps any handler |
| Stack capture | `StackFrame` | plain `string` — no logger dependency |

### `AppLogger` — structured app logger with composable writers

```go
type Config struct {
    App      string   // required; "app" attr + NATS subject prefix
    Instance string   // optional; per-host suffix + "instance" attr
}

func AppLogger(cfg Config, writerOpts ...WriterOption) (*slog.Logger, *slog.LevelVar)
```

Constructs a `*slog.Logger` that emits JSON. With no writer options, output goes
to stdout. Compose writers explicitly via `WriterOption`:

```go
logger, lv := AppLogger(Config{App: "myapp"}, WithStdout())                   // stdout only
logger, lv := AppLogger(Config{App: "myapp"}, WithAsyncNats(nc))              // NATS only
logger, lv := AppLogger(Config{App: "myapp"}, WithStdout(), WithAsyncNats(nc)) // both
```

Every line carries an `app` attribute matching `Config.App`. The returned
`*slog.LevelVar` controls the minimum log level at runtime (default: `Info`)
and is safe for concurrent use:

```go
lv.Set(slog.LevelDebug) // takes effect immediately, no restart needed
```

#### `Config.Instance` — per-host daemons

Daemons deployed on every workload host (`cert-agentd`, `ssh-tunneld`) set
`Instance` to a per-host identifier so log streams can be addressed
individually. When non-empty:

- `WithAsyncNats` publishes to `app_log.<App>.<Instance>` instead of the
  legacy singleton subject — operators can `nats sub 'app_log.cert-agentd.>'`
  for the fleet or `app_log.cert-agentd.host-42` for one machine.
- Every log line gains an `"instance"` attribute alongside `"app"` — so
  attribute-based consumers can filter without parsing subjects.

```go
logger, _ := AppLogger(Config{
    App:      "cert-agentd",
    Instance: envutil.Or("CERT_AGENTD_INSTANCE", envutil.HostnameOrEmpty()),
}, WithStdout(), WithAsyncNats(nc))
```

Singleton daemons (one replica per cluster) leave `Instance` empty and keep
the legacy `app_log.<App>` subject.

Add additional fixed context fields with standard slog:

```go
logger = logger.With("site", "tokyo", "module", "api")
```

#### Writer options

| Option | Description |
|---|---|
| `WithStdout()` | Synchronous stdout writer |
| `WithAsyncNats(nc)` | Async NATS writer; publishes to `app_log.<App>` (or `app_log.<App>.<Instance>` if `Instance` set), 200-entry buffer, discards on full |

### `AppLoggerWithNATS` — combine logger + self-healing NATS shipping

```go
type NATSConfig struct {
    URL      string         // empty disables shipping (logger falls back to stdout-only)
    CertFile string         // mTLS material — leaf reloaded per handshake (rotation-safe)
    KeyFile  string
    CAFile   string

    Timeout       time.Duration // initial dial; 0 → 5s
    DrainTimeout  time.Duration // graceful drain on shutdown; 0 → 2s
    ReconnectWait time.Duration // reconnect backoff; 0 → 2s
}

func AppLoggerWithNATS(loggerCfg Config, natsCfg NATSConfig, writers ...WriterOption) (
    *slog.Logger, *slog.LevelVar, func(),
)
```

One call constructs the logger, dials NATS (when configured), wires the
async writer, and returns a drain callback the caller defers. Dial uses
self-healing semantics — `RetryOnFailedConnect(true)`, `MaxReconnects(-1)`,
configurable `ReconnectWait` — so a broker that's down at boot doesn't fail
process startup. Entries drop on the floor (200-entry buffer) while
disconnected and resume on reconnect.

When mTLS material is configured, the NATS client presents a freshly reloaded
leaf on every handshake — via
[`reloader.ClientConfig`](#clientconfig--single-pool-rotation-safe-mtls-client-config)
— so shipping survives a short-TTL workload cert that an external agent
(cert-agentd) rotates in place: each reconnect re-reads the cert from disk
instead of clinging to the copy loaded at boot (which would eventually expire
and break the handshake). The CA bundle hot-reloads too — server verification
runs against a pool re-read when the file's mtime advances, so a CA rotation
also lands without a restart. The extra cost is an `os.Stat` per handshake (at
connect and reconnect, not per publish), so it's always on; with no cert+key
the connection is plaintext (dev) or server-auth TLS when only `CAFile` is set.

Three startup outcomes are distinguishable for operators grepping boot logs:

```
URL empty   →  INFO "operational log shipping skipped"   reason=no URL configured
dial failed →  WARN "operational log shipping skipped"   reason=dial failure  err=<...>
dialed      →  INFO "operational log shipping configured" subject=app_log.<App>[.<Instance>]
```

The returned drain is always non-nil — safe to defer unconditionally; it's a
no-op when shipping is disabled.

```go
log, _, drain := AppLoggerWithNATS(
    Config{App: "certd"},
    NATSConfig{
        URL:      os.Getenv("CERTD_NATS_URL"),
        CertFile: os.Getenv("CERTD_NATS_CERT"),
        KeyFile:  os.Getenv("CERTD_NATS_KEY"),
        CAFile:   envutil.First("CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
    },
    WithStdout(),
)
defer drain()
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

[↑ Back to top](#packages)

---

## auth/ — auth primitives namespace

Reusable auth-related building blocks. Each sub-package is a leaf
library with minimal dependencies; pick the ones you need. The
namespace is for grouping only — there's no `auth` package itself.

| Sub-package | Purpose |
| --- | --- |
| `auth/oidcclient` | OIDC public-client helper (login, token cache, refresh) — used by SSO CLIs |
| `auth/creds` | Password hashing (bcrypt) + opaque token generation/digest primitives |
| `auth/awsclaims` | Constants + claim shape for AWS STS federation JWTs (`https://aws.amazon.com/tags`) |
| `auth/jwt` | RS256 signer for OIDC ID tokens, AWS federation tokens, OIDC Back-Channel Logout tokens; JWK helpers |

### auth/oidcclient — OIDC public-client helper for CLI tools

Stdlib-only OIDC client used by SSO CLI helpers (credential helpers
for AWS, SSH cert signers, any future tool that needs a user-bound
bearer token). Owns the OAuth 2.0 authorization-code-with-PKCE flow,
the RFC 8628 device authorization grant, refresh-token rotation, and
an on-disk token cache that all helpers in the installation share.

```go
import "github.com/abagile/tokyo3-base/auth/oidcclient"
```

No third-party dependencies — `go install` of a downstream CLI pulls
only stdlib, so helpers stay statically linkable and fast to
distribute.

### Cache layout

A single `login` from any helper populates a shared root that every
other helper reads from. Helper-specific outputs (anything the
helper persists between calls) live in per-helper subdirectories
under the same root:

```
~/.config/auth-sso/
├── config.json              shared SSO state (issuer + client_id), 0o600
├── tokens.json              shared OAuth access + refresh + id token, 0o600
└── <helper>/                per-helper outputs (any files the helper persists)
```

`<helper>` is whatever `appName` the consuming binary passes to
`AppCacheDir(name)`. Convention: strip the binary's `auth-` prefix,
so a binary `auth-foo-creds` writes to `foo-creds/`,
`auth-bar-tunnel` writes to `bar-tunnel/`, etc. The root directory
name (`auth-sso`) is hardcoded so every helper agrees on one
location without configuration.

### Login — `Login`, `LoginOptions`

```go
func Login(ctx context.Context, cfg Config, opt LoginOptions) (*Tokens, error)

type Config struct {
    Issuer   string
    ClientID string
}

type LoginOptions struct {
    Port   int       // loopback redirect port for code flow; 0 picks free
    Device bool      // RFC 8628 device authorization grant
    Stderr io.Writer // user prompts; nil silences
}
```

Runs the chosen OAuth flow, persists Config + Tokens, returns the
fresh `Tokens`. Code flow is the default for desktops with a browser;
the device flow (`opt.Device = true`) prints a verification URL +
short code so the user can approve from any other device — required
on headless hosts (CI runners, containers, jump boxes).

```go
tokens, err := oidcclient.Login(ctx,
    oidcclient.Config{Issuer: "https://id.example.com", ClientID: "tokyo3-cli"},
    oidcclient.LoginOptions{Stderr: os.Stderr},
)
```

S256 PKCE is always used — no client secret needed. The loopback
redirect URI is built from the listener's actual port; the auth
server must implement RFC 8252 §7.3 loopback-aware matching so a
single `http://127.0.0.1/callback` registration accepts any port.

### Token cache — `LoadConfig`, `LoadTokens`, `EnsureFreshTokens`, `Refresh`

```go
func LoadConfig() (*Config, error)
func LoadTokens() (*Tokens, error)
func EnsureFreshTokens(ctx context.Context, cfg Config, accessSkew time.Duration) (*Tokens, error)
func Refresh(ctx context.Context, issuer, clientID, refreshToken string) (*Tokens, error)
```

`EnsureFreshTokens` is what CLI `get`-style commands call on every
invocation: returns cached tokens if the access token has more than
`accessSkew` remaining, otherwise transparently refreshes via the
refresh token, persists the rotated pair, and returns the new tokens.
Refresh-token rotation is the assumed default (the new refresh token
in the response replaces the old); if the issuer omits the new
refresh in the response (rotation disabled at the AS), the previous
value is retained.

```go
cfg, err := oidcclient.LoadConfig()      // run-login prompt if missing
if err != nil { /* ... */ }
tokens, err := oidcclient.EnsureFreshTokens(ctx, *cfg, 30*time.Second)
// tokens.AccessToken is safe to use for ~accessSkew more time
```

`LoadTokens` returns a "no SSO cache at <path>; run login to
authenticate" error when `tokens.json` doesn't exist — CLI helpers
print this verbatim so the user knows what to do.

### Helper-specific subdirs — `AppCacheDir`

```go
func CacheDir() (string, error)
func AppCacheDir(appName string) (string, error)
```

`CacheDir` returns the shared root (`~/.config/auth-sso/`).
`AppCacheDir(name)` returns `~/.config/auth-sso/<name>/`, creating it
0o700 if missing. `name` must match `[A-Za-z0-9_-]+` — the strict
whitelist rules out `.` and `..` so an operator-supplied helper name
can't escape the cache root.

```go
dir, _ := oidcclient.AppCacheDir("foo-creds")
// dir == ~/.config/auth-sso/foo-creds/
```

Convention is to name the subdir after the binary minus any `auth-`
prefix — e.g. a binary `auth-foo-creds` calls
`AppCacheDir("foo-creds")`.

### Logout

```go
func Logout(extras ...string) error
```

Removes `tokens.json` (so the next call requires a fresh login) plus
any extras the caller names. Extras may be absolute paths or paths
relative to `CacheDir`; missing files are silently ignored. The
shared `config.json` is intentionally preserved so the next `login`
can reuse the cached issuer + client_id.

```go
// Wipe shared tokens plus this helper's whole subdir:
oidcclient.Logout("foo-creds")
```

### Utility — `IDTokenClaims`, `SafeFilename`, `WriteFileAtomic`

```go
func IDTokenClaims(idToken string) IDTokenSubjectClaims
func SafeFilename(s string) string
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error
```

`IDTokenClaims` parses the JWT payload (no signature check — the
resource server re-verifies on receipt) so helpers can derive a
human-readable identifier from `email` or `sub`. `SafeFilename`
collapses path-meaningful characters to `_` so role slugs or
principal names can safely be leaf filenames inside `CacheDir`.
`WriteFileAtomic` is a tempfile-rename helper used internally for the
config + tokens files; exported because helpers reuse it for their
own secret-grade writes.

### auth/creds — password hashing and opaque token primitives

The per-credential primitives every auth-shaped tool needs: bcrypt
for human passwords, a random-token generator + SHA-256 digest for
opaque bearer credentials. Stdlib + `golang.org/x/crypto/bcrypt`
only.

```go
import "github.com/abagile/tokyo3-base/auth/creds"

hash, err := creds.HashPassword("correct-horse-battery-staple")
ok       := creds.CheckPassword(hash, candidate)

raw,  _ := creds.GenerateRawToken()   // 64-char hex, cryptographically random
hash    := creds.HashToken(raw)       // SHA-256 digest, store this; emit raw to the user
```

Bcrypt cost is fixed at 12 (~250ms on modern hardware, matches the
OWASP-recommended starting point). `GenerateRawToken` returns 32
bytes of `crypto/rand` output as hex; `HashToken` is plain SHA-256 —
pair them and store only the digest so a database leak doesn't
expose the live token.

### auth/awsclaims — AWS STS federation JWT claim shape

Two-symbol package fixing the wire format AWS STS expects on
`sts:AssumeRoleWithWebIdentity`. Stdlib-only, no third-party
dependencies — separate from `auth/jwt` so lightweight token
validators (CLI helpers, audit verifiers) can reuse it without
pulling in the full signer + JWT library.

```go
import "github.com/abagile/tokyo3-base/auth/awsclaims"

claims := map[string]any{
    awsclaims.PrincipalTagsClaim: awsclaims.PrincipalTagsValue{
        PrincipalTags: map[string][]string{
            "sub":  {userID},
            "team": {team},
        },
        TransitiveTagKeys: []string{"sub", "team"},
    },
}
```

The claim name (`https://aws.amazon.com/tags`) is fixed by AWS and
must appear verbatim. `PrincipalTags` values are list-of-strings
(AWS honours the first element today; the shape is forward-
compatible). `TransitiveTagKeys` names tags that persist through
subsequent `sts:AssumeRole` chains — federation sessions rarely
chain, but marking them transitive keeps audit semantics consistent.

### auth/jwt — RS256 signer + OIDC/federation/logout claim shapes

Stateless RS256 signer for the three JWT shapes an OIDC IdP needs to
mint: ID tokens (OIDC Core 1.0), AWS STS federation tokens, and
back-channel logout tokens (OIDC Back-Channel Logout 1.0). Key
management (load-or-generate from a keystore, JWKS publication) is
intentionally **not** in this package — callers already know which
storage layer they're using; the signer just takes the loaded
`*rsa.PrivateKey` + KID + issuer at construction.

```go
import "github.com/abagile/tokyo3-base/auth/jwt"

s := jwt.New(privateKey, "kid-abc123", "https://id.example.com", jwt.Config{
    IDTokenTTL:         1 * time.Hour,        // optional; default 1h
    FederationTokenTTL: 15 * time.Minute,     // optional; default 15m
    ACRMFA:             "urn:mace:incommon:iap:silver",  // optional; default
})

idTok, _   := s.MintIDToken(userID, clientID, email, name, nonce, scopes, true, amr, authTime, sid, groups)
fedTok, _  := s.MintFederationToken(userID, audience, email, name, groups, amr, authTime, 0, principalTags)
logTok, _  := s.MintLogoutToken(rpAudience, sub, sid, jti, time.Now())
```

Defaults are the values an IdP-style operator typically wants;
override via `Config` when a specific deployment needs different
numbers. The federation token's `lifetime` argument overrides
`Config.FederationTokenTTL` per call (some flows want a tighter
window); pass 0 to fall back to the configured default.

`PublicKeyToJWK(*rsa.PublicKey, kid) JWK` converts a public key into
the `JWK` shape published at `/.well-known/jwks.json`. Caller
assembles the `JWKS` document by walking every active key in its
keystore — this package doesn't know about storage.

[↑ Back to top](#packages)

---

## cli/ — daemon startup composition

```go
import "github.com/abagile/tokyo3-base/cli"

type App struct {
    Name      string  // short binary name → slog "app" attr + app_log subject
    EnvPrefix string  // env-var prefix, e.g. "CERTD"
    Instance  string  // optional per-host id (fleet agents) → app_log.<Name>.<Instance>
}

func (a App) Setup(parent context.Context) Runtime
func (a App) NATS() NATS
func (a App) DB() DB
func (a App) AdminDB() DB
```

Composes the bootstrap prelude every daemon repeats — application logger
(with NATS log shipping), a `SIGINT`/`SIGTERM`-cancelled context, and the
opt-in diagnostics server — depending on `applog`, `debug`, and `envutil`
but **not** a command framework. Each binary keeps its own cobra (or
other) command tree and calls `Setup` from inside its serve command.
`Setup` is additive: a daemon with non-standard env keys can skip it and
wire the pieces directly.

```go
func runServe(ctx context.Context) error {
    rt := cli.App{Name: "certd", EnvPrefix: "CERTD"}.Setup(ctx)
    defer rt.Shutdown()
    log := rt.Log
    // ... build the server, serve until rt.Ctx.Done() ...
}
```

```go
type Runtime struct {
    Log       *slog.Logger
    Ctx       context.Context // cancelled on signal or parent cancel
    NATS      NATS            // resolved NATS material (WORKLOAD_* fallback)
    DB        DB              // resolved runtime Postgres material (no WORKLOAD fallback)
    AdminDB   DB              // admin/migration material (ADMIN_* → DB_* → blank)
    EnvPrefix string
    Shutdown  func()          // defer it: releases the signal hook + drains the logger
}
```

### WORKLOAD identity convention

A daemon's mesh mTLS identity is `<PREFIX>_WORKLOAD_CERT` / `_WORKLOAD_KEY`
/ `_WORKLOAD_CA`. The **NATS** channel reuses it: each of
`<PREFIX>_NATS_CERT/KEY/CA` falls back to the matching `WORKLOAD_*`, so a
daemon that already has a workload identity ships logs and audit over mTLS
without extra cert sets. Set `<PREFIX>_NATS_*` only to override.

The **Postgres** channel splits the fallback. The client **cert/key** are a
database-role credential, not the workload identity, so
`<PREFIX>_DB_CERT/KEY` resolve verbatim (unset ⇒ no client cert, the DSN's
`sslmode` governs TLS). The **CA** is the shared mesh trust root, so
`<PREFIX>_DB_CA` falls back to `<PREFIX>_WORKLOAD_CA`. The admin/migration
material adds an `ADMIN_*` tier on top: cert/key `<PREFIX>_ADMIN_DB_* →
<PREFIX>_DB_*`, and CA `<PREFIX>_ADMIN_DB_CA → <PREFIX>_DB_CA →
<PREFIX>_WORKLOAD_CA`.

```go
type NATS struct { URL, CertFile, KeyFile, CAFile string }
type DB   struct { URL, CertFile, KeyFile, CAFile string }
```

`App.NATS()` resolves the NATS material (callable independently of `Setup`);
`Runtime.NATS` carries the same resolution so audit and other NATS clients
draw from one source of truth.

`App.DB()` (DSN `<PREFIX>_DATABASE_URL`, files `<PREFIX>_DB_*`) and
`App.AdminDB()` (`<PREFIX>_ADMIN_DATABASE_URL` / `_ADMIN_DB_*`, each falling
back to the runtime value) resolve the Postgres material; `Runtime.DB` /
`Runtime.AdminDB` carry it. These resolve material only — the caller builds a
hot-reloading `*tls.Config` from the files via `tls/reloader.ClientConfig`
and owns the connection (pool tuning, migrations); base has no single
Postgres-open layer to host those.

### Audit sink/source

```go
func AuditSink[T any](rt Runtime, subject string) (*journal.EncodedSink[T], error)
func AuditSource(rt Runtime, stream, subject string) (journal.Source, error)
```

Build a daemon's primary audit publisher (typed by the app's Entry `T`)
and own-stream reader from the resolved NATS material — the common case
collapses to one generic call. A daemon that attaches to additional
streams (e.g. certd tailing ssh-proxy's audit) wires those directly.
No-op (no error) when no broker URL is configured.

```go
sink, _ := cli.AuditSink[audit.Entry](rt, audit.Subject)
src,  _ := cli.AuditSource(rt, audit.StreamName, audit.Subject)
```

These are free functions, not methods on a generic `App`, so a daemon that
publishes no audit (e.g. cert-agentd) uses a plain `App` with no spurious
type parameter.

[↑ Back to top](#packages)

---

## clientip/ — spoof-resistant client IP extraction

```go
import "github.com/abagile/tokyo3-base/clientip"

func New(trustedProxies []*net.IPNet) *Extractor
func (e *Extractor) FromRequest(r *http.Request) string // bare host, no port
```

The one way to answer "what is the real client IP?" for an HTTP request, so
rate-limit keying and audit attribution agree across the fleet. The immediate
TCP peer (`r.RemoteAddr`) is the source of truth — the only address a client
can't forge. `X-Forwarded-For` is consulted **only** when that peer is itself a
configured trusted proxy, in which case the **rightmost hop that is not
trusted** (the real client as seen by infrastructure we control) is returned.
Walking right-to-left and stopping at the first untrusted hop defeats a client
that pre-seeds `X-Forwarded-For` to spoof its source. With no trusted proxies
configured, `X-Forwarded-For` is ignored entirely and the peer IP is always
returned.

```go
ext := clientip.New(proxies) // proxies from envutil.CIDRList("MYDAEMON_TRUSTED_PROXIES")
ip := ext.FromRequest(r)     // use as the audit "source" / rate-limit key
```

Use this instead of hand-rolling a `clientIP` helper per daemon. `ratelimit`
keys on it internally; an audit layer should derive its `source` from it too,
so a single source IP is computed identically everywhere. It is HTTP-only — an
SSH/raw-TCP peer is just a `net.Addr` with no forwarding header and needs no
such reasoning.

[↑ Back to top](#packages)

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

[↑ Back to top](#packages)

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

[↑ Back to top](#packages)

---

## debug/ — opt-in diagnostics server

```go
import "github.com/abagile/tokyo3-base/debug"

type Config struct {
    Addr       string        // listen addr, e.g. "127.0.0.1:6060"; empty = disabled
    Log        *slog.Logger  // defaults to slog.Default()
    StatsEvery time.Duration // runtime-stats interval; default 30s
}

func Start(ctx context.Context, cfg Config)
func Handler() http.Handler
```

Serves Go runtime profiles (goroutine, heap, threadcreate, allocs, block,
mutex, CPU, trace) plus a periodic goroutine / OS-thread / heap log line,
for chasing leaks and stalls. A no-op when `Addr` is empty, so importing
it is inert until a daemon opts in.

Unlike `net/http/pprof`, it registers **nothing** on
`http.DefaultServeMux`: the handlers are built directly from
`runtime/pprof` + `runtime/trace` and served on the package's own mux — so
importing it can never quietly attach profiling to a binary that serves
the default mux. `Handler()` exposes that mux for mounting on an existing
admin server.

```go
debug.Start(ctx, debug.Config{Addr: os.Getenv("CERTD_DEBUG_ADDR"), Log: log})

// curl http://127.0.0.1:6060/debug/pprof/goroutine?debug=1     # counts by stack
// curl http://127.0.0.1:6060/debug/pprof/threadcreate?debug=1  # OS threads ≈ cgroup pids.current
```

A steadily climbing `goroutines` in the stats line confirms a goroutine
leak; climbing `os_threads` with flat goroutines points instead at threads
stuck in blocking syscalls/cgo.

> **Unauthenticated** — bind `Addr` to loopback or a private interface;
> never expose it publicly.

[↑ Back to top](#packages)

---

## envutil/ — cmd/ main.go boilerplate helpers

Tiny dependency-free helpers every cmd/main.go in the suite needs: env-var
fallback chains, a fail-fast "required" check, a hostname default for
per-host identifiers, and a safe close-if-Closer wrapper.

```go
import "github.com/abagile/tokyo3-base/envutil"
```

| Function | Purpose |
|---|---|
| `Or(key, fallback string) string` | Env var with a default. Empty/unset → fallback. |
| `First(keys ...string) string` | First non-empty value among the named env vars (fallback chains). |
| `MustEnv(key string) string` | Required env var. Writes `"<key> is required"` to stderr and `os.Exit(2)` when unset — matches Go's `flag.Parse` convention for usage/config errors. |
| `HostnameOrEmpty() string` | `os.Hostname()` on success, `""` on error. Default for per-host identifier env vars like `CERT_AGENTD_INSTANCE`. |

Typed scalar parsers for the same "config from env" shape — an unset/empty var
yields the zero value with no error (so the caller applies its own default); a
malformed value is an error naming the key:

| Function | Purpose |
|---|---|
| `Float(key string) (float64, error)` | Parse a float (e.g. a rate-limit RPS). |
| `Int(key string) (int, error)` | Parse an int (e.g. a burst). |
| `Duration(key string) (time.Duration, error)` | Parse a Go duration (`"750ms"`, `"6h"`). |
| `CIDRList(key string) ([]*net.IPNet, error)` | Parse a comma-separated CIDR list; a bare IP ⇒ `/32` (IPv4) or `/128` (IPv6). Handy for trusted-proxy allow-lists. |

```go
addr      := envutil.Or("MYDAEMON_ADDR", ":8080")
caFile    := envutil.First("MYDAEMON_NATS_CA", "MYDAEMON_WORKLOAD_CA")
issuer    := envutil.MustEnv("MYDAEMON_ISSUER")
instance  := envutil.Or("MYDAEMON_INSTANCE", envutil.HostnameOrEmpty())

rps, err  := envutil.Float("MYDAEMON_RATE_LIMIT_RPS")          // 0 when unset
proxies, err := envutil.CIDRList("MYDAEMON_TRUSTED_PROXIES")   // nil when unset
```

[↑ Back to top](#packages)

---

## guard/ — panic recovery for background work

```go
func Guarded(log *slog.Logger, name string, fn func()) func()
func Go(log *slog.Logger, name string, fn func())
func Tick(log *slog.Logger, name string, fn func())
func Close(v any)
```

A single unrecovered panic in any goroutine crashes the whole process, and
net/http only recovers request handlers — not reapers, sync loops, or
trackers. `Go` spawns a goroutine that recovers, logs (with a stack trace)
under `name`, and returns instead of taking the process down. `Guarded`
returns that same recovery as a `func()` *without* launching it, so it drops
into a launcher that owns the goroutine — `sync.WaitGroup.Go`, errgroup —
when a recovered goroutine must also be joined at shutdown (`Go` is a
one-liner over it). `Tick` is the
in-loop counterpart: call it synchronously inside a ticker body so one bad
iteration logs and the loop keeps firing. Pair them — `Go` as the outer
backstop, `Tick` per iteration. `Close` is the cleanup companion: a
best-effort `Close()` of a value that may or may not implement `io.Closer`
(e.g. an audit sink that's a real client or a no-op) — typically deferred.

A zero-dependency leaf (stdlib only), so a lean tool can recover background
goroutines without pulling the daemon-composition stack in `cli`.

```go
guard.Go(rt.Log, "audit-tracker", func() { tracker.Run(rt.Ctx) })

// joinable: same recovery, but a WaitGroup owns the goroutine so it can be
// waited on at shutdown before the resources it uses are closed.
var workers sync.WaitGroup
workers.Go(guard.Guarded(rt.Log, "reaper", func() { runReaper(rt.Ctx) }))

for {
    select {
    case <-rt.Ctx.Done():
        return
    case <-ticker.C:
        guard.Tick(rt.Log, "reaper", func() { reapOnce(rt.Ctx) })
    }
}

sink, _ := openAuditSink(log)
defer guard.Close(sink)
```

[↑ Back to top](#packages)

---

## httpauth/ — HTTP auth middleware

```go
import "github.com/abagile/tokyo3-base/httpauth"

type BasicAuthConfig struct {
    Username string  // empty (either field) ⇒ gate disabled
    Password string
    Realm    string  // WWW-Authenticate realm; empty ⇒ "restricted"
}

func (c BasicAuthConfig) Enabled() bool
func BasicAuth(cfg BasicAuthConfig, next http.Handler, exempt ...string) http.Handler
```

The HTTP Basic gate the daemons' admin portals share. When either credential
is empty the gate is disabled and `next` is served unguarded — operators
front the service with oauth2-proxy, an mTLS reverse proxy, or another
identity-aware edge instead. When enabled, each request is constant-time
compared against the configured credentials (a sha256 digest of each side, so
an attacker's guess length doesn't leak). Paths in `exempt` (exact match)
bypass the gate — pass `"/healthz"` so external watchdogs can probe without
the admin credentials.

```go
mux := http.NewServeMux()
// ... register routes ...
handler := httpauth.BasicAuth(httpauth.BasicAuthConfig{
    Username: os.Getenv("CERTD_PORTAL_USERNAME"),
    Password: os.Getenv("CERTD_PORTAL_PASSWORD"),
    Realm:    "certd portal",
}, mux, "/healthz")
```

A transport-layer middleware, deliberately separate from the
credential/token primitives in [`auth/`](#auth--auth-primitives-namespace):
it *consumes* them rather than defining them, and keeps `net/http` out of
that transport-agnostic namespace.

[↑ Back to top](#packages)

---

## journal/ — Append-only durable event journal

An append-only, ordered, **fail-closed** event journal with symmetric write
and read faces — the shape that fits audit trails, event-sourcing stores,
financial ledgers, change-data-capture, and anywhere "this event happened,
never lose it" matters. Producers use `Sink`; viewers and consumers use
`Source`. The two are independent — pick whichever face you need.

```go
import (
    "github.com/abagile/tokyo3-base/journal"
    "github.com/abagile/tokyo3-base/journal/jetstream"
    "github.com/abagile/tokyo3-base/journal/sse"
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

`Source.Subscribe` mirrors that contract on the read side: implementations
deliver every published record exactly once per subscription, in publish
order, until the caller cancels the context. Backfill semantics are
explicit (replay the last N, or resume from a known sequence) rather than
implicit, so reconnect behaviour is observable rather than magical.

### Write face — `Sink`

```go
type Sink interface {
    Append(ctx context.Context, payload []byte) error
    Close() error
}

type NoopSink struct{} // discards every payload; for tests / disabled-in-dev
```

The interface is byte-oriented; callers marshal their own payload format
(JSON, protobuf, length-prefixed binary, …). Implementations live in
sub-packages so each transport's SDK weight is opt-in.

#### Typed events with `EncodedSink[T]`

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

inner, _ := jetstream.NewSink(jetstream.SinkConfig{URL: "...", Subject: "..."})
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

### Read face — `Source`

```go
type Msg struct {
    Seq  uint64    // monotonic per-stream sequence assigned by the transport
    Time time.Time // publish time stamped by the transport
    Data []byte    // payload, byte-for-byte as Sink.Append delivered it
}

type Source interface {
    // Subscribe yields a channel of Msgs in publish order, blending a
    // backfill window of historical records with a live tail of new
    // records, until ctx is cancelled.
    //
    //   replay > 0, startFromSeq == 0   → last `replay` records, then tail
    //   replay == 0, startFromSeq == 0  → tail only, no backfill
    //   startFromSeq > 0                → resume from that sequence (replay ignored)
    Subscribe(ctx context.Context, replay int, startFromSeq uint64) (<-chan Msg, error)
    Close() error
}

type NoopSource struct{} // yields nothing; closes channel on ctx cancel
```

Two backfill knobs cover the three patterns a UI / consumer typically
needs: "show me the last 100 events and keep going" (replay > 0,
startFromSeq = 0); "tail forward from now" (both zero); and "resume after a
disconnect from the last sequence I saw" (startFromSeq > 0). The third is
exactly the `Last-Event-ID` reconnect path that `journal/sse` plumbs
through — `Msg.Seq` is the sequence the consumer remembers, and the next
Subscribe with `startFromSeq = lastSeen + 1` continues without duplicates.

`Source` is independent of `Sink`. A process that only consumes (a SCIM
projector, an SSE viewer, a CLI tail) holds a `Source`; a process that
only publishes holds a `Sink`; both can co-exist and own their own NATS
connection. Implementations clean up the underlying transport-level
consumer when ctx is cancelled, so per-request Subscribe is cheap.

#### Typed reads with `EncodedSource[T]`

```go
type Event[T any] struct {
    Seq   uint64
    Time  time.Time
    Value T          // decoded payload
}

type EncodedSource[T any] struct { /* ... */ }

func NewEncodedSource[T any](inner Source, decode func([]byte) (T, error)) *EncodedSource[T]
func NewJSONSource   [T any](inner Source) *EncodedSource[T]   // convenience: decode = json.Unmarshal
```

Symmetric to `EncodedSink[T]`: takes a byte-level `Source` and yields a
channel of `Event[T]` with the decoded value alongside the transport's
sequence and timestamp. The same typed event struct flows on both sides:

```go
src, _ := jetstream.NewSource(jetstream.SourceConfig{ /* ... */ })
typed := journal.NewJSONSource[AuditEntry](src)

events, err := typed.Subscribe(ctx, 100, 0) // last 100 + tail
if err != nil { /* ... */ }
for ev := range events {
    fmt.Printf("seq=%d t=%s entry=%+v\n", ev.Seq, ev.Time, ev.Value)
}
```

For non-JSON formats, supply your own decoder (mirror of `NewEncodedSink`):

```go
typed := journal.NewEncodedSource(src, func(b []byte) (AuditEntry, error) {
    var p eventpb.AuditEntry
    if err := proto.Unmarshal(b, &p); err != nil { return AuditEntry{}, err }
    return fromProto(&p), nil
})
```

**Decode failures are silently dropped.** A malformed record means "this
consumer can't read this payload" — the producer or the type T is the
thing to fix; retrying won't help, and aborting the stream punishes good
records that follow. If you need stricter behaviour (e.g. for compliance
evidence that no record was ever skipped), wrap a raw `Source` and apply
your own decode + error policy — `EncodedSource` is the ergonomic default,
not the universal one.

### `journal/jetstream` — NATS JetStream implementation

Sink (write face):

```go
sink, err := jetstream.NewSink(jetstream.SinkConfig{
    URL:     "tls://nats:4222",
    Subject: "vault.audit.events",     // must be covered by an existing JetStream stream
    TLS:     tlsCfg,                   // optional; nil for plaintext (dev only)
})
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

Source (read face — for live tail / SSE):

```go
src, err := jetstream.NewSource(jetstream.SourceConfig{
    URL:               "tls://nats:4222",
    StreamName:        "vault_audit",          // the stream that covers Subject
    Subject:           "vault.audit.events",
    TLS:               tlsCfg,
    InactiveThreshold: 5 * time.Minute,        // optional; default 5m
})
if err != nil { /* ... */ }
defer src.Close()

// Per subscriber: replay the last 100 records, then tail forever (until ctx done).
msgs, err := src.Subscribe(ctx, 100, 0)
for m := range msgs {
    fmt.Printf("seq=%d t=%s data=%s\n", m.Seq, m.Time, m.Data)
}
```

`Subscribe` creates an **ephemeral, ack-none** JetStream consumer per call,
chooses a delivery policy from the requested backfill window, and tails
the stream until the caller cancels:

| Inputs                         | JetStream `DeliverPolicy` | `OptStartSeq`        |
|--------------------------------|---------------------------|----------------------|
| `startFromSeq > 0`             | `ByStartSequence`         | `startFromSeq`       |
| `replay <= 0` or empty stream  | `New`                     | —                    |
| `replay >= stream length`      | `All`                     | —                    |
| otherwise                      | `ByStartSequence`         | `LastSeq − replay+1` |

Ephemeral + ack-none means the consumer carries no state — JetStream
deletes it after `InactiveThreshold` of silence (default 5 minutes), which
covers a browser reconnect window without leaking abandoned consumers.
The reader's NATS credential needs CONSUME rights on the subject; no
stream-management rights, again because this package does not provision
streams.

#### Convenience: `NewAuditSink[T]` / `NewAuditSource`

```go
func NewAuditSink[T any](cfg AuditSinkConfig) (*journal.EncodedSink[T], error)
func NewAuditSource(cfg AuditSourceConfig)   (journal.Source, error)
```

The same wiring every daemon's `openAuditSink` / `openAuditSource`
spelled out by hand: dial NATS, build TLS config from PEM file paths,
wrap the byte-level Sink in `journal.NewJSONSink[T]`, and emit the
standard "URL not set — sink is no-op" / "<PREFIX>_CERT not set —
without mTLS" / "audit sink: NATS JetStream with mTLS" warn/info log
lines. Operators reading boot logs see one consistent set of
messages across the whole suite.

```go
sink, err := jetstream.NewAuditSink[audit.Entry](jetstream.AuditSinkConfig{
    URL:       os.Getenv("CERTD_NATS_URL"),
    CertFile:  os.Getenv("CERTD_NATS_CERT"),
    KeyFile:   os.Getenv("CERTD_NATS_KEY"),
    CAFile:    envutil.First("CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
    Subject:   audit.Subject,
    EnvPrefix: "CERTD_NATS",
    Log:       log,
})
```

`EnvPrefix` is the env-var family name that appears in the no-op /
no-mTLS warns (e.g. `"CERTD_NATS_URL not set — audit sink is no-op"`).
URL empty returns a typed sink wrapping `journal.NoopSink` — safe to
`Append` against; drops every entry. `NewAuditSource` mirrors the
shape for the read side and returns `journal.NoopSource{}` when URL
is empty (downstream UI renders empty, mirroring the no-broker
dev story).

With a full cert+key pair, the connection's TLS config reloads the
leaf from disk on every handshake and re-reads the CA pool when its
file's mtime advances (via
[`reloader.ClientConfig`](#clientconfig--single-pool-rotation-safe-mtls-client-config),
same contract as the log shipper), so audit publishing and reads
survive in-place rotation of both the short-TTL workload cert and
the CA bundle without a daemon restart. CA-only stays one-shot
server-auth TLS; no material stays plaintext (dev).

### `journal/sse` — generic Server-Sent-Events handler

```go
type Handler struct {
    Source    journal.Source
    Replay    int           // default 100
    Heartbeat time.Duration // default 30s; 0 disables
}

func (Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

Streams any `journal.Source` to a browser as Server-Sent Events with one
HTTP handler. Each `Msg` becomes one SSE event:

```
id: 1234
data: {"id":"e-1","action":"secret.set",…}

```

The `id:` line is the journal sequence; on reconnect the browser's
`EventSource` automatically sends `Last-Event-ID: 1234`, and the handler
resumes via `Source.Subscribe(ctx, _, 1235)` so a transient drop replays
only the missed events — not the full backfill window. Comment-line
heartbeats (`: ping`) fire every `Heartbeat` to keep proxy connections
warm.

Handler doesn't speak authentication — wrap with whatever middleware the
host app already uses (cookie session, bearer token, mTLS):

```go
src, _ := jetstream.NewSource(jetstream.SourceConfig{ /* ... */ })
defer src.Close()

mux.Handle("GET /admin/audit/sse",
    s.adminAuth(sse.Handler{
        Source:    src,
        Replay:    100,
        Heartbeat: 30 * time.Second,
    }))
```

The Data is forwarded byte-for-byte from `Msg.Data`, so producers using
`journal.NewJSONSink[T]` already publish wire-ready JSON — no transcoding
on the read side. Browsers parse the `data:` payload as their own JSON.

### `journal.Tracker[T]` — server-rendered recent-events ring

```go
type TrackerConfig[T any] struct {
    Source Source              // required
    Decode func(Msg) (T, bool) // required; ok=false skips (decode failure OR filtered out)
    Less   func(a, b T) bool   // optional: newest-first comparator ⇒ sorted; nil ⇒ arrival order
    Max    int                 // ring cap; 0 ⇒ DefaultTrackerSize (500)
    Label  string              // optional, for the "subscribed" log line
    Log    *slog.Logger
}

func NewTracker[T any](cfg TrackerConfig[T]) (*Tracker[T], error)
func (t *Tracker[T]) Run(ctx context.Context) error // Subscribe(replay=Max) + tail until ctx
func (t *Tracker[T]) Snapshot() []T                 // newest-first copy, concurrent-safe
```

A bounded in-memory ring of the most recent decoded events from a `Source`,
kept current by a background `Run` loop. It is the **server-side-rendered**
counterpart to [`journal/sse`](#journalsse--generic-server-sent-events-handler):
where the SSE handler pushes a live stream to a browser, a `Tracker`
materializes a snapshot an admin page can render synchronously (a "recent
activity" table) — the right tool when the view is server-rendered rather than
a JS-driven live tail.

`Decode` folds decoding and filtering into one step — return `ok=false` to skip
a record (a JSON failure or an unwanted event, e.g. the wrong action), so the
caller owns any per-skip logging. `Less` picks the ordering: a newest-first
comparator (e.g. by an event timestamp) re-sorts the ring on each ingest;
`nil` prepends by arrival, which suits a stream whose publish order already
matches recency. Own the `Run` goroutine with [`guard.Go`](#guard--panic-recovery-for-background-work)
(or a [`run.Group`](#run--component-lifecycle-coordination) component).

```go
tr, _ := journal.NewTracker(journal.TrackerConfig[AuditEvent]{
    Source: src,
    Decode: decodeAuditEvent, // json.Unmarshal + validity ⇒ (AuditEvent, ok)
    Less:   func(a, b AuditEvent) bool { return a.OccurredAt.After(b.OccurredAt) },
})
guard.Go(log, "audit-tracker", func() { _ = tr.Run(ctx) })

// in the /audit page handler:
events := tr.Snapshot() // newest-first, safe under concurrent Run
```

[↑ Back to top](#packages)

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

[↑ Back to top](#packages)

---

## oidc/ — OIDC ID-token verification

```go
import "github.com/abagile/tokyo3-base/oidc"

type Claims struct {
    Subject, Email, Name string
    Groups               []string
    Nonce                string
    Issuer               string    // iss
    AuthTime             time.Time // auth_time
    SessionID            string    // sid
}

type TokenVerifier interface {
    Verify(ctx context.Context, rawIDToken string) (*Claims, error)
}

func NewHTTPVerifier(ctx context.Context, issuer, audience string) (*HTTPVerifier, error)
func NewLazyHTTPVerifier(issuer, audience string) (*LazyVerifier, error)

// OAuth2 endpoints from discovery, for a login broker that also runs the
// code exchange against the same provider (no second discovery):
func (v *HTTPVerifier) Endpoint() oauth2.Endpoint
func (v *LazyVerifier) Endpoint(ctx context.Context) (oauth2.Endpoint, error)

// Back-channel logout (HTTPVerifier and LazyVerifier):
type LogoutClaims struct {
    Issuer, Subject, SessionID, JTI string
    IssuedAt, ExpiresAt             time.Time
}
func (v *HTTPVerifier) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error)
func (v *LazyVerifier) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error)
```

Verifies inbound OIDC ID tokens — signature, issuer, audience, expiry — so a
service derives a caller's identity and groups from a cryptographically-signed
assertion rather than a self-declared request field. `HTTPVerifier` wraps
[`coreos/go-oidc`](https://github.com/coreos/go-oidc) (OIDC discovery + JWKS
fetch, auto-refreshed on key rotation). `LazyVerifier` defers that I/O to the
first `Verify`, so a daemon boots even while its IdP is briefly unreachable and
self-heals on the next request — a transient outage at boot surfaces as a 401,
not a crash. Consumers depend on the `TokenVerifier` interface, so tests inject
a stub instead of standing up a real issuer.

`VerifyLogoutToken` validates an [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
`logout_token` over the same JWKS-backed verifier (§2.6: rejects a `nonce`,
requires the `backchannel-logout` event, requires `jti` and at least one of
`sub`/`sid`). Pair it with the `SessionID` (`sid`) now surfaced on `Claims` to
correlate and terminate the right session on a logout callback.

```go
v, err := oidc.NewLazyHTTPVerifier(
    os.Getenv("MYDAEMON_OIDC_ISSUER"),
    os.Getenv("MYDAEMON_OIDC_AUDIENCE"), // the OIDC client_id minted for this service
)
// per request — treat any error as 401:
claims, err := v.Verify(r.Context(), bearerToken)
if err != nil { /* 401 */ }
allowed := slices.Contains(claims.Groups, "admins")
```

### Authenticator — browser login + sealed session

```go
type AuthenticatorConfig struct {
    Issuer, ClientID, ClientSecret, RedirectURL string
    AdminGroup   string         // required group claim; "" ⇒ any authenticated user
    Verifier     TokenVerifier  // validates the returned ID token (audience = ClientID)
    SessionKey   []byte         // 32-byte key sealing the session + flow cookies (AES-256-GCM)
    SessionTTL   time.Duration  // 0 ⇒ 8h
    CookiePrefix string         // <prefix>_session / <prefix>_flow (required)
    CookiePath   string         // "" ⇒ "/"
    LoginPath, CallbackPath, LogoutPath string // defaults /auth/{login,callback,logout}
    ExemptPaths  []string       // extra unauthenticated paths (e.g. "/healthz")
    Now func() time.Time        // injectable clock
    Log *slog.Logger
}

func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error)
func (a *Authenticator) LoginHandler() http.HandlerFunc
func (a *Authenticator) CallbackHandler() http.HandlerFunc
func (a *Authenticator) LogoutHandler() http.HandlerFunc
func (a *Authenticator) Gate(next http.Handler) http.Handler
func SessionFromContext(ctx context.Context) (Session, bool)
```

Native browser-based OIDC login for an admin portal — the Authorization-Code +
PKCE flow, an AES-256-GCM-sealed session cookie, and an optional admin-group
gate. It owns only the browser glue: `LoginHandler` mints state/nonce/PKCE and
redirects to the IdP; `CallbackHandler` validates state, exchanges the code
(via `auth/oidcclient`), verifies the ID token + nonce with the `TokenVerifier`,
and seals the session; `Gate` enforces the session (and group) on the protected
mux — redirecting unauthenticated GETs to login (with `return_to`) and 401-ing
other methods. Downstream handlers read the identity via `SessionFromContext`.

Pair it with [`httpauth.BasicAuth`](#httpauth--http-auth-middleware): a portal
runs OIDC login when configured, else falls back to the Basic gate.

```go
auth, _ := oidc.NewAuthenticator(oidc.AuthenticatorConfig{
    Issuer: issuer, ClientID: clientID, ClientSecret: secret,
    RedirectURL:  "https://certd.example.com/portal/auth/callback",
    AdminGroup:   "ca-portal-admin",
    Verifier:     verifier,          // an oidc.TokenVerifier (audience = clientID)
    SessionKey:   key,               // 32 bytes, e.g. crypto.ParseKEK(hex)
    CookiePrefix: "certd_portal",
    CookiePath:   "/portal/",
})
mux.Handle("GET /auth/login", auth.LoginHandler())
mux.Handle("GET /auth/callback", auth.CallbackHandler())
mux.Handle("GET /auth/logout", auth.LogoutHandler())
handler := auth.Gate(mux) // wrap the protected routes
```

Cookies are HttpOnly, Secure (when served over TLS), SameSite=Lax, scoped to
`CookiePath`; the flow cookie is short-lived (10m) and the session honors
`SessionTTL`. `return_to` is confined to a local absolute path so a crafted
value can't bounce the browser to an attacker origin.

[↑ Back to top](#packages)

---

## ratelimit/ — per-source-IP HTTP rate limiter

```go
import "github.com/abagile/tokyo3-base/ratelimit"

type Config struct {
    RPS            float64       // per-source req/s; <= 0 disables (New returns nil)
    Burst          int           // token-bucket burst; < 1 ⇒ 1
    TrustedProxies []*net.IPNet  // proxies whose X-Forwarded-For is trusted for keying
    Log            *slog.Logger
    OnThrottle     http.HandlerFunc // renders a throttled response; nil ⇒ plain-text 429
}

func New(cfg Config) *Limiter
func (l *Limiter) Middleware(next http.Handler, exempt ...string) http.Handler
```

Baseline defense-in-depth for any workload that exposes an API. `New` returns
a token-bucket limiter keyed on the immediate TCP peer; `Middleware` wraps a
handler, returning 429 + `Retry-After` when a source exceeds its rate. A nil
`*Limiter` (when `RPS <= 0`) passes through, so callers wire it
unconditionally; `exempt` paths bypass it — pass `"/healthz"`. Set `OnThrottle`
to render the throttled response yourself (e.g. JSON for API clients, HTML for
browsers); the `Retry-After` header is already set when it runs, and the default
is a plain-text 429 via `http.Error`.

```go
rl := ratelimit.New(ratelimit.Config{
    RPS:            rps,
    Burst:          burst,
    TrustedProxies: proxies, // from envutil.CIDRList("MYDAEMON_TRUSTED_PROXIES")
    Log:            log,
})
mux := http.NewServeMux()
// ... routes ...
handler := rl.Middleware(mux, "/healthz")
```

### What it is (and isn't)

It throttles **per source, per replica, in process** — brute-force and
credential-stuffing on auth paths, single-client resource exhaustion against an
expensive signer or DB pool, and the automated scanning/fuzzing that precedes
an exploit. The key is the real client IP from
[`clientip`](#clientip--spoof-resistant-client-ip-extraction): the immediate
peer, never a raw `X-Forwarded-For`, so it can't be spoofed via the header;
`X-Forwarded-For` is honored only when the peer is a configured `TrustedProxies`
CIDR, in which case the rightmost *untrusted* hop (the real client behind our
own edge) becomes the key. Derive audit attribution from the same `clientip`
extractor so the limiter and the audit log agree on the source.

It is **not** a volumetric-DoS control: a distributed flood from many IPs
bypasses per-IP limits, replicas don't coordinate, and L3/L4 floods never reach
the app — those belong to an upstream LB/WAF/CDN. Nor is it an exploit (e.g.
RCE) mitigation; it only slows the probing that precedes one. Front the service
with edge protection for availability; use this to bound single-source abuse.

Idle buckets are swept lazily (no background goroutine) so a stream of distinct
source IPs can't grow the map without bound.

[↑ Back to top](#packages)

---

## run/ — component lifecycle coordination

```go
import "github.com/abagile/tokyo3-base/run"

type Component func(context.Context) error

func Group(ctx context.Context, components ...Component) error
func HTTPServer(srv *http.Server, shutdownTimeout time.Duration, useTLS bool) Component
```

The serve/shutdown discipline every daemon repeats: run N long-lived
components concurrently, let the first to exit cancel the rest, and report
the first error that isn't `context.Canceled`. `Group` derives a child of
`ctx`, runs each `Component` on it, and on any component's return cancels
that child. Siblings the caller runs on the parent `ctx` — best-effort
pollers launched via `guard.Go` — are untouched, so they stop on the
parent's own cancellation (a signal) or at process exit, not on a component
exit.

`HTTPServer` adapts a stdlib `*http.Server` into a `Component`: it serves
until `ctx` cancels, then `Shutdown`s within `shutdownTimeout`, folding
`http.ErrServerClosed` to nil. Pass `useTLS` for `ListenAndServeTLS` (the
server's `TLSConfig` is the cert source, so the cert/key args stay empty).

```go
// single HTTPS server
err := run.Group(rt.Ctx, run.HTTPServer(httpSrv, 10*time.Second, true))

// several components — a ctx-aware method value satisfies Component directly,
// a stdlib server gets the adapter
err := run.Group(rt.Ctx,
    sshSrv.ListenAndServe,                          // func(context.Context) error
    run.HTTPServer(portalSrv, 5*time.Second, false),
)
```

A component must return when its context is cancelled; one that ignores it
stalls `Group`'s wait. `Group` is dependency-free (stdlib only), so tools and
tests can use it without pulling in the `cli` daemon-composition stack.

[↑ Back to top](#packages)

---

## tls/ — stateless TLS helpers

Pure helpers for the boring parts of running a TLS server or client
without inventing your own PKI: build `*tls.Config` from PEM files or
strings, parse a trust pool, verify a peer chain, and ship a self-signed
dev fallback covering `localhost`, `*.localhost`, and loopback IPs.
Everything here reads its inputs once and returns — no caching, no
goroutines. For material that rotates under a running process (leaf
reloaded per handshake, CA pool re-read on change), see
[`tls/reloader`](#tlsreloader--hot-reload-loaders--multi-pool-orchestrator).

```go
import "github.com/abagile/tokyo3-base/tls"
```

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
func CertPoolFromPEM (pemData []byte)                   (*x509.CertPool, error)
func CertPoolFromFile(path string)                      (*x509.CertPool, error)
func FromFiles       (certFile, keyFile, caFile string) (*tls.Config,   error)
func FromPEM         (certPEM,  keyPEM,  caPEM  string) (*tls.Config,   error)
func VerifyPeerChain (roots *x509.CertPool, cs tls.ConnectionState) error
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
`CertPoolFromFile(path)` is the path-taking variant — reads the PEM
file and rejects bundles with zero certificates so a typo'd path
doesn't silently disable trust.

`VerifyPeerChain` runs chain + hostname verification of a peer against a
root pool (roots as anchors, intermediates from the rest of the peer
chain, SNI as the DNS name). Standalone it's a one-shot check; it's also
the verification primitive the hot-reload loaders in `tls/reloader` pair
with `InsecureSkipVerify` to verify against a live, swappable pool.

### tls/reloader — hot-reload loaders + multi-pool orchestrator

```go
import "github.com/abagile/tokyo3-base/tls/reloader"
```

Everything stateful: TLS material that rotates under a running process
without a restart. Three tiers, low to high — the loaders, the
single-pool client shortcut, and the named multi-pool orchestrator.

#### CertLoader / CALoader — the reloading primitives

```go
type CertLoader struct {
    OnSwap  func(cert *tls.Certificate, mtime time.Time)  // optional observation hooks
    OnError func(err error)
    /* ... */
}

func NewCertLoader(certFile, keyFile string) *CertLoader
func (c *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error)        // server side
func (c *CertLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) // client side
func (c *CertLoader) Reload() error                                                          // forced, bypasses the mtime gate

type CALoader struct {
    OnSwap  func(raw []byte, mtime time.Time)  // raw PEM, for fingerprinting
    OnError func(err error)
    /* ... */
}

func NewCALoader(caFile string) *CALoader
func (l *CALoader) Pool() (*x509.CertPool, error)
func (l *CALoader) VerifyConnection(cs tls.ConnectionState) error
```

`CertLoader.GetCertificate` slots into `tls.Config.GetCertificate` (server)
and `GetClientCertificate` into `tls.Config.GetClientCertificate` (client);
both share one stat-and-reload path. On every handshake the loader
stat-checks the cert file; if the mtime has advanced it reloads the pair
and serves the new cert from then on. Concurrent stale callers are coalesced
through a double-checked write lock. When a reload fails (e.g. cert written,
key not yet during a rotation) the previously cached cert is returned so
in-flight handshakes are unaffected. `Reload()` re-reads regardless of mtime
— for rotators whose write may not advance the mtime past the cached value
(same-second coalescing).

`CALoader` is the trust-side sibling: wire `VerifyConnection` into
`tls.Config.VerifyConnection` (with `InsecureSkipVerify`, since the standard
verifier freezes `RootCAs` at construction) so a CA bundle dropped in place
is honored on the next handshake. The `OnSwap`/`OnError` hooks on both are
observation seams the `Reloader` orchestrator uses for swap/failure logging;
a failed re-read keeps the previous cert/pool live so a corrupt drop-in
never opens a trust window.

```go
// server cert that cert-manager / SPIFFE / ACME rotates in place:
loader := reloader.NewCertLoader("/etc/tls/server.crt", "/etc/tls/server.key")
srv := &http.Server{
    Addr:      ":443",
    TLSConfig: &tls.Config{GetCertificate: loader.GetCertificate},
}
srv.ListenAndServeTLS("", "")  // empty paths — cert comes from GetCertificate
```

#### ClientConfig — single-pool rotation-safe mTLS client config

```go
func ClientConfig(certFile, keyFile, caFile string) (*tls.Config, error)
```

`tls.FromFiles` loads the leaf into `tls.Config.Certificates` **once** at
build time — fine for a long-lived server cert, but a trap for a *client*
whose short-TTL workload cert is rotated in place: the connection keeps
presenting the boot-time copy and breaks on the first reconnect after it
expires. `ClientConfig` closes that gap by composing the two loaders — the
leaf reloads per handshake via `CertLoader.GetClientCertificate`, and the CA
pool re-reads on mtime change via `CALoader.VerifyConnection` (the config
carries `InsecureSkipVerify`; verification runs against the live pool). A
failed re-read keeps the previous pool live. `certFile`/`keyFile` are
required and eagerly loaded so a bad path fails the call rather than the
first silent handshake; `caFile` is optional (empty ⇒ system roots,
standard verification).

```go
// e.g. a NATS log/audit client whose cert cert-agentd rotates every ~10 min
cfg, err := reloader.ClientConfig(
    "/certs/workload.crt",
    "/certs/workload.key",
    "/certs/ca.crt",
)
if err != nil { /* ... */ }
nc, err := nats.Connect(url, nats.Secure(cfg))
```

The `applog` NATS shipping helper drives this for you whenever
`NATSConfig.CertFile`/`KeyFile` are set; reach for `ClientConfig` directly
when wiring a bespoke long-lived single-pool mTLS client. For named
multi-pool trust, expiry telemetry, and poll/refresh disciplines, use the
`Reloader` orchestrator below.

#### ClientTLS — optional-client-cert config builder

```go
func ClientTLS(certFile, keyFile, caFile string) (*tls.Config, error)
```

The "optional client cert" companion to `ClientConfig`, for a client that
*may or may not* present a cert (Postgres, a SCIM endpoint, …):

- a full cert+key pair ⇒ `ClientConfig` (hot-reloading mTLS — leaf per
  handshake, CA pool on mtime);
- no pair ⇒ `btls.FromFiles` — a one-shot config that **still verifies the
  server against `caFile` when one is set** (fail-secure: an operator who
  configures a CA gets server verification regardless of whether a client cert
  is also present), or `(nil, nil)` when nothing is configured so the caller
  falls back to the DSN's `sslmode` / plaintext.

Reach for `ClientConfig` directly when the client cert is mandatory, and
`btls.FromFiles` for an always-one-shot config (e.g. a short-lived migration
connection that closes before any rotation matters).

#### ServerTLS — server-side HTTPS config builder

```go
type ServerTLSConfig struct {
    CertFile, KeyFile string             // server leaf; both empty ⇒ self-signed dev fallback
    ClientCAFile      string             // optional inbound mTLS client-CA bundle
    ClientAuth        tls.ClientAuthType // applied when ClientCAFile set; 0 ⇒ VerifyClientCertIfGiven
    MinVersion        uint16             // 0 ⇒ Go default
    Log               *slog.Logger
}

func ServerTLS(cfg ServerTLSConfig) (*tls.Config, error)
```

The server-side sibling of `ClientConfig` — the `*tls.Config` an HTTPS
listener needs. A cert+key pair wires a hot-reloading `CertLoader`
(`GetCertificate`); both empty falls back to an ephemeral
[`SelfSignedCert`](#selfsignedcert--ephemeral-dev-fallback) (dev, logged as a
warning). An optional `ClientCAFile` wires hot-reloading inbound mTLS via
`NewClientCALoader` — the bundle re-reads mtime-gated with keep-last-good, so
a client-CA rotation (widen→narrow) lands without a restart. Each daemon
previously carried a near-identical `buildServerTLS`; they now differ only in
the env-var names and workload-CA fallback they resolve before calling.

```go
tlsCfg, err := reloader.ServerTLS(reloader.ServerTLSConfig{
    CertFile:     os.Getenv("CERTD_API_CERT"),
    KeyFile:      os.Getenv("CERTD_API_KEY"),
    ClientCAFile: envutil.First("CERTD_API_CLIENT_CA", "CERTD_WORKLOAD_CA"),
    MinVersion:   tls.VersionTLS12,
    Log:          log,
})
if err != nil { /* ... */ }
srv := &http.Server{Addr: addr, TLSConfig: tlsCfg, Handler: routes}
srv.ListenAndServeTLS("", "")  // empty paths — cert comes from TLSConfig
```

#### Reloader — named multi-pool orchestrator

For **client-side** mTLS where the workload cert+key and one or more CA
trust pools rotate from under a running daemon — typical of cert-agentd
renewing its own SPIFFE cert in-process, or ssh-tunneld picking up an
external rotator's drop-in.

```go
type Config struct {
    CertPath, KeyPath string
    Pools             map[string]string  // name → CA bundle path
    PollCert          bool               // true ⇒ also mtime-poll cert+key
    Log               *slog.Logger
}

type Reloader struct { /* ... */ }

func New(cfg Config) (*Reloader, error)
func (r *Reloader) Refresh() error                                       // explicit cert re-read
func (r *Reloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
func (r *Reloader) LeafExpiry() time.Time                                // leaf cert NotAfter
func (r *Reloader) TLSConfig(poolName string, opts ...TLSConfigOption) *tls.Config
func (r *Reloader) RunPoll(ctx context.Context, interval time.Duration) error
func (r *Reloader) VerifyConnection(poolName string) func(tls.ConnectionState) error

func WithServerName(name string) TLSConfigOption
```

`Reloader.TLSConfig(poolName)` returns a `*tls.Config` whose
`GetClientCertificate` and `VerifyConnection` callbacks read live in-memory
state — rotated material applies on the next TLS handshake without
rebuilding the http.Client. `InsecureSkipVerify: true` is set on purpose;
the standard verifier freezes `RootCAs` at config-construction, so
hot-reload uses `VerifyConnection` against a per-handshake pool snapshot
instead.

The mechanics are the primitives above — one `CertLoader` for the pair,
one `CALoader` per file-backed pool — so material whose file mtime has
advanced is also picked up lazily at the next handshake, with swap and
failure logging wired through the loaders' `OnSwap`/`OnError` hooks. On
top of that, two refresh disciplines, picked per use case:

- **Explicit refresh** (`PollCert: false`): caller invokes `r.Refresh()`
  from wherever a new cert lands — typically a renewer's `OnRenewed`
  callback. Suits binaries that mint their own certs in-process;
  `Refresh` bypasses the mtime gate, covering same-second writes that
  per-handshake pickup would miss.
- **mtime polling** (`PollCert: true`): `RunPoll` probes the cert+key
  files' mtimes on a fixed cadence. Suits binaries whose cert is
  rotated by an external agent; the poll bounds how long a rotation
  waits for the next handshake and gives failures a warn cadence.

CA pools are always mtime-probed by `RunPoll` regardless of `PollCert` —
they don't have a single explicit-refresh trigger like the cert+key pair
does. Each pool is registered with a caller-chosen name in `Config.Pools`
(`"ca"`, `"proxy"`, `"certd"`, …); the same name flows through
`TLSConfig(name)` to address per-pool tls.Configs from one Reloader.

An empty path in `Config.Pools` is a sentinel for "load from
`x509.SystemCertPool()`" — useful for dev paths that connect to a
public-CA-signed endpoint without pinning trust. System pools are
snapshot at construction; they can't be hot-reloaded and `RunPoll`
skips them silently:

```go
r, _ := reloader.New(reloader.Config{
    CertPath: certPath, KeyPath: keyPath,
    Pools: map[string]string{
        "ca": os.Getenv("CERTD_CA_BUNDLE"),  // "" → OS trust store
    },
    PollCert: true,
    Log:      log,
})
```

```go
// single-pool, explicit-refresh (cert-agentd pattern):
r, _ := reloader.New(reloader.Config{
    CertPath: "/etc/workload/cert.pem",
    KeyPath:  "/etc/workload/key.pem",
    Pools:    map[string]string{"ca": "/etc/workload/ca.pem"},
    Log:      log,
})
client, _ := certd.NewClient(certdURL, r.TLSConfig("ca"))
// after a successful renewal:
r.Refresh()
go func() { errCh <- r.RunPoll(ctx, reloader.DefaultPollInterval) }()

// multi-pool, passive mtime pickup (ssh-tunneld pattern):
r, _ := reloader.New(reloader.Config{
    CertPath: certPath, KeyPath: keyPath,
    Pools: map[string]string{
        "proxy": proxyCAPath,
        "certd": certdCAPath,
    },
    PollCert: true,
    Log:      log,
})
proxyTLS := r.TLSConfig("proxy", reloader.WithServerName("proxy.internal"))
certdTLS := r.TLSConfig("certd")
go func() { errCh <- r.RunPoll(ctx, reloader.DefaultPollInterval) }()
```

`RunPoll` blocks until ctx cancel — the caller owns the goroutine lifecycle
(matches `http.Server.ListenAndServe`'s discipline). Read failures during
RunPoll keep the previous in-memory state live and emit a warn log so a
corrupt drop-in never opens a trust window.

#### Expiry helpers

```go
func (r *Reloader) WarnIfNearExpiry(threshold time.Duration, msg string)
func (r *Reloader) ExpiryAttrs(attrName string) func() []any
```

`WarnIfNearExpiry` emits a single startup-time Warn on the reloader's
logger when the leaf cert is within `threshold` of expiry (typical
threshold: `24*time.Hour`). The line carries `remaining` and
`not_after` structured attrs so alerting rules can fire on either
field without parsing message text. No-op until the cert has loaded.

`ExpiryAttrs(attrName)` returns a closure that yields
`[attrName, time-until-leaf-expiry-rounded-to-seconds]` on every
call — the shape that retry-surface error-attrs hooks like
`revcheck.Config.RefreshErrorAttrs`, `hostcert.Config.SignErrorAttrs`,
and `renew.Config.SignErrorAttrs` want. Operators grep one
consistent attr across every retry surface to see cert exhaustion
approaching.

```go
r.WarnIfNearExpiry(24*time.Hour, "workload mTLS cert near expiry")

renewer, _ := renew.New(renew.Config{
    SignErrorAttrs: r.ExpiryAttrs("mtls_cert_remaining"),
    // ...
})
```

Pairs with `tls.CertLoader` above on the **server** side; together they
cover both directions of hot-reload for daemons that act as both client and
server.

[↑ Back to top](#packages)

---

## version/ — build version resolution

```go
import "github.com/abagile/tokyo3-base/version"

func Resolve(injected string) string
```

Maps an ldflags-injected `main.Version` to an effective version string,
falling back to `runtime/debug.BuildInfo` so `go install …@vX.Y.Z` and
source-tree builds still report something useful without a Make-driven
inject. Keep `var Version = "dev"` in `main` (the linker target stays
`main.Version`) and call `version.Resolve(Version)`.

Resolution order:

1. `injected`, when the linker set it to anything other than `"dev"`.
2. `BuildInfo.Main.Version` when it's a real module version (e.g.
   `v1.2.3`) — what `go install pkg@vX.Y.Z` records.
3. `dev-<vcs.revision[:7]>[-dirty] (<vcs.time>)` from the VCS settings the
   toolchain stamps into source-tree builds; the commit time is appended
   when present, rendered in the local time zone.
4. `"dev"` — last resort (e.g. `go run` outside a module).

```go
var Version = "dev" // -ldflags "-X main.Version=v1.2.3"
fmt.Printf("%s %s\n", appName, version.Resolve(Version))
// tagged install → "v1.2.3"
// local build    → "dev-1a2b3c4 (2026-05-31T17:30:00+08:00)"
```

> A Docker image built from a source copy with no `.git` and no ldflags
> reports `"dev"` — stamp the tag via a `VERSION` build-arg + `-X
> main.Version` so released images carry their version.

[↑ Back to top](#packages)
