// Package creds handles password hashing and opaque token generation —
// the per-credential primitives every auth-shaped tool needs. Sits
// under the auth/ namespace alongside other auth primitives
// (auth/oidcclient, auth/awsclaims, auth/jwt).
//
// Stdlib + golang.org/x/crypto only, no external auth-server
// dependencies, so any tool can pull it without dragging in HTTP
// handlers or storage.
package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the work factor passed to bcrypt.GenerateFromPassword
// on every HashPassword call. Default 12 (~250ms on modern hardware)
// — the OWASP-recommended starting point for bcrypt as of 2024;
// revisit periodically as hardware improves.
//
// Exposed as a mutable package var (rather than a constant or a
// per-call argument) so test suites can drop the cost during init —
// e.g. `func init() { creds.BcryptCost = bcrypt.MinCost }` — and
// reclaim the ~250ms per hash that otherwise dominates suite runtime.
//
// Set once at program init / TestMain. Not safe for concurrent
// mutation alongside HashPassword calls. Range is bcrypt.MinCost (4)
// through bcrypt.MaxCost (31); the bcrypt library returns an error
// for out-of-range values, so no separate validation is needed here.
var BcryptCost = 12

// HashPassword bcrypts a plaintext password at BcryptCost. The
// returned string includes the algorithm version, cost, and salt, so
// it round-trips through CheckPassword without storing any of those
// separately.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword returns true iff password matches a previously
// HashPassword'd value. Constant-time within bcrypt's compare; safe
// against timing attacks on the digest.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// GenerateRawToken returns a cryptographically random 32-byte hex
// string (64 chars). Used as the source-of-truth for opaque bearer
// tokens, refresh tokens, and any short-lived random secret — the
// caller is expected to HashToken before storage.
func GenerateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a raw token. Pair with
// GenerateRawToken: emit the raw value to the user, store only the
// hash. Lookups hash the presented credential and compare against the
// stored digest, so a database leak doesn't expose the live token.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
