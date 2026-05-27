// Package awsclaims defines the JWT claim shapes AWS STS recognises during
// sts:AssumeRoleWithWebIdentity. Sits under the auth/ namespace alongside
// other auth primitives (auth/oidcclient, auth/creds, auth/jwt).
//
// This package is deliberately dependency-light — it imports only the Go
// standard library — so that lightweight tooling (CLI helpers that mint
// or validate federation tokens) can reuse it without pulling in any
// auth-server backend, AWS SDK, or audit pipeline. The JWT signer at
// auth/jwt and any future tooling share the constants and types declared
// here, keeping a single source of truth for the wire format.
//
// AWS documents the claim at:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
package awsclaims

// PrincipalTagsClaim is the JWT claim name AWS STS reads when minting a
// session via sts:AssumeRoleWithWebIdentity. The claim name is fixed by
// AWS and must appear verbatim in the JWT; STS ignores any other claim
// name regardless of payload shape. Each key inside the value's
// principal_tags map surfaces in the resulting STS session as
// `aws:PrincipalTag/<key>` for policy evaluation.
const PrincipalTagsClaim = "https://aws.amazon.com/tags"

// PrincipalTagsValue is the inner shape of the AWS tags claim. The
// JSON encoding is fixed by AWS — field names are snake_case and
// principal_tags values must be list-of-strings (AWS honours the first
// element today; the list shape is retained for forward compatibility).
//
// TransitiveTagKeys names keys that persist through subsequent
// sts:AssumeRole chain calls — federation sessions rarely chain, but
// marking all keys transitive keeps audit semantics consistent across
// any chaining a downstream service might perform.
type PrincipalTagsValue struct {
	PrincipalTags     map[string][]string `json:"principal_tags"`
	TransitiveTagKeys []string            `json:"transitive_tag_keys"`
}
