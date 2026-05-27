package awsclaims_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/auth/awsclaims"
)

// TestPrincipalTagsClaim_ExactString pins the claim name AWS expects.
// STS rejects any other claim name silently — losing the "https://"
// prefix or trailing the path with a slash means session tags simply
// don't propagate. Tested as a literal so an accidental edit raises a
// build-time failure.
func TestPrincipalTagsClaim_ExactString(t *testing.T) {
	const want = "https://aws.amazon.com/tags"
	if awsclaims.PrincipalTagsClaim != want {
		t.Errorf("PrincipalTagsClaim = %q, want %q", awsclaims.PrincipalTagsClaim, want)
	}
}

// TestPrincipalTagsValue_WireShape verifies the JSON encoding matches
// what AWS STS reads on sts:AssumeRoleWithWebIdentity. Field names
// must be snake_case; principal_tags values must be list-of-strings
// (not bare strings); transitive_tag_keys is a plain list of names.
//
// This is the entire load-bearing contract — anything that munges the
// keys or flattens the value lists breaks AWS-side tag propagation.
func TestPrincipalTagsValue_WireShape(t *testing.T) {
	v := awsclaims.PrincipalTagsValue{
		PrincipalTags: map[string][]string{
			"sub":  {"alice-uuid"},
			"team": {"platform"},
		},
		TransitiveTagKeys: []string{"sub", "team"},
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"principal_tags"`,
		`"transitive_tag_keys"`,
		`"sub":["alice-uuid"]`,
		`"team":["platform"]`,
		`"transitive_tag_keys":["sub","team"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in encoded form:\n  %s", want, got)
		}
	}

	// Round-trip: decode back and confirm both fields survive.
	var back awsclaims.PrincipalTagsValue
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(back.PrincipalTags) != 2 || back.PrincipalTags["sub"][0] != "alice-uuid" {
		t.Errorf("PrincipalTags round-trip lost data: %+v", back.PrincipalTags)
	}
	if len(back.TransitiveTagKeys) != 2 {
		t.Errorf("TransitiveTagKeys round-trip lost data: %+v", back.TransitiveTagKeys)
	}
}

// TestPrincipalTagsValue_EmptyOmitsNothing checks that even zero-value
// structs serialise without panicking. AWS will reject an empty tags
// claim at session creation, but the encoder shouldn't choke on it.
func TestPrincipalTagsValue_EmptyOmitsNothing(t *testing.T) {
	v := awsclaims.PrincipalTagsValue{}
	if _, err := json.Marshal(v); err != nil {
		t.Errorf("Marshal of zero value: %v", err)
	}
}
