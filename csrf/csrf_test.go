package csrf

import "testing"

func TestTokenValidate(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	tok, err := Token(secret, "roles/new")
	if err != nil || tok == "" {
		t.Fatalf("Token: %q, %v", tok, err)
	}
	if !Validate(secret, tok, "roles/new") {
		t.Error("valid token rejected")
	}
	if Validate(secret, tok, "revocations") {
		t.Error("token accepted for a different scope")
	}
	if Validate(secret, tok+"x", "roles/new") {
		t.Error("tampered token accepted")
	}
	if Validate(secret, "", "roles/new") {
		t.Error("empty token accepted")
	}
	if Validate("", tok, "roles/new") {
		t.Error("empty secret accepted")
	}
	other, _ := NewSecret()
	if Validate(other, tok, "roles/new") {
		t.Error("token accepted under a different secret")
	}
}

func TestToken_MaskedPerCall(t *testing.T) {
	secret, _ := NewSecret()
	a, err1 := Token(secret, "s")
	b, err2 := Token(secret, "s")
	if err1 != nil || err2 != nil {
		t.Fatalf("Token: %v, %v", err1, err2)
	}
	if a == b {
		t.Error("wire token identical across calls — masking inactive (BREACH exposure)")
	}
	if !Validate(secret, a, "s") || !Validate(secret, b, "s") {
		t.Error("both issued tokens must remain valid")
	}
}

func TestToken_EmptySecretErrors(t *testing.T) {
	if _, err := Token("", "s"); err == nil {
		t.Error("want error minting a token over an empty secret")
	}
}

func TestValidate_RejectsMalformedToken(t *testing.T) {
	secret, _ := NewSecret()
	if Validate(secret, "short", "s") {
		t.Error("malformed token accepted")
	}
}
