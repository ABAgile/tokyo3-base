package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK is a JSON Web Key (RFC 7517) for an RSA public key.
type JWK struct {
	KTY string `json:"kty"`
	USE string `json:"use"`
	ALG string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set returned at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWK converts an RSA public key + KID into the JWK shape
// RPs consume from /.well-known/jwks.json. The caller assembles a
// JWKS by collecting JWKs from every active key in its keystore —
// this package doesn't know about storage.
func PublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		KTY: "RSA",
		USE: "sig",
		ALG: "RS256",
		KID: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
