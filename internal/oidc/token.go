package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenIssuer signs JWTs using an RSA private key.
type TokenIssuer struct {
	privateKey jwk.Key
	issuer     string
	publicJWKS jwk.Set
}

// NewTokenIssuer creates a TokenIssuer from a PEM-encoded RSA private key.
func NewTokenIssuer(privateKeyPEM, keyID, issuer string) (*TokenIssuer, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := jwk.ParseKey(block.Bytes, jwk.WithPEM(true))
	if err != nil {
		// Try parsing the raw PEM string directly
		privKey, err = jwk.ParseKey([]byte(privateKeyPEM), jwk.WithPEM(true))
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	}

	if err := privKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, err
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	pubSet := jwk.NewSet()
	if err := pubSet.AddKey(pubKey); err != nil {
		return nil, err
	}

	return &TokenIssuer{
		privateKey: privKey,
		issuer:     issuer,
		publicJWKS: pubSet,
	}, nil
}

// NewLocalTokenIssuer generates an ephemeral RSA key for local development.
func NewLocalTokenIssuer(issuer string) (*TokenIssuer, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privKey, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from RSA key: %w", err)
	}

	if err := privKey.Set(jwk.KeyIDKey, "local-key-1"); err != nil {
		return nil, err
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	pubSet := jwk.NewSet()
	if err := pubSet.AddKey(pubKey); err != nil {
		return nil, err
	}

	return &TokenIssuer{
		privateKey: privKey,
		issuer:     issuer,
		publicJWKS: pubSet,
	}, nil
}

// SignIDToken creates a signed OIDC ID Token.
func (ti *TokenIssuer) SignIDToken(sub, email string, groups []string, aud, nonce string) (string, error) {
	now := time.Now()

	builder := jwt.NewBuilder().
		Issuer(ti.issuer).
		Subject(sub).
		Audience([]string{aud}).
		IssuedAt(now).
		Expiration(now.Add(1 * time.Hour)).
		Claim("email", email).
		Claim("email_verified", true)

	if nonce != "" {
		builder = builder.Claim("nonce", nonce)
	}
	if len(groups) > 0 {
		builder = builder.Claim("groups", groups)
	}

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build ID token: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, ti.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return string(signed), nil
}

// SignAccessToken creates a signed access token.
func (ti *TokenIssuer) SignAccessToken(sub string, scopes []string, aud string) (string, error) {
	now := time.Now()

	token, err := jwt.NewBuilder().
		Issuer(ti.issuer).
		Subject(sub).
		Audience([]string{aud}).
		IssuedAt(now).
		Expiration(now.Add(1 * time.Hour)).
		Claim("scope", scopes).
		Claim("token_use", "access").
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build access token: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, ti.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return string(signed), nil
}

// JWKS returns the public key set for the JWKS endpoint.
func (ti *TokenIssuer) JWKS() jwk.Set {
	return ti.publicJWKS
}

// Issuer returns the issuer URL.
func (ti *TokenIssuer) Issuer() string {
	return ti.issuer
}
