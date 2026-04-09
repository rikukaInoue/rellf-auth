package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuthCodePayload contains the data embedded in a stateless authorization code.
type AuthCodePayload struct {
	Sub                 string   `json:"sub"`
	Email               string   `json:"email"`
	Groups              []string `json:"groups,omitempty"`
	ClientID            string   `json:"cid"`
	RedirectURI         string   `json:"ruri"`
	Scopes              []string `json:"scp"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"cc,omitempty"`
	CodeChallengeMethod string   `json:"ccm,omitempty"`
	ExpiresAt           int64    `json:"exp"`
	AuthTime            int64    `json:"auth_time,omitempty"`
	AMR                 []string `json:"amr,omitempty"`
}

// AuthCodeCodec encodes/decodes stateless authorization codes using AES-GCM.
type AuthCodeCodec struct {
	aead cipher.AEAD
}

// NewAuthCodeCodec creates a codec from a hex-encoded AES-256 key (64 hex chars = 32 bytes).
func NewAuthCodeCodec(keyHex string) (*AuthCodeCodec, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid auth code key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("auth code key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &AuthCodeCodec{aead: aead}, nil
}

// Encode encrypts the payload into a base64url-encoded authorization code.
func (c *AuthCodeCodec) Encode(payload *AuthCodePayload) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth code payload: %w", err)
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decode decrypts a base64url-encoded authorization code and validates its expiration.
func (c *AuthCodeCodec) Decode(code string) (*AuthCodePayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("invalid auth code encoding: %w", err)
	}

	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("auth code too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth code: %w", err)
	}

	var payload AuthCodePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth code payload: %w", err)
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("auth code expired")
	}

	return &payload, nil
}
