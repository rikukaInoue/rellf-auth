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

const DefaultRefreshTokenTTL = 7 * 24 * time.Hour

type RefreshTokenPayload struct {
	Sub       string   `json:"sub"`
	Email     string   `json:"email"`
	Groups    []string `json:"groups,omitempty"`
	ClientID  string   `json:"cid"`
	Scopes    []string `json:"scp"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
}

type RefreshTokenCodec struct {
	aead cipher.AEAD
}

func NewRefreshTokenCodec(keyHex string) (*RefreshTokenCodec, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("refresh token key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &RefreshTokenCodec{aead: aead}, nil
}

func (c *RefreshTokenCodec) Encode(payload *RefreshTokenPayload) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token payload: %w", err)
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (c *RefreshTokenCodec) Decode(token string) (*RefreshTokenPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token encoding: %w", err)
	}

	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("refresh token too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	var payload RefreshTokenPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token payload: %w", err)
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("refresh token expired")
	}

	return &payload, nil
}

func (c *RefreshTokenCodec) Issue(sub, email string, groups []string, clientID string, scopes []string) (string, error) {
	now := time.Now()
	payload := &RefreshTokenPayload{
		Sub:       sub,
		Email:     email,
		Groups:    groups,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: now.Add(DefaultRefreshTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
	}
	return c.Encode(payload)
}
