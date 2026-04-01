package domain

import "time"

// Session represents an active authentication session.
type Session struct {
	UserID    string
	TokenUse  string // "access" or "id"
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionHistory tracks login activity for a user.
type SessionHistory struct {
	UserID      string
	LastLoginAt *time.Time
	LoginCount  int
}

// RecordLogin updates the session history with a new login.
func (h *SessionHistory) RecordLogin() {
	now := time.Now()
	h.LastLoginAt = &now
	h.LoginCount++
}

// IsInactive checks if the user hasn't logged in within the given duration.
func (h *SessionHistory) IsInactive(threshold time.Duration) bool {
	if h.LastLoginAt == nil {
		return true
	}
	return time.Since(*h.LastLoginAt) > threshold
}
