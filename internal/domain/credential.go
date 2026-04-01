package domain

import "time"

// Credential represents a user's authentication state.
// Wraps Cognito password/MFA operations.
type Credential struct {
	UserID          string
	MFAEnabled      bool
	PasswordSetAt   *time.Time
	LastResetAt     *time.Time
	ResetRequired   bool
}

// PasswordReset records that a password reset was initiated.
func (c *Credential) PasswordReset() {
	now := time.Now()
	c.LastResetAt = &now
	c.ResetRequired = true
}

// PasswordConfirmed records that the user has set a new password.
func (c *Credential) PasswordConfirmed() {
	now := time.Now()
	c.PasswordSetAt = &now
	c.ResetRequired = false
}
