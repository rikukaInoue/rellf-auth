package domain

import (
	"fmt"
	"time"
)

type UserStatus string

const (
	StatusPending   UserStatus = "pending"
	StatusActive    UserStatus = "active"
	StatusSuspended UserStatus = "suspended"
	StatusDeleted   UserStatus = "deleted"
)

// User is the read-only interface for querying users across all states.
type User interface {
	UserID() string
	UserEmail() string
	UserStatus() UserStatus
	UserCreatedAt() time.Time
}

// PendingUser represents a user who has signed up but not yet confirmed.
// Can only be confirmed.
type PendingUser struct {
	ID        string
	Email     string
	CreatedAt time.Time
}

func (u *PendingUser) UserID() string          { return u.ID }
func (u *PendingUser) UserEmail() string       { return u.Email }
func (u *PendingUser) UserStatus() UserStatus  { return StatusPending }
func (u *PendingUser) UserCreatedAt() time.Time { return u.CreatedAt }

func (u *PendingUser) Confirm() *ActiveUser {
	return &ActiveUser{
		ID:          u.ID,
		Email:       u.Email,
		Groups:      []string{},
		ActivatedAt: time.Now(),
		CreatedAt:   u.CreatedAt,
	}
}

// ActiveUser represents a confirmed, active user.
// Can be suspended, deleted, or have groups updated.
type ActiveUser struct {
	ID          string
	Email       string
	Groups      []string
	LastLoginAt *time.Time
	ActivatedAt time.Time
	CreatedAt   time.Time
}

func (u *ActiveUser) UserID() string          { return u.ID }
func (u *ActiveUser) UserEmail() string       { return u.Email }
func (u *ActiveUser) UserStatus() UserStatus  { return StatusActive }
func (u *ActiveUser) UserCreatedAt() time.Time { return u.CreatedAt }

func (u *ActiveUser) Suspend(reason string) *SuspendedUser {
	return &SuspendedUser{
		ID:          u.ID,
		Email:       u.Email,
		Groups:      u.Groups,
		SuspendedAt: time.Now(),
		Reason:      reason,
		CreatedAt:   u.CreatedAt,
	}
}

func (u *ActiveUser) Delete(reason string) *DeletedUser {
	return &DeletedUser{
		ID:        u.ID,
		Email:     u.Email,
		DeletedAt: time.Now(),
		Reason:    reason,
		CreatedAt: u.CreatedAt,
	}
}

func (u *ActiveUser) UpdateGroups(groups []string) *ActiveUser {
	u.Groups = groups
	return u
}

func (u *ActiveUser) RecordLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}

// SuspendedUser represents a temporarily disabled user.
// Can be reactivated or deleted.
type SuspendedUser struct {
	ID          string
	Email       string
	Groups      []string
	SuspendedAt time.Time
	Reason      string
	CreatedAt   time.Time
}

func (u *SuspendedUser) UserID() string          { return u.ID }
func (u *SuspendedUser) UserEmail() string       { return u.Email }
func (u *SuspendedUser) UserStatus() UserStatus  { return StatusSuspended }
func (u *SuspendedUser) UserCreatedAt() time.Time { return u.CreatedAt }

func (u *SuspendedUser) Reactivate() *ActiveUser {
	return &ActiveUser{
		ID:          u.ID,
		Email:       u.Email,
		Groups:      u.Groups,
		ActivatedAt: time.Now(),
		CreatedAt:   u.CreatedAt,
	}
}

func (u *SuspendedUser) Delete(reason string) *DeletedUser {
	return &DeletedUser{
		ID:        u.ID,
		Email:     u.Email,
		DeletedAt: time.Now(),
		Reason:    reason,
		CreatedAt: u.CreatedAt,
	}
}

// DeletedUser represents a permanently removed user.
// No operations available — terminal state.
type DeletedUser struct {
	ID        string
	Email     string
	DeletedAt time.Time
	Reason    string
	CreatedAt time.Time
}

func (u *DeletedUser) UserID() string          { return u.ID }
func (u *DeletedUser) UserEmail() string       { return u.Email }
func (u *DeletedUser) UserStatus() UserStatus  { return StatusDeleted }
func (u *DeletedUser) UserCreatedAt() time.Time { return u.CreatedAt }

// FromCognito reconstructs the appropriate User type from Cognito data.
func FromCognito(id, email, status string, groups []string, createdAt time.Time, suspendedAt *time.Time, suspendReason string) (User, error) {
	switch UserStatus(status) {
	case StatusPending:
		return &PendingUser{
			ID:        id,
			Email:     email,
			CreatedAt: createdAt,
		}, nil
	case StatusActive:
		return &ActiveUser{
			ID:          id,
			Email:       email,
			Groups:      groups,
			ActivatedAt: createdAt,
			CreatedAt:   createdAt,
		}, nil
	case StatusSuspended:
		su := &SuspendedUser{
			ID:        id,
			Email:     email,
			Groups:    groups,
			Reason:    suspendReason,
			CreatedAt: createdAt,
		}
		if suspendedAt != nil {
			su.SuspendedAt = *suspendedAt
		}
		return su, nil
	case StatusDeleted:
		return &DeletedUser{
			ID:        id,
			Email:     email,
			CreatedAt: createdAt,
		}, nil
	default:
		return nil, fmt.Errorf("unknown user status: %s", status)
	}
}
