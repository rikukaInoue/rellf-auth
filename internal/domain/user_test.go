package domain

import (
	"testing"
	"time"
)

func TestPendingUser_Confirm(t *testing.T) {
	pending := &PendingUser{
		ID:        "user-1",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
	}

	if pending.UserStatus() != StatusPending {
		t.Errorf("expected pending, got %s", pending.UserStatus())
	}

	active := pending.Confirm()

	if active.UserStatus() != StatusActive {
		t.Errorf("expected active, got %s", active.UserStatus())
	}
	if active.ID != "user-1" {
		t.Errorf("expected user-1, got %s", active.ID)
	}
	if len(active.Groups) != 0 {
		t.Errorf("expected empty groups, got %v", active.Groups)
	}
}

func TestActiveUser_Suspend(t *testing.T) {
	active := &ActiveUser{
		ID:     "user-1",
		Email:  "test@example.com",
		Groups: []string{"lawyer", "site:editor"},
	}

	suspended := active.Suspend("inactive 90 days")

	if suspended.UserStatus() != StatusSuspended {
		t.Errorf("expected suspended, got %s", suspended.UserStatus())
	}
	if suspended.Reason != "inactive 90 days" {
		t.Errorf("expected reason, got %s", suspended.Reason)
	}
	if len(suspended.Groups) != 2 {
		t.Errorf("expected groups preserved, got %v", suspended.Groups)
	}
}

func TestSuspendedUser_Reactivate(t *testing.T) {
	suspended := &SuspendedUser{
		ID:     "user-1",
		Email:  "test@example.com",
		Groups: []string{"lawyer"},
		Reason: "test",
	}

	active := suspended.Reactivate()

	if active.UserStatus() != StatusActive {
		t.Errorf("expected active, got %s", active.UserStatus())
	}
	if len(active.Groups) != 1 || active.Groups[0] != "lawyer" {
		t.Errorf("expected groups preserved, got %v", active.Groups)
	}
}

func TestActiveUser_Delete(t *testing.T) {
	active := &ActiveUser{
		ID:    "user-1",
		Email: "test@example.com",
	}

	deleted := active.Delete("退職")

	if deleted.UserStatus() != StatusDeleted {
		t.Errorf("expected deleted, got %s", deleted.UserStatus())
	}
	if deleted.Reason != "退職" {
		t.Errorf("expected reason, got %s", deleted.Reason)
	}
}

func TestDeletedUser_IsTerminal(t *testing.T) {
	deleted := &DeletedUser{
		ID:    "user-1",
		Email: "test@example.com",
	}

	// DeletedUser has no transition methods — this is enforced at compile time.
	// We just verify it satisfies the User interface.
	var u User = deleted
	if u.UserStatus() != StatusDeleted {
		t.Errorf("expected deleted, got %s", u.UserStatus())
	}
}

func TestFromCognito(t *testing.T) {
	now := time.Now()

	tests := []struct {
		status   string
		expected UserStatus
	}{
		{"pending", StatusPending},
		{"active", StatusActive},
		{"suspended", StatusSuspended},
		{"deleted", StatusDeleted},
	}

	for _, tt := range tests {
		u, err := FromCognito("id", "email", tt.status, nil, now, nil, "")
		if err != nil {
			t.Errorf("unexpected error for %s: %v", tt.status, err)
		}
		if u.UserStatus() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, u.UserStatus())
		}
	}

	_, err := FromCognito("id", "email", "unknown", nil, now, nil, "")
	if err == nil {
		t.Error("expected error for unknown status")
	}
}
