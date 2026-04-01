package domain

import "time"

// AuditEventType represents the type of lifecycle event.
type AuditEventType string

const (
	AuditSignUp       AuditEventType = "signup"
	AuditConfirm      AuditEventType = "confirm"
	AuditLogin        AuditEventType = "login"
	AuditSuspend      AuditEventType = "suspend"
	AuditReactivate   AuditEventType = "reactivate"
	AuditDelete       AuditEventType = "delete"
	AuditRoleAdd      AuditEventType = "role_add"
	AuditRoleRemove   AuditEventType = "role_remove"
	AuditPasswordReset AuditEventType = "password_reset"
)

// AuditEvent records a lifecycle state change.
type AuditEvent struct {
	ID        string
	UserID    string
	EventType AuditEventType
	Actor     string // who performed the action (admin user ID or "system")
	Detail    string // additional context (e.g., reason, role name)
	Timestamp time.Time
}

// NewAuditEvent creates a new audit event.
func NewAuditEvent(userID string, eventType AuditEventType, actor, detail string) *AuditEvent {
	return &AuditEvent{
		UserID:    userID,
		EventType: eventType,
		Actor:     actor,
		Detail:    detail,
		Timestamp: time.Now(),
	}
}

// AuditLog is a collection of audit events for a user.
type AuditLog struct {
	UserID string
	Events []AuditEvent
}

// Append adds an event to the log.
func (l *AuditLog) Append(event *AuditEvent) {
	l.Events = append(l.Events, *event)
}

// Latest returns the most recent N events.
func (l *AuditLog) Latest(n int) []AuditEvent {
	if len(l.Events) <= n {
		return l.Events
	}
	return l.Events[len(l.Events)-n:]
}
