package domain

import "time"

// RoleAssignment represents a user's membership in a group/role.
type RoleAssignment struct {
	UserID    string
	Role      string
	AssignedAt time.Time
}

// RoleSet manages a user's current roles.
type RoleSet struct {
	UserID      string
	Assignments []RoleAssignment
}

// NewRoleSet creates a RoleSet from a list of role names.
func NewRoleSet(userID string, roles []string) *RoleSet {
	assignments := make([]RoleAssignment, len(roles))
	for i, r := range roles {
		assignments[i] = RoleAssignment{
			UserID: userID,
			Role:   r,
		}
	}
	return &RoleSet{
		UserID:      userID,
		Assignments: assignments,
	}
}

// Roles returns the current role names.
func (rs *RoleSet) Roles() []string {
	roles := make([]string, len(rs.Assignments))
	for i, a := range rs.Assignments {
		roles[i] = a.Role
	}
	return roles
}

// HasRole checks if the user has a specific role.
func (rs *RoleSet) HasRole(role string) bool {
	for _, a := range rs.Assignments {
		if a.Role == role {
			return true
		}
	}
	return false
}

// Add adds a role. Returns false if already assigned.
func (rs *RoleSet) Add(role string) bool {
	if rs.HasRole(role) {
		return false
	}
	rs.Assignments = append(rs.Assignments, RoleAssignment{
		UserID:     rs.UserID,
		Role:       role,
		AssignedAt: time.Now(),
	})
	return true
}

// Remove removes a role. Returns false if not assigned.
func (rs *RoleSet) Remove(role string) bool {
	for i, a := range rs.Assignments {
		if a.Role == role {
			rs.Assignments = append(rs.Assignments[:i], rs.Assignments[i+1:]...)
			return true
		}
	}
	return false
}
