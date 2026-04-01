package usecase

import (
	"context"
	"fmt"

	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/domain"
)

type UserUseCase struct {
	admin cognito.AdminService
}

func NewUserUseCase(admin cognito.AdminService) *UserUseCase {
	return &UserUseCase{admin: admin}
}

func (uc *UserUseCase) GetUser(ctx context.Context, username string) (domain.User, error) {
	detail, err := uc.admin.AdminGetUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("get user failed: %w", err)
	}
	return toDomainUser(detail), nil
}

func (uc *UserUseCase) ListUsers(ctx context.Context, filter string, limit int32, token *string) ([]domain.User, *string, error) {
	result, err := uc.admin.AdminListUsers(ctx, filter, limit, token)
	if err != nil {
		return nil, nil, fmt.Errorf("list users failed: %w", err)
	}

	users := make([]domain.User, len(result.Users))
	for i, u := range result.Users {
		users[i] = summaryToDomainUser(u)
	}

	return users, result.PaginationToken, nil
}

func (uc *UserUseCase) ConfirmUser(ctx context.Context, username, actor string) (*domain.ActiveUser, *domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	pending, ok := user.(*domain.PendingUser)
	if !ok {
		return nil, nil, fmt.Errorf("cannot confirm: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminConfirmSignUp(ctx, username); err != nil {
		return nil, nil, fmt.Errorf("cognito confirm failed: %w", err)
	}

	active := pending.Confirm()
	event := domain.NewAuditEvent(username, domain.AuditConfirm, actor, "")

	return active, event, nil
}

func (uc *UserUseCase) SuspendUser(ctx context.Context, username, reason, actor string) (*domain.SuspendedUser, *domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	active, ok := user.(*domain.ActiveUser)
	if !ok {
		return nil, nil, fmt.Errorf("cannot suspend: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminDisableUser(ctx, username); err != nil {
		return nil, nil, fmt.Errorf("cognito disable failed: %w", err)
	}

	suspended := active.Suspend(reason)
	event := domain.NewAuditEvent(username, domain.AuditSuspend, actor, reason)

	return suspended, event, nil
}

func (uc *UserUseCase) ReactivateUser(ctx context.Context, username, actor string) (*domain.ActiveUser, *domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	suspended, ok := user.(*domain.SuspendedUser)
	if !ok {
		return nil, nil, fmt.Errorf("cannot reactivate: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminEnableUser(ctx, username); err != nil {
		return nil, nil, fmt.Errorf("cognito enable failed: %w", err)
	}

	active := suspended.Reactivate()
	event := domain.NewAuditEvent(username, domain.AuditReactivate, actor, "")

	return active, event, nil
}

func (uc *UserUseCase) DeleteUser(ctx context.Context, username, reason, actor string) (*domain.DeletedUser, *domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	var deleted *domain.DeletedUser

	switch u := user.(type) {
	case *domain.ActiveUser:
		deleted = u.Delete(reason)
	case *domain.SuspendedUser:
		deleted = u.Delete(reason)
	default:
		return nil, nil, fmt.Errorf("cannot delete: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminDeleteUser(ctx, username); err != nil {
		return nil, nil, fmt.Errorf("cognito delete failed: %w", err)
	}

	event := domain.NewAuditEvent(username, domain.AuditDelete, actor, reason)

	return deleted, event, nil
}

func (uc *UserUseCase) AddRole(ctx context.Context, username, role, actor string) (*domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	active, ok := user.(*domain.ActiveUser)
	if !ok {
		return nil, fmt.Errorf("cannot add role: user is %s", user.UserStatus())
	}

	roleSet := domain.NewRoleSet(username, active.Groups)
	if !roleSet.Add(role) {
		return nil, fmt.Errorf("user already has role: %s", role)
	}

	active.UpdateGroups(roleSet.Roles())
	event := domain.NewAuditEvent(username, domain.AuditRoleAdd, actor, role)

	return event, nil
}

func (uc *UserUseCase) RemoveRole(ctx context.Context, username, role, actor string) (*domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	active, ok := user.(*domain.ActiveUser)
	if !ok {
		return nil, fmt.Errorf("cannot remove role: user is %s", user.UserStatus())
	}

	roleSet := domain.NewRoleSet(username, active.Groups)
	if !roleSet.Remove(role) {
		return nil, fmt.Errorf("user does not have role: %s", role)
	}

	active.UpdateGroups(roleSet.Roles())
	event := domain.NewAuditEvent(username, domain.AuditRoleRemove, actor, role)

	return event, nil
}

func (uc *UserUseCase) ResetPassword(ctx context.Context, username, actor string) (*domain.AuditEvent, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	if user.UserStatus() == domain.StatusPending || user.UserStatus() == domain.StatusDeleted {
		return nil, fmt.Errorf("cannot reset password: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminResetPassword(ctx, username); err != nil {
		return nil, fmt.Errorf("cognito reset password failed: %w", err)
	}

	event := domain.NewAuditEvent(username, domain.AuditPasswordReset, actor, "")

	return event, nil
}

func toDomainUser(d *cognito.AdminUserDetail) domain.User {
	status := mapCognitoStatus(d.Status, d.Enabled)

	var groups []string
	if g, ok := d.Attributes["cognito:groups"]; ok && g != "" {
		groups = []string{g}
	}

	u, err := domain.FromCognito(
		d.Username,
		d.Email,
		string(status),
		groups,
		d.CreatedAt,
		nil,
		"",
	)
	if err != nil {
		return &domain.PendingUser{
			ID:        d.Username,
			Email:     d.Email,
			CreatedAt: d.CreatedAt,
		}
	}
	return u
}

func summaryToDomainUser(s cognito.AdminUserSummary) domain.User {
	status := mapCognitoStatus(s.Status, s.Enabled)

	u, _ := domain.FromCognito(
		s.Username,
		s.Email,
		string(status),
		nil,
		s.CreatedAt,
		nil,
		"",
	)
	return u
}

func mapCognitoStatus(cognitoStatus string, enabled bool) domain.UserStatus {
	switch {
	case cognitoStatus == "UNCONFIRMED":
		return domain.StatusPending
	case !enabled:
		return domain.StatusSuspended
	default:
		return domain.StatusActive
	}
}
