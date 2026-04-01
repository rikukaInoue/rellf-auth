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

func (uc *UserUseCase) ConfirmUser(ctx context.Context, username string) (*domain.ActiveUser, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	pending, ok := user.(*domain.PendingUser)
	if !ok {
		return nil, fmt.Errorf("cannot confirm: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminConfirmSignUp(ctx, username); err != nil {
		return nil, fmt.Errorf("cognito confirm failed: %w", err)
	}

	return pending.Confirm(), nil
}

func (uc *UserUseCase) SuspendUser(ctx context.Context, username, reason string) (*domain.SuspendedUser, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	active, ok := user.(*domain.ActiveUser)
	if !ok {
		return nil, fmt.Errorf("cannot suspend: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminDisableUser(ctx, username); err != nil {
		return nil, fmt.Errorf("cognito disable failed: %w", err)
	}

	return active.Suspend(reason), nil
}

func (uc *UserUseCase) ReactivateUser(ctx context.Context, username string) (*domain.ActiveUser, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	suspended, ok := user.(*domain.SuspendedUser)
	if !ok {
		return nil, fmt.Errorf("cannot reactivate: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminEnableUser(ctx, username); err != nil {
		return nil, fmt.Errorf("cognito enable failed: %w", err)
	}

	return suspended.Reactivate(), nil
}

func (uc *UserUseCase) DeleteUser(ctx context.Context, username, reason string) (*domain.DeletedUser, error) {
	user, err := uc.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	var deleted *domain.DeletedUser

	switch u := user.(type) {
	case *domain.ActiveUser:
		deleted = u.Delete(reason)
	case *domain.SuspendedUser:
		deleted = u.Delete(reason)
	default:
		return nil, fmt.Errorf("cannot delete: user is %s", user.UserStatus())
	}

	if err := uc.admin.AdminDeleteUser(ctx, username); err != nil {
		return nil, fmt.Errorf("cognito delete failed: %w", err)
	}

	return deleted, nil
}

func toDomainUser(d *cognito.AdminUserDetail) domain.User {
	status := mapCognitoStatus(d.Status, d.Enabled)

	// Extract groups from Cognito attributes if present
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
