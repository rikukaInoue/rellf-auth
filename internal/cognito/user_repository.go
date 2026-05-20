package cognito

import (
	"context"

	"github.com/inouetaishi/rellf-auth/internal/usecase"
)

// GetUser satisfies usecase.UserRepository.
func (c *Client) GetUser(ctx context.Context, username string) (*usecase.UserDetail, error) {
	d, err := c.AdminGetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	return &usecase.UserDetail{
		Username:   d.Username,
		Email:      d.Email,
		Status:     d.Status,
		Enabled:    d.Enabled,
		CreatedAt:  d.CreatedAt,
		ModifiedAt: d.ModifiedAt,
		Attributes: d.Attributes,
	}, nil
}

// ListUsers satisfies usecase.UserRepository.
func (c *Client) ListUsers(ctx context.Context, filter string, limit int32, paginationToken *string) (*usecase.UserListResult, error) {
	result, err := c.AdminListUsers(ctx, filter, limit, paginationToken)
	if err != nil {
		return nil, err
	}
	users := make([]usecase.UserSummary, len(result.Users))
	for i, u := range result.Users {
		users[i] = usecase.UserSummary{
			Username:   u.Username,
			Email:      u.Email,
			Status:     u.Status,
			Enabled:    u.Enabled,
			CreatedAt:  u.CreatedAt,
			ModifiedAt: u.ModifiedAt,
		}
	}
	return &usecase.UserListResult{
		Users:           users,
		PaginationToken: result.PaginationToken,
	}, nil
}

// CreateUser satisfies usecase.UserRepository.
func (c *Client) CreateUser(ctx context.Context, email, tempPassword string) (*usecase.UserDetail, error) {
	d, err := c.AdminCreateUser(ctx, email, tempPassword)
	if err != nil {
		return nil, err
	}
	return &usecase.UserDetail{
		Username:   d.Username,
		Email:      d.Email,
		Status:     d.Status,
		Enabled:    d.Enabled,
		CreatedAt:  d.CreatedAt,
		ModifiedAt: d.ModifiedAt,
		Attributes: d.Attributes,
	}, nil
}

// ConfirmUser satisfies usecase.UserRepository.
func (c *Client) ConfirmUser(ctx context.Context, username string) error {
	return c.AdminConfirmSignUp(ctx, username)
}

// ResetPassword satisfies usecase.UserRepository.
func (c *Client) ResetPassword(ctx context.Context, username string) error {
	return c.AdminResetPassword(ctx, username)
}

// DisableUser satisfies usecase.UserRepository.
func (c *Client) DisableUser(ctx context.Context, username string) error {
	return c.AdminDisableUser(ctx, username)
}

// EnableUser satisfies usecase.UserRepository.
func (c *Client) EnableUser(ctx context.Context, username string) error {
	return c.AdminEnableUser(ctx, username)
}

// DeleteUser satisfies usecase.UserRepository.
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	return c.AdminDeleteUser(ctx, username)
}
