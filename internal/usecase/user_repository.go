package usecase

import (
	"context"
	"time"
)

type UserDetail struct {
	Username   string
	Email      string
	Status     string
	Enabled    bool
	CreatedAt  time.Time
	ModifiedAt time.Time
	Attributes map[string]string
}

type UserSummary struct {
	Username   string
	Email      string
	Status     string
	Enabled    bool
	CreatedAt  time.Time
	ModifiedAt time.Time
}

type UserListResult struct {
	Users           []UserSummary
	PaginationToken *string
}

// UserRepository handles user CRUD and lifecycle operations.
type UserRepository interface {
	GetUser(ctx context.Context, username string) (*UserDetail, error)
	ListUsers(ctx context.Context, filter string, limit int32, paginationToken *string) (*UserListResult, error)
	CreateUser(ctx context.Context, email, tempPassword string) (*UserDetail, error)
	ConfirmUser(ctx context.Context, username string) error
	ResetPassword(ctx context.Context, username string) error
	DisableUser(ctx context.Context, username string) error
	EnableUser(ctx context.Context, username string) error
	DeleteUser(ctx context.Context, username string) error
}
