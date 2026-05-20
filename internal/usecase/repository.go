package usecase

import (
	"context"

	"github.com/inouetaishi/rellf-auth/internal/domain"
)

// CredentialStore handles user authentication, registration, and password operations.
type CredentialStore interface {
	CredentialVerifier
	SignUp(ctx context.Context, email, password string) (*domain.SignUpResult, error)
	ConfirmSignUp(ctx context.Context, email, code string) error
	ForgotPassword(ctx context.Context, email string) error
	ConfirmForgotPassword(ctx context.Context, email, code, newPassword string) error
}

// ProviderStore handles external identity provider linking.
type ProviderStore interface {
	LinkProvider(ctx context.Context, username, providerName, providerUID string) error
	UnlinkProvider(ctx context.Context, username, providerName, providerUID string) error
	GetLinkedProviders(ctx context.Context, username string) ([]domain.LinkedProvider, error)
}
