package usecase

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthenticatedUser struct {
	Sub      string
	Email    string
	Username string
	Groups   []string
}

type CredentialVerifier interface {
	LoginIDToken(ctx context.Context, email, password string) (idTokenRaw string, err error)
}

type AuthUseCase struct {
	verifier CredentialVerifier
}

func NewAuthUseCase(verifier CredentialVerifier) *AuthUseCase {
	return &AuthUseCase{verifier: verifier}
}

func (uc *AuthUseCase) Authenticate(ctx context.Context, email, password string) (*AuthenticatedUser, error) {
	idTokenRaw, err := uc.verifier.LoginIDToken(ctx, email, password)
	if err != nil {
		return nil, err
	}

	return uc.parseIdentity(idTokenRaw)
}

func (uc *AuthUseCase) parseIdentity(idTokenRaw string) (*AuthenticatedUser, error) {
	idToken, err := jwt.Parse([]byte(idTokenRaw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	sub := idToken.Subject()

	var email string
	if v, ok := idToken.Get("email"); ok {
		email, _ = v.(string)
	}

	username := sub
	if v, ok := idToken.Get("cognito:username"); ok {
		if s, ok := v.(string); ok && s != "" {
			username = s
		}
	}

	var groups []string
	if v, ok := idToken.Get("cognito:groups"); ok {
		if gs, ok := v.([]interface{}); ok {
			for _, g := range gs {
				if s, ok := g.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	return &AuthenticatedUser{
		Sub:      sub,
		Email:    email,
		Username: username,
		Groups:   groups,
	}, nil
}
