// @title          rellf-auth API
// @version        1.0
// @description    Authentication API with Cognito, email/password and Google OAuth
// @host           localhost:8080
// @BasePath       /
// @securityDefinitions.apikey BearerAuth
// @in             header
// @name           Authorization
// @description    Enter "Bearer {token}"
package main

import (
	"log"

	"github.com/inouetaishi/rellf-auth/internal/admin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/oidc"
	"github.com/inouetaishi/rellf-auth/internal/router"
	"github.com/inouetaishi/rellf-auth/internal/usecase"

	_ "github.com/inouetaishi/rellf-auth/docs"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cognitoClient, err := cognito.New(cfg)
	if err != nil {
		log.Fatalf("failed to create cognito client: %v", err)
	}

	// OIDC Provider setup
	var tokenIssuer *oidc.TokenIssuer
	if cfg.OIDCSigningKey == "auto" {
		tokenIssuer, err = oidc.NewLocalTokenIssuer(cfg.OIDCIssuer)
		if err != nil {
			log.Fatalf("failed to create local token issuer: %v", err)
		}
		log.Println("WARNING: OIDC using auto-generated ephemeral RSA key (local mode)")
	} else {
		tokenIssuer, err = oidc.NewTokenIssuer(cfg.OIDCSigningKey, cfg.OIDCKeyID, cfg.OIDCIssuer)
		if err != nil {
			log.Fatalf("failed to create token issuer: %v", err)
		}
	}

	authCodeCodec, err := oidc.NewAuthCodeCodec(cfg.OIDCAuthCodeKey)
	if err != nil {
		log.Fatalf("failed to create auth code codec: %v", err)
	}

	oidcClients, err := oidc.ParseClients(cfg.OIDCClients)
	if err != nil {
		log.Fatalf("failed to parse OIDC clients: %v", err)
	}
	clientRegistry := oidc.NewClientRegistry(oidcClients)

	var jwtMw *middleware.JWTMiddleware
	if cfg.IsLocal() {
		jwtMw = middleware.NewLocalJWTMiddleware(tokenIssuer.JWKS(), cfg.OIDCIssuer, cfg.CognitoClientID)
	} else {
		jwtMw = middleware.NewJWTMiddleware(tokenIssuer.JWKS(), cfg.OIDCIssuer, cfg.CognitoClientID)
	}

	authUC := usecase.NewAuthUseCase(cognitoClient)
	userUC := usecase.NewUserUseCase(cognitoClient)
	oidcH := oidc.NewOIDCHandler(authUC, userUC, tokenIssuer, authCodeCodec, clientRegistry, cfg)
	h := handler.New(cognitoClient, cognitoClient, authUC, tokenIssuer, cfg)
	adminH := admin.NewAdminHandler(cognitoClient, authUC, tokenIssuer, cfg)
	r := router.Setup(h, adminH, oidcH, jwtMw, cfg)

	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
