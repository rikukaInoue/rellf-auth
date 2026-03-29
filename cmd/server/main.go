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

	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/router"

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

	var jwtMw *middleware.JWTMiddleware
	if cfg.IsLocal() {
		jwtMw = middleware.NewLocalJWTMiddleware(cfg.CognitoClientID)
	} else {
		jwtMw, err = middleware.NewJWTMiddleware(cfg.AWSRegion, cfg.CognitoPoolID, cfg.CognitoClientID)
		if err != nil {
			log.Fatalf("failed to create JWT middleware: %v", err)
		}
	}

	h := handler.New(cognitoClient, cfg)
	r := router.Setup(h, jwtMw)

	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
