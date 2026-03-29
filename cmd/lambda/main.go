// @title          rellf-auth API
// @version        1.0
// @description    Authentication API with Cognito, email/password and Google OAuth
// @host           localhost
// @BasePath       /
// @securityDefinitions.apikey BearerAuth
// @in             header
// @name           Authorization
// @description    Enter "Bearer {token}"
package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/router"

	_ "github.com/inouetaishi/rellf-auth/docs"
)

var ginLambda *ginadapter.GinLambdaV2

func init() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cognitoClient, err := cognito.New(cfg)
	if err != nil {
		log.Fatalf("failed to create cognito client: %v", err)
	}

	jwtMw, err := middleware.NewJWTMiddleware(cfg.AWSRegion, cfg.CognitoPoolID, cfg.CognitoClientID)
	if err != nil {
		log.Fatalf("failed to create JWT middleware: %v", err)
	}

	h := handler.New(cognitoClient, cfg)
	r := router.Setup(h, jwtMw)
	ginLambda = ginadapter.NewV2(r)
}

func handleRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return ginLambda.ProxyWithContext(ctx, req)
}

func main() {
	lambda.Start(handleRequest)
}
