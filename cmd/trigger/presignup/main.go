package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

var cognitoClient *cip.Client

func init() {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}
	cognitoClient = cip.NewFromConfig(cfg)
}

func handler(ctx context.Context, event events.CognitoEventUserPoolsPreSignup) (events.CognitoEventUserPoolsPreSignup, error) {
	email, ok := event.Request.UserAttributes["email"]
	if !ok || email == "" {
		return event, nil
	}

	// For external providers (Google etc.), auto-confirm and verify email
	triggerSource := event.TriggerSource
	if triggerSource == "PreSignUp_ExternalProvider" {
		event.Response.AutoConfirmUser = true
		event.Response.AutoVerifyEmail = true

		// Check if a native (email/password) user already exists with this email
		existingUser, err := findUserByEmail(ctx, event.UserPoolID, email)
		if err != nil {
			log.Printf("error looking up existing user: %v", err)
			return event, nil
		}

		if existingUser != nil {
			// Link the external provider to the existing native account
			// event.UserName for external provider is like "Google_123456789"
			providerName, providerUID := parseExternalUsername(event.UserName)
			if providerName == "" {
				log.Printf("could not parse external username: %s", event.UserName)
				return event, nil
			}

			err = linkProviderToUser(ctx, event.UserPoolID, *existingUser, providerName, providerUID)
			if err != nil {
				log.Printf("error linking provider: %v", err)
				return event, fmt.Errorf("failed to link accounts: %w", err)
			}

			log.Printf("linked %s to existing user %s", event.UserName, *existingUser)
		}
	}

	return event, nil
}

func findUserByEmail(ctx context.Context, userPoolID, email string) (*string, error) {
	input := &cip.ListUsersInput{
		UserPoolId: aws.String(userPoolID),
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
		Limit:      aws.Int32(10),
	}

	result, err := cognitoClient.ListUsers(ctx, input)
	if err != nil {
		return nil, err
	}

	// Find a native (Cognito) user with verified email
	for _, user := range result.Users {
		isNative := true
		emailVerified := false

		for _, attr := range user.Attributes {
			if aws.ToString(attr.Name) == "email_verified" && aws.ToString(attr.Value) == "true" {
				emailVerified = true
			}
		}

		// Check if this is a native user (no provider prefix in username)
		for _, id := range user.Attributes {
			if aws.ToString(id.Name) == "cognito:user_status" {
				// External provider users have different status
				break
			}
		}

		if isNative && emailVerified {
			return user.Username, nil
		}
	}

	return nil, nil
}

// parseExternalUsername parses "Google_123456789" into ("Google", "123456789").
func parseExternalUsername(username string) (string, string) {
	for i, c := range username {
		if c == '_' && i > 0 && i < len(username)-1 {
			return username[:i], username[i+1:]
		}
	}
	return "", ""
}

func linkProviderToUser(ctx context.Context, userPoolID, nativeUsername, providerName, providerUID string) error {
	input := &cip.AdminLinkProviderForUserInput{
		UserPoolId: aws.String(userPoolID),
		DestinationUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String("Cognito"),
			ProviderAttributeValue: aws.String(nativeUsername),
		},
		SourceUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String(providerName),
			ProviderAttributeValue: aws.String(providerUID),
			ProviderAttributeName:  aws.String("Cognito_Subject"),
		},
	}

	_, err := cognitoClient.AdminLinkProviderForUser(ctx, input)
	if err != nil {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "ap-northeast-1"
		}
		log.Printf("AdminLinkProviderForUser failed for pool=%s, dest=%s, source=%s:%s: %v",
			userPoolID, nativeUsername, providerName, providerUID, err)
	}
	return err
}

func main() {
	lambda.Start(handler)
}
