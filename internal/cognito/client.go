package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/inouetaishi/rellf-auth/internal/config"
)

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type SignUpOutput struct {
	UserConfirmed bool   `json:"user_confirmed"`
	UserSub       string `json:"user_sub"`
}

type LinkedProvider struct {
	ProviderName string `json:"provider_name"`
	ProviderUID  string `json:"provider_uid"`
}

type Service interface {
	SignUp(ctx context.Context, email, password string) (*SignUpOutput, error)
	ConfirmSignUp(ctx context.Context, email, code string) error
	Login(ctx context.Context, email, password string) (*AuthTokens, error)
	ForgotPassword(ctx context.Context, email string) error
	ConfirmForgotPassword(ctx context.Context, email, code, newPassword string) error
	LinkProvider(ctx context.Context, username, providerName, providerUID string) error
	UnlinkProvider(ctx context.Context, username, providerName, providerUID string) error
	GetLinkedProviders(ctx context.Context, username string) ([]LinkedProvider, error)
}

type Client struct {
	cip          *cip.Client
	poolID       string
	clientID     string
	clientSecret string
}

func New(cfg *config.Config) (*Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	opts := []func(*cip.Options){}
	if cfg.AWSEndpointURL != "" {
		opts = append(opts, func(o *cip.Options) {
			o.BaseEndpoint = aws.String(cfg.AWSEndpointURL)
		})
	}

	return &Client{
		cip:          cip.NewFromConfig(awsCfg, opts...),
		poolID:       cfg.CognitoPoolID,
		clientID:     cfg.CognitoClientID,
		clientSecret: cfg.CognitoClientSecret,
	}, nil
}

func (c *Client) computeSecretHash(username string) string {
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	mac.Write([]byte(username + c.clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (c *Client) SignUp(ctx context.Context, email, password string) (*SignUpOutput, error) {
	input := &cip.SignUpInput{
		ClientId:   aws.String(c.clientID),
		Username:   aws.String(email),
		Password:   aws.String(password),
		SecretHash: aws.String(c.computeSecretHash(email)),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String(email)},
		},
	}

	result, err := c.cip.SignUp(ctx, input)
	if err != nil {
		return nil, err
	}

	return &SignUpOutput{
		UserConfirmed: result.UserConfirmed,
		UserSub:       aws.ToString(result.UserSub),
	}, nil
}

func (c *Client) ConfirmSignUp(ctx context.Context, email, code string) error {
	input := &cip.ConfirmSignUpInput{
		ClientId:         aws.String(c.clientID),
		Username:         aws.String(email),
		ConfirmationCode: aws.String(code),
		SecretHash:       aws.String(c.computeSecretHash(email)),
	}
	_, err := c.cip.ConfirmSignUp(ctx, input)
	return err
}

func (c *Client) Login(ctx context.Context, email, password string) (*AuthTokens, error) {
	input := &cip.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(c.clientID),
		AuthParameters: map[string]string{
			"USERNAME":    email,
			"PASSWORD":    password,
			"SECRET_HASH": c.computeSecretHash(email),
		},
	}

	result, err := c.cip.InitiateAuth(ctx, input)
	if err != nil {
		return nil, err
	}

	return &AuthTokens{
		AccessToken:  aws.ToString(result.AuthenticationResult.AccessToken),
		IDToken:      aws.ToString(result.AuthenticationResult.IdToken),
		RefreshToken: aws.ToString(result.AuthenticationResult.RefreshToken),
		ExpiresIn:    result.AuthenticationResult.ExpiresIn,
		TokenType:    aws.ToString(result.AuthenticationResult.TokenType),
	}, nil
}

func (c *Client) ForgotPassword(ctx context.Context, email string) error {
	input := &cip.ForgotPasswordInput{
		ClientId:   aws.String(c.clientID),
		Username:   aws.String(email),
		SecretHash: aws.String(c.computeSecretHash(email)),
	}
	_, err := c.cip.ForgotPassword(ctx, input)
	return err
}

func (c *Client) ConfirmForgotPassword(ctx context.Context, email, code, newPassword string) error {
	input := &cip.ConfirmForgotPasswordInput{
		ClientId:         aws.String(c.clientID),
		Username:         aws.String(email),
		ConfirmationCode: aws.String(code),
		Password:         aws.String(newPassword),
		SecretHash:       aws.String(c.computeSecretHash(email)),
	}
	_, err := c.cip.ConfirmForgotPassword(ctx, input)
	return err
}

func (c *Client) LinkProvider(ctx context.Context, username, providerName, providerUID string) error {
	input := &cip.AdminLinkProviderForUserInput{
		UserPoolId: aws.String(c.poolID),
		DestinationUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String("Cognito"),
			ProviderAttributeValue: aws.String(username),
		},
		SourceUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String(providerName),
			ProviderAttributeValue: aws.String(providerUID),
			ProviderAttributeName:  aws.String("Cognito_Subject"),
		},
	}
	_, err := c.cip.AdminLinkProviderForUser(ctx, input)
	return err
}

func (c *Client) UnlinkProvider(ctx context.Context, username, providerName, providerUID string) error {
	input := &cip.AdminDisableProviderForUserInput{
		UserPoolId: aws.String(c.poolID),
		User: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String(providerName),
			ProviderAttributeValue: aws.String(providerUID),
		},
	}
	_, err := c.cip.AdminDisableProviderForUser(ctx, input)
	return err
}

func (c *Client) GetLinkedProviders(ctx context.Context, username string) ([]LinkedProvider, error) {
	input := &cip.AdminGetUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}

	result, err := c.cip.AdminGetUser(ctx, input)
	if err != nil {
		return nil, err
	}

	var providers []LinkedProvider

	// The native Cognito account itself
	providers = append(providers, LinkedProvider{
		ProviderName: "Cognito",
		ProviderUID:  aws.ToString(result.Username),
	})

	// Check for linked identities in user attributes
	for _, attr := range result.UserAttributes {
		if aws.ToString(attr.Name) == "identities" {
			// identities is a JSON array of linked providers
			var identities []struct {
				ProviderName string `json:"providerName"`
				UserID       string `json:"userId"`
			}
			if err := json.Unmarshal([]byte(aws.ToString(attr.Value)), &identities); err == nil {
				for _, id := range identities {
					providers = append(providers, LinkedProvider{
						ProviderName: id.ProviderName,
						ProviderUID:  id.UserID,
					})
				}
			}
		}
	}

	return providers, nil
}
