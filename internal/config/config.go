package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	AWSRegion           string `envconfig:"AWS_REGION" required:"true"`
	AWSEndpointURL      string `envconfig:"AWS_ENDPOINT_URL"`
	CognitoPoolID       string `envconfig:"COGNITO_POOL_ID" required:"true"`
	CognitoClientID     string `envconfig:"COGNITO_CLIENT_ID" required:"true"`
	CognitoClientSecret string `envconfig:"COGNITO_CLIENT_SECRET" required:"true"`
	CognitoDomain       string `envconfig:"COGNITO_DOMAIN" required:"true"`
	OAuthCallbackURL    string `envconfig:"OAUTH_CALLBACK_URL" required:"true"`

	// OIDC Provider settings
	OIDCIssuer      string `envconfig:"OIDC_ISSUER" required:"true"`
	OIDCSigningKey  string `envconfig:"OIDC_SIGNING_KEY" required:"true"`  // RSA PEM or "auto" for local
	OIDCKeyID       string `envconfig:"OIDC_KEY_ID" required:"true"`
	OIDCAuthCodeKey string `envconfig:"OIDC_AUTH_CODE_KEY" required:"true"` // AES-256 hex (64 chars)
	OIDCClients     string `envconfig:"OIDC_CLIENTS" required:"true"`      // client definitions
}

// IsLocal returns true when running against a local emulator (floci/LocalStack).
func (c *Config) IsLocal() bool {
	return c.AWSEndpointURL != ""
}

// Load reads config from environment variables.
// If a value starts with "ssm:", the remainder is treated as an SSM Parameter Store path
// and the actual value is fetched from SSM.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	if err := resolveSSMValues(&cfg); err != nil {
		return nil, fmt.Errorf("failed to resolve SSM parameters: %w", err)
	}

	return &cfg, nil
}

func resolveSSMValues(cfg *Config) error {
	fields := []*string{
		&cfg.CognitoClientSecret,
		&cfg.OIDCSigningKey,
		&cfg.OIDCAuthCodeKey,
	}

	// Collect SSM paths
	var paths []string
	for _, f := range fields {
		if strings.HasPrefix(*f, "ssm:") {
			paths = append(paths, strings.TrimPrefix(*f, "ssm:"))
		}
	}

	if len(paths) == 0 {
		return nil
	}

	// Fetch all SSM values in one call
	values, err := fetchSSMParameters(cfg, paths)
	if err != nil {
		return err
	}

	// Replace field values
	for _, f := range fields {
		if strings.HasPrefix(*f, "ssm:") {
			path := strings.TrimPrefix(*f, "ssm:")
			val, ok := values[path]
			if !ok {
				return fmt.Errorf("SSM parameter not found: %s", path)
			}
			*f = val
		}
	}

	return nil
}

func fetchSSMParameters(cfg *Config, paths []string) (map[string]string, error) {
	ctx := context.Background()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	opts := []func(*ssm.Options){}
	if cfg.AWSEndpointURL != "" {
		opts = append(opts, func(o *ssm.Options) {
			o.BaseEndpoint = aws.String(cfg.AWSEndpointURL)
		})
	}

	client := ssm.NewFromConfig(awsCfg, opts...)

	names := make([]string, len(paths))
	copy(names, paths)

	input := &ssm.GetParametersInput{
		Names:          names,
		WithDecryption: aws.Bool(true),
	}

	result, err := client.GetParameters(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSM parameters: %w", err)
	}

	values := make(map[string]string, len(result.Parameters))
	for _, p := range result.Parameters {
		values[aws.ToString(p.Name)] = aws.ToString(p.Value)
	}

	return values, nil
}
