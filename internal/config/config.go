package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	AWSRegion          string `envconfig:"AWS_REGION" required:"true"`
	CognitoPoolID      string `envconfig:"COGNITO_POOL_ID" required:"true"`
	CognitoClientID    string `envconfig:"COGNITO_CLIENT_ID" required:"true"`
	CognitoClientSecret string `envconfig:"COGNITO_CLIENT_SECRET" required:"true"`
	CognitoDomain      string `envconfig:"COGNITO_DOMAIN" required:"true"`
	OAuthCallbackURL   string `envconfig:"OAUTH_CALLBACK_URL" required:"true"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
