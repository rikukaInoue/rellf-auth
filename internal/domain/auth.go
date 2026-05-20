package domain

type SignUpResult struct {
	UserConfirmed bool
	UserSub       string
}

type LinkedProvider struct {
	ProviderName string
	ProviderUID  string
}

type AuthenticatedUser struct {
	Sub      string
	Email    string
	Username string
	Groups   []string
}
