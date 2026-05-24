package domain

const (
	TokenUseAccess = "access"
	TokenUseID     = "id"

	AMRPassword  = "pwd"
	AMRFederated = "federated"

	GroupAdmin = "admin"
)

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
