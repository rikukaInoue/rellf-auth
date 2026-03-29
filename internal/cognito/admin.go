package cognito

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type AdminService interface {
	AdminListUsers(ctx context.Context, filter string, limit int32, paginationToken *string) (*AdminListUsersOutput, error)
	AdminGetUser(ctx context.Context, username string) (*AdminUserDetail, error)
	AdminCreateUser(ctx context.Context, email, tempPassword string) (*AdminUserDetail, error)
	AdminConfirmSignUp(ctx context.Context, username string) error
	AdminResetPassword(ctx context.Context, username string) error
	AdminDisableUser(ctx context.Context, username string) error
	AdminEnableUser(ctx context.Context, username string) error
	AdminDeleteUser(ctx context.Context, username string) error
}

type AdminUserSummary struct {
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Status     string    `json:"status"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

type AdminListUsersOutput struct {
	Users           []AdminUserSummary `json:"users"`
	PaginationToken *string            `json:"pagination_token,omitempty"`
}

type AdminUserDetail struct {
	Username   string            `json:"username"`
	Email      string            `json:"email"`
	Status     string            `json:"status"`
	Enabled    bool              `json:"enabled"`
	CreatedAt  time.Time         `json:"created_at"`
	ModifiedAt time.Time         `json:"modified_at"`
	Attributes map[string]string `json:"attributes"`
}

func (c *Client) AdminListUsers(ctx context.Context, filter string, limit int32, paginationToken *string) (*AdminListUsersOutput, error) {
	input := &cip.ListUsersInput{
		UserPoolId: aws.String(c.poolID),
		Limit:      aws.Int32(limit),
	}
	if filter != "" {
		input.Filter = aws.String(filter)
	}
	if paginationToken != nil {
		input.PaginationToken = paginationToken
	}

	result, err := c.cip.ListUsers(ctx, input)
	if err != nil {
		return nil, err
	}

	users := make([]AdminUserSummary, 0, len(result.Users))
	for _, u := range result.Users {
		users = append(users, adminUserSummaryFromCognito(u))
	}

	return &AdminListUsersOutput{
		Users:           users,
		PaginationToken: result.PaginationToken,
	}, nil
}

func (c *Client) AdminGetUser(ctx context.Context, username string) (*AdminUserDetail, error) {
	input := &cip.AdminGetUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}

	result, err := c.cip.AdminGetUser(ctx, input)
	if err != nil {
		return nil, err
	}

	attrs := make(map[string]string, len(result.UserAttributes))
	email := ""
	for _, a := range result.UserAttributes {
		name := aws.ToString(a.Name)
		value := aws.ToString(a.Value)
		attrs[name] = value
		if name == "email" {
			email = value
		}
	}

	return &AdminUserDetail{
		Username:   aws.ToString(result.Username),
		Email:      email,
		Status:     string(result.UserStatus),
		Enabled:    result.Enabled,
		CreatedAt:  aws.ToTime(result.UserCreateDate),
		ModifiedAt: aws.ToTime(result.UserLastModifiedDate),
		Attributes: attrs,
	}, nil
}

func (c *Client) AdminCreateUser(ctx context.Context, email, tempPassword string) (*AdminUserDetail, error) {
	input := &cip.AdminCreateUserInput{
		UserPoolId:    aws.String(c.poolID),
		Username:      aws.String(email),
		TemporaryPassword: aws.String(tempPassword),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: aws.String(email)},
			{Name: aws.String("email_verified"), Value: aws.String("true")},
		},
	}

	result, err := c.cip.AdminCreateUser(ctx, input)
	if err != nil {
		return nil, err
	}

	attrs := make(map[string]string, len(result.User.Attributes))
	for _, a := range result.User.Attributes {
		attrs[aws.ToString(a.Name)] = aws.ToString(a.Value)
	}

	return &AdminUserDetail{
		Username:   aws.ToString(result.User.Username),
		Email:      email,
		Status:     string(result.User.UserStatus),
		Enabled:    result.User.Enabled,
		CreatedAt:  aws.ToTime(result.User.UserCreateDate),
		ModifiedAt: aws.ToTime(result.User.UserLastModifiedDate),
		Attributes: attrs,
	}, nil
}

func (c *Client) AdminConfirmSignUp(ctx context.Context, username string) error {
	input := &cip.AdminConfirmSignUpInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}
	_, err := c.cip.AdminConfirmSignUp(ctx, input)
	return err
}

func (c *Client) AdminResetPassword(ctx context.Context, username string) error {
	input := &cip.AdminResetUserPasswordInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}
	_, err := c.cip.AdminResetUserPassword(ctx, input)
	return err
}

func (c *Client) AdminDisableUser(ctx context.Context, username string) error {
	input := &cip.AdminDisableUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}
	_, err := c.cip.AdminDisableUser(ctx, input)
	return err
}

func (c *Client) AdminEnableUser(ctx context.Context, username string) error {
	input := &cip.AdminEnableUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}
	_, err := c.cip.AdminEnableUser(ctx, input)
	return err
}

func (c *Client) AdminDeleteUser(ctx context.Context, username string) error {
	input := &cip.AdminDeleteUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(username),
	}
	_, err := c.cip.AdminDeleteUser(ctx, input)
	return err
}

func adminUserSummaryFromCognito(u types.UserType) AdminUserSummary {
	email := ""
	for _, a := range u.Attributes {
		if aws.ToString(a.Name) == "email" {
			email = aws.ToString(a.Value)
			break
		}
	}
	return AdminUserSummary{
		Username:   aws.ToString(u.Username),
		Email:      email,
		Status:     string(u.UserStatus),
		Enabled:    u.Enabled,
		CreatedAt:  aws.ToTime(u.UserCreateDate),
		ModifiedAt: aws.ToTime(u.UserLastModifiedDate),
	}
}
