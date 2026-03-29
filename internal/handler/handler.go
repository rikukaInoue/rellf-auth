package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
)

type Handler struct {
	auth cognito.Service
	cfg  *config.Config
}

func New(auth cognito.Service, cfg *config.Config) *Handler {
	return &Handler{auth: auth, cfg: cfg}
}

type ErrorResponse struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// AuthTokensResponse represents the authentication tokens returned on login.
type AuthTokensResponse struct {
	AccessToken  string `json:"access_token" example:"eyJraWQ..."`
	IDToken      string `json:"id_token" example:"eyJraWQ..."`
	RefreshToken string `json:"refresh_token" example:"eyJjdH..."`
	ExpiresIn    int32  `json:"expires_in" example:"3600"`
	TokenType    string `json:"token_type" example:"Bearer"`
}

// SignUpResponse represents the sign-up result.
type SignUpResponse struct {
	UserConfirmed bool   `json:"user_confirmed" example:"false"`
	UserSub       string `json:"user_sub" example:"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`
}

// LinkedProviderResponse represents a linked identity provider.
type LinkedProviderResponse struct {
	ProviderName string `json:"provider_name" example:"Google"`
	ProviderUID  string `json:"provider_uid" example:"123456789"`
}

// ProvidersResponse is the list of linked providers.
type ProvidersResponse struct {
	Providers []LinkedProviderResponse `json:"providers"`
}

// MessageResponse is a generic success message.
type MessageResponse struct {
	Message string `json:"message" example:"success"`
}

func errorResponse(c *gin.Context, status int, msg string, detail string) {
	c.JSON(status, ErrorResponse{Message: msg, Detail: detail})
}

// HealthCheck godoc
// @Summary      ヘルスチェック
// @Description  サーバーの稼働状態を確認
// @Tags         system
// @Produce      json
// @Success      200 {object} map[string]string
// @Router       /health [get]
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
