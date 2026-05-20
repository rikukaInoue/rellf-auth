package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// LinkGoogle godoc
// @Summary      Googleアカウントをリンク
// @Description  認証済みユーザーのアカウントにGoogleログインを紐づける。Google OAuth認証ページにリダイレクト。
// @Tags         account-link
// @Security     BearerAuth
// @Success      302 "Google認証ページにリダイレクト"
// @Failure      401 {object} ErrorResponse
// @Router       /api/link/google [get]
func (h *Handler) LinkGoogle(c *gin.Context) {
	token, _ := c.Get("token_claims")
	jwtToken := token.(jwt.Token)
	username := jwtToken.Subject()

	state := "link:" + username

	authURL := fmt.Sprintf(
		"https://%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=openid+email+profile&identity_provider=Google",
		h.cfg.CognitoDomain,
		h.cfg.CognitoClientID,
		url.QueryEscape(h.cfg.OAuthCallbackURL),
		url.QueryEscape(state),
	)

	c.JSON(http.StatusOK, gin.H{"redirect_url": authURL})
}

// UnlinkProvider godoc
// @Summary      プロバイダのリンク解除
// @Description  認証済みユーザーから指定されたログインプロバイダの紐づけを解除
// @Tags         account-link
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "プロバイダ名 (例: google)"
// @Success      200 {object} map[string]string
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /api/link/{provider} [delete]
func (h *Handler) UnlinkProvider(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		errorResponse(c, http.StatusBadRequest, "missing provider", "")
		return
	}

	// Normalize provider name
	providerName = normalizeProviderName(providerName)
	if providerName == "Cognito" {
		errorResponse(c, http.StatusBadRequest, "cannot unlink native account", "")
		return
	}

	token, _ := c.Get("token_claims")
	jwtToken := token.(jwt.Token)
	username := jwtToken.Subject()

	// Get current linked providers to find the UID
	providers, err := h.providers.GetLinkedProviders(c.Request.Context(), username)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to get linked providers", err.Error())
		return
	}

	var providerUID string
	for _, p := range providers {
		if p.ProviderName == providerName {
			providerUID = p.ProviderUID
			break
		}
	}

	if providerUID == "" {
		errorResponse(c, http.StatusNotFound, "provider not linked", "")
		return
	}

	if err := h.providers.UnlinkProvider(c.Request.Context(), username, providerName, providerUID); err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to unlink provider", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%s unlinked successfully", providerName)})
}

// GetProviders godoc
// @Summary      リンク済みプロバイダ一覧
// @Description  認証済みユーザーに紐づけられているログインプロバイダの一覧を取得
// @Tags         account-link
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} ProvidersResponse
// @Failure      401 {object} ErrorResponse
// @Router       /api/providers [get]
func (h *Handler) GetProviders(c *gin.Context) {
	token, _ := c.Get("token_claims")
	jwtToken := token.(jwt.Token)
	username := jwtToken.Subject()

	providers, err := h.providers.GetLinkedProviders(c.Request.Context(), username)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to get providers", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func normalizeProviderName(name string) string {
	switch strings.ToLower(name) {
	case "google":
		return "Google"
	default:
		return name
	}
}
