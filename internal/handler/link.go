package handler

import (
	"encoding/json"
	"fmt"
	"io"
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

// handleLinkCallback handles the OAuth callback when linking a provider to an existing account.
func (h *Handler) handleLinkCallback(c *gin.Context, code, username string) {
	// Exchange code for tokens to get the external user's identity
	tokenURL := fmt.Sprintf("https://%s/oauth2/token", h.cfg.CognitoDomain)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", h.cfg.CognitoClientID)
	data.Set("client_secret", h.cfg.CognitoClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", h.cfg.OAuthCallbackURL)

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "token exchange failed", err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to read token response", err.Error())
		return
	}

	if resp.StatusCode != http.StatusOK {
		errorResponse(c, http.StatusBadRequest, "token exchange failed", string(body))
		return
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to parse token response", err.Error())
		return
	}

	// Parse the ID token to get the Google sub (no signature verification needed here
	// since we got it directly from Cognito's token endpoint over HTTPS)
	idToken, err := jwt.Parse([]byte(tokenResp.IDToken), jwt.WithVerify(false))
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to parse id token", err.Error())
		return
	}

	googleSub := idToken.Subject()
	if googleSub == "" {
		errorResponse(c, http.StatusInternalServerError, "missing sub in id token", "")
		return
	}

	// Link the Google identity to the existing user
	if err := h.auth.LinkProvider(c.Request.Context(), username, "Google", googleSub); err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to link provider", err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/pages/dashboard")
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
	providers, err := h.auth.GetLinkedProviders(c.Request.Context(), username)
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

	if err := h.auth.UnlinkProvider(c.Request.Context(), username, providerName, providerUID); err != nil {
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

	providers, err := h.auth.GetLinkedProviders(c.Request.Context(), username)
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
