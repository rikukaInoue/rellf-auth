package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// OAuthGoogle godoc
// @Summary      Googleログイン
// @Description  Google OAuthログインページにリダイレクト
// @Tags         oauth
// @Success      302 "Google認証ページにリダイレクト"
// @Router       /auth/oauth/google [get]
func (h *Handler) OAuthGoogle(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to generate state", err.Error())
		return
	}

	authURL := fmt.Sprintf(
		"https://%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=openid+email+profile&identity_provider=Google",
		h.cfg.CognitoDomain,
		h.cfg.CognitoClientID,
		url.QueryEscape(h.cfg.OAuthCallbackURL),
		url.QueryEscape(state),
	)

	c.Redirect(http.StatusFound, authURL)
}

// OAuthCallback godoc
// @Summary      OAuthコールバック
// @Description  Google OAuth認証後のコールバック。認可コードをトークンに交換する。stateが"link:"で始まる場合はアカウントリンクフローに分岐。
// @Tags         oauth
// @Produce      json
// @Param        code  query string true  "認可コード"
// @Param        state query string false "ステートパラメータ"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} ErrorResponse
// @Router       /auth/oauth/callback [get]
func (h *Handler) OAuthCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		errorResponse(c, http.StatusBadRequest, "missing code parameter", "")
		return
	}

	state := c.Query("state")
	if strings.HasPrefix(state, "link:") {
		username := strings.TrimPrefix(state, "link:")
		h.handleLinkCallback(c, code, username)
		return
	}

	cognitoIDToken, err := h.exchangeCognitoCode(c, code)
	if err != nil {
		return
	}

	idToken, err := jwt.Parse([]byte(cognitoIDToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to parse id token", err.Error())
		return
	}

	sub := idToken.Subject()
	var email string
	if v, ok := idToken.Get("email"); ok {
		email, _ = v.(string)
	}
	var groups []string
	if v, ok := idToken.Get("cognito:groups"); ok {
		if gs, ok := v.([]interface{}); ok {
			for _, g := range gs {
				if s, ok := g.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	selfIDToken, err := h.issuer.SignIDToken(sub, email, groups, h.cfg.CognitoClientID, "", 0, []string{"federated"})
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "token signing failed", err.Error())
		return
	}

	selfAccessToken, err := h.issuer.SignAccessToken(sub, []string{"openid", "email", "profile"}, h.cfg.CognitoClientID)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "token signing failed", err.Error())
		return
	}

	redirect := fmt.Sprintf("/pages/dashboard#access_token=%s&id_token=%s",
		url.QueryEscape(selfAccessToken),
		url.QueryEscape(selfIDToken),
	)
	c.Redirect(http.StatusFound, redirect)
}

// exchangeCognitoCode exchanges an OAuth authorization code for Cognito tokens
// and returns the raw ID token string. On error, it writes the HTTP error response.
func (h *Handler) exchangeCognitoCode(c *gin.Context, code string) (string, error) {
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
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to read token response", err.Error())
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		errorResponse(c, http.StatusBadRequest, "token exchange failed", string(body))
		return "", fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to parse token response", err.Error())
		return "", err
	}

	return tokenResp.IDToken, nil
}

// handleLinkCallback handles the OAuth callback when linking a provider to an existing account.
func (h *Handler) handleLinkCallback(c *gin.Context, code, username string) {
	cognitoIDToken, err := h.exchangeCognitoCode(c, code)
	if err != nil {
		return
	}

	idToken, err := jwt.Parse([]byte(cognitoIDToken), jwt.WithVerify(false))
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to parse id token", err.Error())
		return
	}

	googleSub := idToken.Subject()
	if googleSub == "" {
		errorResponse(c, http.StatusInternalServerError, "missing sub in id token", "")
		return
	}

	if err := h.providers.LinkProvider(c.Request.Context(), username, "Google", googleSub); err != nil {
		errorResponse(c, http.StatusInternalServerError, "failed to link provider", err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/pages/dashboard")
}

// Me godoc
// @Summary      ユーザー情報取得
// @Description  認証済みユーザーの情報を返す
// @Tags         user
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} map[string]string
// @Failure      401 {object} ErrorResponse
// @Router       /api/me [get]
func (h *Handler) Me(c *gin.Context) {
	sub, _ := c.Get("user_sub")
	c.JSON(http.StatusOK, gin.H{"sub": sub})
}
