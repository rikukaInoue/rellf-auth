package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login godoc
// @Summary      ログイン
// @Description  メールアドレスとパスワードでログインし、JWTトークンを取得
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "ログイン情報"
// @Success      200 {object} AuthTokensResponse
// @Failure      401 {object} ErrorResponse
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	user, err := h.authUC.Authenticate(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		errorResponse(c, http.StatusUnauthorized, "login failed", err.Error())
		return
	}

	idToken, err := h.issuer.SignIDToken(user.Sub, user.Email, user.Groups, h.cfg.CognitoClientID, "", 0, []string{"pwd"})
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "token signing failed", err.Error())
		return
	}

	accessToken, err := h.issuer.SignAccessToken(user.Sub, []string{"openid", "email", "profile"}, h.cfg.CognitoClientID)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, "token signing failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, AuthTokensResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   900,
	})
}
