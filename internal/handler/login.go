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

	tokens, err := h.auth.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		errorResponse(c, http.StatusUnauthorized, "login failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, tokens)
}
