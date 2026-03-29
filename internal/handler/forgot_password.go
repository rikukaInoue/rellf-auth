package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPassword godoc
// @Summary      パスワードリセット要求
// @Description  パスワードリセット用の確認コードをメールで送信
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ForgotPasswordRequest true "メールアドレス"
// @Success      200 {object} map[string]string
// @Failure      400 {object} ErrorResponse
// @Router       /auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	if err := h.auth.ForgotPassword(c.Request.Context(), req.Email); err != nil {
		errorResponse(c, http.StatusBadRequest, "forgot password failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset code sent"})
}

type ConfirmForgotPasswordRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ConfirmForgotPassword godoc
// @Summary      パスワードリセット確認
// @Description  確認コードと新しいパスワードでパスワードをリセット
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ConfirmForgotPasswordRequest true "リセット情報"
// @Success      200 {object} map[string]string
// @Failure      400 {object} ErrorResponse
// @Router       /auth/confirm-forgot-password [post]
func (h *Handler) ConfirmForgotPassword(c *gin.Context) {
	var req ConfirmForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	if err := h.auth.ConfirmForgotPassword(c.Request.Context(), req.Email, req.Code, req.NewPassword); err != nil {
		errorResponse(c, http.StatusBadRequest, "password reset failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}
