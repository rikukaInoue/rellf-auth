package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type SignUpRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// SignUp godoc
// @Summary      ユーザー登録
// @Description  メールアドレスとパスワードで新規ユーザーを登録。登録後に確認コードがメールで送信される。
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body SignUpRequest true "登録情報"
// @Success      201 {object} SignUpResponse
// @Failure      400 {object} ErrorResponse
// @Router       /auth/signup [post]
func (h *Handler) SignUp(c *gin.Context) {
	var req SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	result, err := h.auth.SignUp(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		errorResponse(c, http.StatusBadRequest, "signup failed", err.Error())
		return
	}

	c.JSON(http.StatusCreated, result)
}

type ConfirmSignUpRequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

// ConfirmSignUp godoc
// @Summary      メール確認
// @Description  サインアップ時に送信された確認コードでメールアドレスを検証
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ConfirmSignUpRequest true "確認情報"
// @Success      200 {object} map[string]string
// @Failure      400 {object} ErrorResponse
// @Router       /auth/confirm-signup [post]
func (h *Handler) ConfirmSignUp(c *gin.Context) {
	var req ConfirmSignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	if err := h.auth.ConfirmSignUp(c.Request.Context(), req.Email, req.Code); err != nil {
		errorResponse(c, http.StatusBadRequest, "confirmation failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email confirmed successfully"})
}
