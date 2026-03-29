package router

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
)

func Setup(h *handler.Handler, jwtMw *middleware.JWTMiddleware) *gin.Engine {
	r := gin.Default()

	r.GET("/health", h.HealthCheck)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	auth := r.Group("/auth")
	{
		auth.POST("/signup", h.SignUp)
		auth.POST("/confirm-signup", h.ConfirmSignUp)
		auth.POST("/login", h.Login)
		auth.POST("/forgot-password", h.ForgotPassword)
		auth.POST("/confirm-forgot-password", h.ConfirmForgotPassword)

		auth.GET("/oauth/google", h.OAuthGoogle)
		auth.GET("/oauth/callback", h.OAuthCallback)
	}

	// Protected routes
	protected := r.Group("/api")
	protected.Use(jwtMw.Verify())
	{
		protected.GET("/me", h.Me)
		protected.GET("/providers", h.GetProviders)
		protected.GET("/link/google", h.LinkGoogle)
		protected.DELETE("/link/:provider", h.UnlinkProvider)
	}

	return r
}
