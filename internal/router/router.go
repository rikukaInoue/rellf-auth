package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/inouetaishi/rellf-auth/internal/admin"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
)

func Setup(h *handler.Handler, adminH *admin.AdminHandler, jwtMw *middleware.JWTMiddleware) *gin.Engine {
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

	// Admin panel
	r.GET("/admin/login", adminH.LoginPage)
	r.POST("/admin/login", adminH.LoginSubmit)
	r.StaticFS("/admin/static", http.FS(adminH.StaticFS()))

	adminGroup := r.Group("/admin")
	adminGroup.Use(jwtMw.VerifyAdminCookie())
	{
		adminGroup.POST("/logout", adminH.Logout)
		adminGroup.GET("/users", adminH.ListUsers)
		adminGroup.GET("/users/new", adminH.CreateUserPage)
		adminGroup.POST("/users/new", adminH.CreateUserSubmit)
		adminGroup.GET("/users/:username", adminH.UserDetail)
		adminGroup.POST("/users/:username/confirm", adminH.ConfirmUser)
		adminGroup.POST("/users/:username/reset-password", adminH.ResetPassword)
		adminGroup.POST("/users/:username/disable", adminH.DisableUser)
		adminGroup.POST("/users/:username/enable", adminH.EnableUser)
		adminGroup.POST("/users/:username/delete", adminH.DeleteUser)
	}

	return r
}
