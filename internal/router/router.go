package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/inouetaishi/rellf-auth/internal/admin"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/oidc"
	"github.com/inouetaishi/rellf-auth/internal/pages"
)

func Setup(h *handler.Handler, adminH *admin.AdminHandler, oidcH *oidc.OIDCHandler, jwtMw *middleware.JWTMiddleware, cfg *config.Config) *gin.Engine {
	r := gin.Default()
	r.Use(middleware.SecurityHeaders())
	if cfg.CORSOrigins != "" {
		origins := strings.Split(cfg.CORSOrigins, ",")
		r.Use(middleware.CORS(origins))
	}

	// Public endpoints (no basic auth)
	r.GET("/health", h.HealthCheck)
	r.GET("/.well-known/openid-configuration", oidcH.Discovery)
	r.GET("/oidc/jwks.json", oidcH.JWKS)

	// OIDC Provider endpoints (no basic auth — used by external clients)
	r.GET("/oidc/authorize", oidcH.Authorize)
	r.POST("/oidc/authorize", oidcH.AuthorizeSubmit)
	r.POST("/oidc/token", oidcH.Token)
	r.GET("/oidc/userinfo", oidcH.UserInfo)
	r.StaticFS("/oidc/static", oidcH.StaticFS())

	// Auth API (no basic auth — called via fetch from pages)
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

	// Protected API (JWT required — no basic auth needed)
	protected := r.Group("/api")
	protected.Use(jwtMw.Verify())
	{
		protected.GET("/me", h.Me)
		protected.GET("/providers", h.GetProviders)
		protected.GET("/link/google", h.LinkGoogle)
		protected.DELETE("/link/:provider", h.UnlinkProvider)
	}

	// Apply basic auth to UI routes when configured
	if cfg.BasicAuthEnabled() {
		r.Use(middleware.BasicAuth(cfg.BasicAuthUser, cfg.BasicAuthPass))
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// User pages (provisional)
	pagesH := pages.NewPagesHandler()
	r.GET("/pages/login", pagesH.LoginPage)
	r.GET("/pages/signup", pagesH.SignupPage)
	r.GET("/pages/dashboard", pagesH.DashboardPage)
	r.StaticFS("/pages/static", http.FS(pagesH.StaticFS()))

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
