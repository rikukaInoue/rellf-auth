package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/inouetaishi/rellf-auth/internal/domain"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// VerifyAdminCookie returns a Gin middleware that authenticates admin users
// via a JWT stored in the "admin_token" cookie and checks for "admin" group membership.
func (m *JWTMiddleware) VerifyAdminCookie() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("admin_token")
		if err != nil || tokenString == "" {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		token, err := jwt.Parse([]byte(tokenString),
			jwt.WithKeySet(m.keySet),
			jwt.WithValidate(true),
			jwt.WithIssuer(m.issuer),
		)

		if err != nil {
			secure := !m.local
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie("admin_token", "", -1, "/admin", "", secure, true)
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		// Check "groups" claim for "admin" (self-issued tokens use "groups", not "cognito:groups")
		groupsRaw, ok := token.Get("groups")
		if !ok || !containsAdmin(groupsRaw) {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		c.Set("admin_user", token.Subject())
		c.Set("token_claims", token)
		c.Next()
	}
}

func containsAdmin(groupsRaw interface{}) bool {
	switch groups := groupsRaw.(type) {
	case []interface{}:
		for _, g := range groups {
			if s, ok := g.(string); ok && s == domain.GroupAdmin {
				return true
			}
		}
	case []string:
		for _, g := range groups {
			if g == domain.GroupAdmin {
				return true
			}
		}
	case string:
		return groups == domain.GroupAdmin
	}
	return false
}
