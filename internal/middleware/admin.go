package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
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

		var token jwt.Token

		if m.local {
			token, err = jwt.Parse([]byte(tokenString),
				jwt.WithVerify(false),
				jwt.WithValidate(true),
			)
		} else {
			token, err = jwt.Parse([]byte(tokenString),
				jwt.WithKeySet(m.keySet),
				jwt.WithValidate(true),
				jwt.WithIssuer(m.issuer),
			)
		}

		if err != nil {
			secure := !m.local
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie("admin_token", "", -1, "/admin", "", secure, true)
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		// Check cognito:groups for "admin"
		// In local mode, floci may not include groups in tokens, so skip the check
		if !m.local {
			groupsRaw, ok := token.Get("cognito:groups")
			if !ok || !containsAdmin(groupsRaw) {
				c.Redirect(http.StatusFound, "/admin/login")
				c.Abort()
				return
			}
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
			if s, ok := g.(string); ok && s == "admin" {
				return true
			}
		}
	case []string:
		for _, g := range groups {
			if g == "admin" {
				return true
			}
		}
	case string:
		return groups == "admin"
	}
	return false
}
