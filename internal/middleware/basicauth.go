package middleware

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/gin-gonic/gin"
)

// BasicAuth returns a middleware that performs HTTP Basic Authentication.
// Credentials are compared using constant-time comparison.
func BasicAuth(username, password string) gin.HandlerFunc {
	expectedUser := sha256.Sum256([]byte(username))
	expectedPass := sha256.Sum256([]byte(password))

	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", `Basic realm="restricted"`)
			c.AbortWithStatus(401)
			return
		}

		userHash := sha256.Sum256([]byte(user))
		passHash := sha256.Sum256([]byte(pass))

		userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUser[:])
		passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPass[:])

		if userMatch != 1 || passMatch != 1 {
			c.Header("WWW-Authenticate", `Basic realm="restricted"`)
			c.AbortWithStatus(401)
			return
		}

		c.Next()
	}
}
