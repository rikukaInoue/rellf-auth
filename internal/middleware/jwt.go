package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/inouetaishi/rellf-auth/internal/domain"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JWTMiddleware struct {
	keySet   jwk.Set
	issuer   string
	clientID string
	local    bool
}

func NewJWTMiddleware(keySet jwk.Set, issuer, clientID string) *JWTMiddleware {
	return &JWTMiddleware{
		keySet:   keySet,
		issuer:   issuer,
		clientID: clientID,
	}
}

func NewLocalJWTMiddleware(keySet jwk.Set, issuer, clientID string) *JWTMiddleware {
	log.Println("WARNING: JWT middleware running in local mode - relaxed validation")
	return &JWTMiddleware{
		keySet:   keySet,
		issuer:   issuer,
		clientID: clientID,
		local:    true,
	}
}

func (m *JWTMiddleware) Verify() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization header format"})
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse([]byte(tokenString),
			jwt.WithKeySet(m.keySet),
			jwt.WithValidate(true),
			jwt.WithIssuer(m.issuer),
		)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid token", "detail": err.Error()})
			return
		}

		tokenUse, ok := token.Get("token_use")
		if !ok || (tokenUse != domain.TokenUseAccess && tokenUse != domain.TokenUseID) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid token_use claim"})
			return
		}

		if tokenUse == domain.TokenUseID {
			audiences := token.Audience()
			found := false
			for _, aud := range audiences {
				if aud == m.clientID {
					found = true
					break
				}
			}
			if !found {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid audience"})
				return
			}
		}

		c.Set("user_sub", token.Subject())
		c.Set("token_claims", token)

		c.Next()
	}
}
