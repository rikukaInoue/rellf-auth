package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JWTMiddleware struct {
	keySet   jwk.Set
	issuer   string
	clientID string
	cache    *jwk.Cache
}

func NewJWTMiddleware(region, poolID, clientID string) (*JWTMiddleware, error) {
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, poolID)
	jwksURL := issuer + "/.well-known/jwks.json"

	cache := jwk.NewCache(context.Background())
	if err := cache.Register(jwksURL); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Perform initial fetch
	keySet, err := cache.Get(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return &JWTMiddleware{
		keySet:   keySet,
		issuer:   issuer,
		clientID: clientID,
		cache:    cache,
	}, nil
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

		// Verify token_use claim
		tokenUse, ok := token.Get("token_use")
		if !ok || (tokenUse != "access" && tokenUse != "id") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid token_use claim"})
			return
		}

		// For ID tokens, verify audience matches client ID
		if tokenUse == "id" {
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

		// Set claims in context
		c.Set("user_sub", token.Subject())
		c.Set("token_claims", token)

		c.Next()
	}
}
