package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
)

// OIDCHandler handles all OIDC Provider endpoints.
type OIDCHandler struct {
	cognito   cognito.Service
	issuer    *TokenIssuer
	codec     *AuthCodeCodec
	clients   *ClientRegistry
	cfg       *config.Config
	templates *template.Template
	staticFS  fs.FS
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(
	cognitoSvc cognito.Service,
	issuer *TokenIssuer,
	codec *AuthCodeCodec,
	clients *ClientRegistry,
	cfg *config.Config,
) *OIDCHandler {
	return &OIDCHandler{
		cognito:   cognitoSvc,
		issuer:    issuer,
		codec:     codec,
		clients:   clients,
		cfg:       cfg,
		templates: parseTemplates(),
		staticFS:  staticSubFS(),
	}
}

// StaticFS returns the embedded static file system for serving CSS/JS.
func (h *OIDCHandler) StaticFS() http.FileSystem {
	return http.FS(h.staticFS)
}

// Discovery serves the OpenID Connect Discovery document.
func (h *OIDCHandler) Discovery(c *gin.Context) {
	iss := h.issuer.Issuer()
	c.JSON(http.StatusOK, gin.H{
		"issuer":                 iss,
		"authorization_endpoint": iss + "/oidc/authorize",
		"token_endpoint":         iss + "/oidc/token",
		"userinfo_endpoint":      iss + "/oidc/userinfo",
		"jwks_uri":               iss + "/oidc/jwks.json",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code"},
		"subject_types_supported":  []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":        []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// JWKS serves the JSON Web Key Set (public keys).
func (h *OIDCHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.issuer.JWKS())
}

// loginPageData holds template data for the login page.
type loginPageData struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Email               string
	Error               string
}

// Authorize renders the login page (GET /oidc/authorize).
func (h *OIDCHandler) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	if _, err := h.clients.Validate(clientID, redirectURI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	data := loginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	h.templates.ExecuteTemplate(c.Writer, "login.html", data)
}

// AuthorizeSubmit handles the login form submission (POST /oidc/authorize).
func (h *OIDCHandler) AuthorizeSubmit(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	responseType := c.PostForm("response_type")
	scope := c.PostForm("scope")
	state := c.PostForm("state")
	nonce := c.PostForm("nonce")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")

	if _, err := h.clients.Validate(clientID, redirectURI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Authenticate via Cognito
	tokens, err := h.cognito.Login(c.Request.Context(), email, password)
	if err != nil {
		data := loginPageData{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			ResponseType:        responseType,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Email:               email,
			Error:               "メールアドレスまたはパスワードが正しくありません",
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusOK)
		h.templates.ExecuteTemplate(c.Writer, "login.html", data)
		return
	}

	// Extract sub and email from Cognito ID token (trusted, no sig verification needed)
	idToken, err := jwt.Parse([]byte(tokens.IDToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to parse ID token"})
		return
	}

	sub := idToken.Subject()
	emailClaim := ""
	if v, ok := idToken.Get("email"); ok {
		emailClaim, _ = v.(string)
	}

	// Extract groups
	var groups []string
	if v, ok := idToken.Get("cognito:groups"); ok {
		if gs, ok := v.([]interface{}); ok {
			for _, g := range gs {
				if s, ok := g.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	scopes := strings.Split(scope, " ")

	// Build authorization code
	payload := &AuthCodePayload{
		Sub:                 sub,
		Email:               emailClaim,
		Groups:              groups,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute).Unix(),
	}

	code, err := h.codec.Encode(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to generate auth code"})
		return
	}

	// Redirect with code and state
	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}
	c.Redirect(http.StatusFound, redirect)
}

// Token exchanges an authorization code for tokens (POST /oidc/token).
func (h *OIDCHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	codeVerifier := c.PostForm("code_verifier")

	// Decode authorization code
	payload, err := h.codec.Decode(code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid or expired authorization code"})
		return
	}

	// Validate client
	if payload.ClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client_id mismatch"})
		return
	}

	client, err := h.clients.ValidateSecret(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	// Validate redirect_uri
	if payload.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}

	// PKCE verification
	if payload.CodeChallenge != "" {
		if codeVerifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code_verifier required"})
			return
		}
		if !verifyPKCE(payload.CodeChallenge, payload.CodeChallengeMethod, codeVerifier) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	} else if client.IsPublic() {
		// Public clients must use PKCE
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "public clients must use PKCE"})
		return
	}

	// Sign tokens
	idToken, err := h.issuer.SignIDToken(payload.Sub, payload.Email, payload.Groups, clientID, payload.Nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	accessToken, err := h.issuer.SignAccessToken(payload.Sub, payload.Scopes, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// UserInfo returns claims for the authenticated user (GET /oidc/userinfo).
func (h *OIDCHandler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		c.Header("WWW-Authenticate", "Bearer")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	tokenString := authHeader[7:]

	// Verify the access token using the issuer's public key
	jwks := h.issuer.JWKS()
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(jwks),
		jwt.WithValidate(true),
		jwt.WithIssuer(h.issuer.Issuer()),
	)
	if err != nil {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// Verify it's an access token
	tokenUse, _ := token.Get("token_use")
	if tokenUse != "access" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "not an access token"})
		return
	}

	// Build userinfo response from the access token claims
	// For richer data, we could call Cognito AdminGetUser here
	resp := gin.H{
		"sub": token.Subject(),
	}

	// Add scopes-dependent claims
	if scopes, ok := token.Get("scope"); ok {
		if scopeList, ok := scopes.([]interface{}); ok {
			for _, s := range scopeList {
				if str, ok := s.(string); ok && str == "email" {
					// We need to get email from Cognito since access token doesn't carry it
					// For now, return sub; email enrichment can be added later
					resp["email_verified"] = true
				}
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// verifyPKCE checks that code_verifier matches code_challenge.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// VerifyAccessToken parses and validates an access token issued by this OIDC provider.
// Returns the parsed JWT token or an error.
func (h *OIDCHandler) VerifyAccessToken(tokenString string) (jwt.Token, error) {
	return jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(h.issuer.JWKS()),
		jwt.WithValidate(true),
		jwt.WithIssuer(h.issuer.Issuer()),
	)
}

// PublicJWKS returns the public JWKS for use by middleware.
func (h *OIDCHandler) PublicJWKS() jwk.Set {
	return h.issuer.JWKS()
}

// IssuerURL returns the OIDC issuer URL.
func (h *OIDCHandler) IssuerURL() string {
	return h.issuer.Issuer()
}
