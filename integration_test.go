//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/inouetaishi/rellf-auth/internal/admin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/oidc"
	"github.com/inouetaishi/rellf-auth/internal/router"
)

// setupTestServer creates a real server backed by floci Cognito.
// Requires: make floci-setup (floci running + .env.local written)
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("failed to load config (is floci running? run: make floci-setup): %v", err)
	}

	cognitoClient, err := cognito.New(cfg)
	if err != nil {
		t.Fatalf("failed to create cognito client: %v", err)
	}

	jwtMw := middleware.NewLocalJWTMiddleware(cfg.CognitoClientID)

	tokenIssuer, err := oidc.NewLocalTokenIssuer(cfg.OIDCIssuer)
	if err != nil {
		t.Fatalf("failed to create local token issuer: %v", err)
	}

	authCodeCodec, err := oidc.NewAuthCodeCodec(cfg.OIDCAuthCodeKey)
	if err != nil {
		t.Fatalf("failed to create auth code codec: %v", err)
	}

	oidcClients, err := oidc.ParseClients(cfg.OIDCClients)
	if err != nil {
		t.Fatalf("failed to parse OIDC clients: %v", err)
	}
	clientRegistry := oidc.NewClientRegistry(oidcClients)
	oidcH := oidc.NewOIDCHandler(cognitoClient, tokenIssuer, authCodeCodec, clientRegistry, cfg)

	h := handler.New(cognitoClient, cfg)
	adminH := admin.NewAdminHandler(cognitoClient, cognitoClient, cfg)
	r := router.Setup(h, adminH, oidcH, jwtMw)

	return httptest.NewServer(r)
}

func post(t *testing.T, url string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	return resp
}

func get(t *testing.T, url string, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	return resp
}

func readJSON(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse JSON: %s", string(body))
	}
	return result
}

func TestHealthCheck(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/health", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestSignUpAndLogin(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	email := "integration-test@example.com"
	password := "Test1234!"

	// 1. Sign up
	resp := post(t, ts.URL+"/auth/signup", map[string]string{
		"email": email, "password": password,
	})
	if resp.StatusCode != http.StatusCreated {
		body := readJSON(t, resp)
		t.Fatalf("signup: expected 201, got %d: %v", resp.StatusCode, body)
	}
	signupBody := readJSON(t, resp)
	if signupBody["user_sub"] == nil || signupBody["user_sub"] == "" {
		t.Fatal("signup: missing user_sub")
	}

	// 2. Confirm sign up (floci accepts any code)
	resp = post(t, ts.URL+"/auth/confirm-signup", map[string]string{
		"email": email, "code": "000000",
	})
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("confirm: expected 200, got %d: %v", resp.StatusCode, body)
	}

	// 3. Login
	resp = post(t, ts.URL+"/auth/login", map[string]string{
		"email": email, "password": password,
	})
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("login: expected 200, got %d: %v", resp.StatusCode, body)
	}
	tokens := readJSON(t, resp)

	accessToken, ok := tokens["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("login: missing access_token")
	}
	if tokens["id_token"] == nil || tokens["id_token"] == "" {
		t.Fatal("login: missing id_token")
	}
	if tokens["refresh_token"] == nil || tokens["refresh_token"] == "" {
		t.Fatal("login: missing refresh_token")
	}

	// 4. Access protected endpoint with token
	resp = get(t, ts.URL+"/api/me", accessToken)
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("me: expected 200, got %d: %v", resp.StatusCode, body)
	}
	me := readJSON(t, resp)
	if me["sub"] == nil || me["sub"] == "" {
		t.Fatal("me: missing sub")
	}
}

func TestSignUp_InvalidRequest(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	tests := []struct {
		name   string
		body   map[string]string
		status int
	}{
		{"missing email", map[string]string{"password": "Test1234!"}, http.StatusBadRequest},
		{"invalid email", map[string]string{"email": "bad", "password": "Test1234!"}, http.StatusBadRequest},
		{"short password", map[string]string{"email": "a@b.com", "password": "short"}, http.StatusBadRequest},
		{"empty body", map[string]string{}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := post(t, ts.URL+"/auth/signup", tt.body)
			if resp.StatusCode != tt.status {
				t.Errorf("expected %d, got %d", tt.status, resp.StatusCode)
			}
			resp.Body.Close()
		})
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := post(t, ts.URL+"/auth/login", map[string]string{
		"email": "nonexistent@example.com", "password": "WrongPass1!",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		body := readJSON(t, resp)
		t.Fatalf("expected 401, got %d: %v", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestLogin_InvalidRequest(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := post(t, ts.URL+"/auth/login", map[string]string{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProtectedEndpoint_NoToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/api/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProtectedEndpoint_InvalidToken(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/api/me", "invalid-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestForgotPassword(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Sign up a user first
	email := "forgot-test@example.com"
	resp := post(t, ts.URL+"/auth/signup", map[string]string{
		"email": email, "password": "Test1234!",
	})
	resp.Body.Close()

	resp = post(t, ts.URL+"/auth/confirm-signup", map[string]string{
		"email": email, "code": "000000",
	})
	resp.Body.Close()

	// Request password reset
	resp = post(t, ts.URL+"/auth/forgot-password", map[string]string{
		"email": email,
	})
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("forgot-password: expected 200, got %d: %v", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Confirm password reset (floci accepts any code)
	resp = post(t, ts.URL+"/auth/confirm-forgot-password", map[string]string{
		"email": email, "code": "000000", "new_password": "NewPass1!",
	})
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("confirm-forgot: expected 200, got %d: %v", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Login with new password
	resp = post(t, ts.URL+"/auth/login", map[string]string{
		"email": email, "password": "NewPass1!",
	})
	if resp.StatusCode != http.StatusOK {
		body := readJSON(t, resp)
		t.Fatalf("login with new password: expected 200, got %d: %v", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestOAuthGoogle_Redirect(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/auth/oauth/google")
	if err != nil {
		t.Fatalf("GET oauth/google failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("missing Location header")
	}
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/auth/oauth/callback", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
