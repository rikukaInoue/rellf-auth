//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/inouetaishi/rellf-auth/internal/admin"
	"github.com/inouetaishi/rellf-auth/internal/cognito"
	"github.com/inouetaishi/rellf-auth/internal/config"
	"github.com/inouetaishi/rellf-auth/internal/handler"
	"github.com/inouetaishi/rellf-auth/internal/middleware"
	"github.com/inouetaishi/rellf-auth/internal/oidc"
	"github.com/inouetaishi/rellf-auth/internal/router"
)

func setupOIDCTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
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

// ensureOIDCTestUser creates and confirms a test user for OIDC tests.
func ensureOIDCTestUser(t *testing.T, baseURL, email, password string) {
	t.Helper()

	resp := post(t, baseURL+"/auth/signup", map[string]string{
		"email": email, "password": password,
	})
	resp.Body.Close()

	resp = post(t, baseURL+"/auth/confirm-signup", map[string]string{
		"email": email, "code": "000000",
	})
	resp.Body.Close()
}

func TestOIDC_Discovery(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/.well-known/openid-configuration", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := readJSON(t, resp)

	// Verify required fields
	requiredFields := []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "jwks_uri",
	}
	for _, field := range requiredFields {
		if body[field] == nil {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify response_types_supported
	if rt, ok := body["response_types_supported"].([]interface{}); !ok || len(rt) == 0 {
		t.Error("missing or empty response_types_supported")
	}
}

func TestOIDC_JWKS(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/jwks.json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := readJSON(t, resp)
	keys, ok := body["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatal("JWKS must contain at least one key")
	}

	// Check first key has required fields
	key := keys[0].(map[string]interface{})
	for _, field := range []string{"kty", "kid", "n", "e"} {
		if key[field] == nil {
			t.Errorf("key missing field: %s", field)
		}
	}
}

func TestOIDC_Authorize_ShowsLoginPage(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid+email&state=test123", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// Should contain form elements
	if !strings.Contains(bodyStr, `name="email"`) {
		t.Error("login page missing email field")
	}
	if !strings.Contains(bodyStr, `name="password"`) {
		t.Error("login page missing password field")
	}
	if !strings.Contains(bodyStr, `value="test-client"`) {
		t.Error("login page missing client_id hidden field")
	}
}

func TestOIDC_Authorize_InvalidClient(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/authorize?client_id=unknown&redirect_uri=http://evil.com/callback&response_type=code&scope=openid", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid client, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDC_Authorize_InvalidResponseType(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=token&scope=openid", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported response_type, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDC_AuthorizationCodeFlow(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	email := "oidc-test@example.com"
	password := "Test1234!"
	ensureOIDCTestUser(t, ts.URL, email, password)

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Generate PKCE pair (public client requires PKCE)
	codeVerifier := "test-verifier-for-authorization-code-flow-test-1234"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Step 1: POST /oidc/authorize with credentials
	form := url.Values{
		"email":                 {email},
		"password":              {password},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {"mystate123"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := noRedirect.PostForm(ts.URL+"/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST /oidc/authorize failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302 redirect, got %d: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("missing Location header")
	}

	// Parse redirect URL to extract code and state
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}

	code := redirectURL.Query().Get("code")
	state := redirectURL.Query().Get("state")
	if code == "" {
		t.Fatal("missing code in redirect")
	}
	if state != "mystate123" {
		t.Fatalf("state mismatch: got %q, want %q", state, "mystate123")
	}

	// Step 2: POST /oidc/token to exchange code for tokens
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"code_verifier": {codeVerifier},
	}

	tokenResp, err := http.PostForm(ts.URL+"/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST /oidc/token failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token exchange: expected 200, got %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokens map[string]interface{}
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	if err := json.Unmarshal(tokenBody, &tokens); err != nil {
		t.Fatalf("failed to parse token response: %v", err)
	}

	// Verify token response fields
	if tokens["access_token"] == nil || tokens["access_token"] == "" {
		t.Fatal("missing access_token")
	}
	if tokens["id_token"] == nil || tokens["id_token"] == "" {
		t.Fatal("missing id_token")
	}
	if tokens["token_type"] != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %v", tokens["token_type"])
	}

	// Step 3: GET /oidc/userinfo with access token
	accessToken := tokens["access_token"].(string)
	userInfoResp := get(t, ts.URL+"/oidc/userinfo", accessToken)
	if userInfoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userInfoResp.Body)
		t.Fatalf("userinfo: expected 200, got %d: %s", userInfoResp.StatusCode, string(body))
	}

	userInfo := readJSON(t, userInfoResp)
	if userInfo["sub"] == nil || userInfo["sub"] == "" {
		t.Fatal("userinfo: missing sub")
	}
}

func TestOIDC_AuthorizationCodeFlow_PKCE(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	email := "oidc-pkce@example.com"
	password := "Test1234!"
	ensureOIDCTestUser(t, ts.URL, email, password)

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Generate PKCE pair
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Step 1: POST /oidc/authorize with PKCE
	form := url.Values{
		"email":                 {email},
		"password":              {password},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {"pkce-state"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	resp, err := noRedirect.PostForm(ts.URL+"/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST /oidc/authorize failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302, got %d: %s", resp.StatusCode, string(body))
	}

	redirectURL, _ := url.Parse(resp.Header.Get("Location"))
	code := redirectURL.Query().Get("code")

	// Step 2: Exchange with correct code_verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"code_verifier": {codeVerifier},
	}

	tokenResp, err := http.PostForm(ts.URL+"/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST /oidc/token failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("PKCE token exchange: expected 200, got %d: %s", tokenResp.StatusCode, string(body))
	}
}

func TestOIDC_PKCE_WrongVerifier(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	email := "oidc-pkce-bad@example.com"
	password := "Test1234!"
	ensureOIDCTestUser(t, ts.URL, email, password)

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	codeVerifier := "correct-verifier-value-that-is-long-enough-for-pkce"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	form := url.Values{
		"email":                 {email},
		"password":              {password},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	resp, _ := noRedirect.PostForm(ts.URL+"/oidc/authorize", form)
	resp.Body.Close()
	redirectURL, _ := url.Parse(resp.Header.Get("Location"))
	code := redirectURL.Query().Get("code")

	// Use wrong verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"test-client"},
		"code_verifier": {"wrong-verifier-should-fail"},
	}

	tokenResp, _ := http.PostForm(ts.URL+"/oidc/token", tokenForm)
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong verifier, got %d", tokenResp.StatusCode)
	}
}

func TestOIDC_Token_ExpiredCode(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	// Use a completely invalid code
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"invalid-code-value"},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"test-client"},
	}

	tokenResp, err := http.PostForm(ts.URL+"/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST /oidc/token failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid code, got %d", tokenResp.StatusCode)
	}
}

func TestOIDC_Token_WrongGrantType(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	tokenForm := url.Values{
		"grant_type": {"client_credentials"},
	}

	tokenResp, err := http.PostForm(ts.URL+"/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST /oidc/token failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported grant type, got %d", tokenResp.StatusCode)
	}
}

func TestOIDC_Authorize_WrongPassword(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	email := "oidc-wrongpw@example.com"
	password := "Test1234!"
	ensureOIDCTestUser(t, ts.URL, email, password)

	form := url.Values{
		"email":         {email},
		"password":      {"WrongPassword1!"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}

	resp, err := http.PostForm(ts.URL+"/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST /oidc/authorize failed: %v", err)
	}
	defer resp.Body.Close()

	// Should re-render login page (200) with error, not redirect
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (login page with error), got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "メールアドレスまたはパスワードが正しくありません") {
		t.Error("expected error message in login page")
	}
}

func TestOIDC_UserInfo_NoToken(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/userinfo", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDC_UserInfo_InvalidToken(t *testing.T) {
	ts := setupOIDCTestServer(t)
	defer ts.Close()

	resp := get(t, ts.URL+"/oidc/userinfo", "invalid-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
