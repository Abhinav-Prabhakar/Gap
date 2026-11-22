package gap

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func apiKeyRequest(header, value, bearer string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if header != "" {
		request.Header.Set(header, value)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return request
}

func TestAPIKeyAuthTable(t *testing.T) {
	auth := NewAPIKeyAuth(APIKeyAuthOptions{
		Keys: []APIKeyRecord{{
			Key: "secret-key",
			Principal: TestPrincipal(TestPrincipalOptions{
				ID:       "usr_api",
				TenantID: "ten_1",
				Email:    "api@example.com",
			}),
			Scopes: []string{"invoices:read"},
		}},
	})
	tests := []struct {
		name       string
		request    *http.Request
		wantOK     bool
		wantScopes []string
	}{
		{name: "x-api-key", request: apiKeyRequest("X-API-Key", "secret-key", ""), wantOK: true, wantScopes: []string{"*", "invoices:read"}},
		{name: "bearer", request: apiKeyRequest("", "", "secret-key"), wantOK: true},
		{name: "wrong", request: apiKeyRequest("X-API-Key", "nope", ""), wantOK: false},
		{name: "missing", request: apiKeyRequest("", "", ""), wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := auth.Authenticate(test.request)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if test.wantOK && result == nil {
				t.Fatal("expected authentication")
			}
			if !test.wantOK && result != nil {
				t.Fatalf("unexpected authentication: %#v", result)
			}
			if test.wantOK {
				if result.Principal.ID != "usr_api" {
					t.Fatalf("principal = %#v", result.Principal)
				}
				if test.wantScopes != nil && !equalStrings(result.Scopes, test.wantScopes) {
					t.Fatalf("scopes = %#v, want %#v", result.Scopes, test.wantScopes)
				}
				if result.Principal.TenantID != "ten_1" {
					t.Fatalf("tenant = %q", result.Principal.TenantID)
				}
			}
		})
	}
	if !strings.Contains(auth.Challenge(), `realm="gap"`) {
		t.Fatalf("challenge = %q", auth.Challenge())
	}
}

func TestAPIKeyHeaderRestriction(t *testing.T) {
	auth := NewAPIKeyAuth(APIKeyAuthOptions{
		Header: "x-api-key",
		Keys: []APIKeyRecord{{
			Key:       "secret",
			Principal: TestPrincipal(),
		}},
	})
	if result, _ := auth.Authenticate(apiKeyRequest("", "", "secret")); result != nil {
		t.Fatal("bearer token must be ignored when only X-API-Key is allowed")
	}
	if result, _ := auth.Authenticate(apiKeyRequest("X-API-Key", "secret", "")); result == nil {
		t.Fatal("X-API-Key must be accepted")
	}
}

func TestAPIKeyResolver(t *testing.T) {
	auth := NewAPIKeyAuth(APIKeyAuthOptions{
		Resolve: func(request *http.Request) (*APIKeyRecord, error) {
			if request.Header.Get("X-API-Key") == "dynamic" {
				return &APIKeyRecord{
					Key:       "dynamic",
					Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_dynamic"}),
				}, nil
			}
			return nil, nil
		},
	})
	result, err := auth.Authenticate(apiKeyRequest("X-API-Key", "dynamic", ""))
	if err != nil || result == nil || result.Principal.ID != "usr_dynamic" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if result, _ := auth.Authenticate(apiKeyRequest("X-API-Key", "other", "")); result != nil {
		t.Fatal("resolver accepted the wrong key")
	}
}

func TestJWTAuth(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksForRSA(t, &privateKey.PublicKey, "key-1")
	auth, err := NewJWTAuth(JWTAuthOptions{
		Issuer:   "https://issuer.test",
		Audience: []string{"gap"},
		JWKS:     jwks,
	})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}

	valid := signJWT(t, privateKey, "key-1", jwt.MapClaims{
		"sub":       "usr_jwt",
		"iss":       "https://issuer.test",
		"aud":       "gap",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"scope":     "invoices:read reports:read",
		"tenant_id": "ten_9",
		"email":     "jwt@example.com",
	})
	result, err := auth.Authenticate(apiKeyRequest("", "", valid))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result == nil {
		t.Fatal("expected authentication")
	}
	if result.Principal.ID != "usr_jwt" || result.Principal.TenantID != "ten_9" {
		t.Fatalf("principal = %#v", result.Principal)
	}
	if !equalStrings(result.Scopes, []string{"invoices:read", "reports:read"}) {
		t.Fatalf("scopes = %#v", result.Scopes)
	}
	if result.ExpiresAt == 0 {
		t.Fatal("missing expiry")
	}

	expired := signJWT(t, privateKey, "key-1", jwt.MapClaims{
		"sub": "usr_jwt",
		"iss": "https://issuer.test",
		"aud": "gap",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	if result, _ := auth.Authenticate(apiKeyRequest("", "", expired)); result != nil {
		t.Fatal("expired token was accepted")
	}

	wrongAudience := signJWT(t, privateKey, "key-1", jwt.MapClaims{
		"sub": "usr_jwt",
		"iss": "https://issuer.test",
		"aud": "other",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if result, _ := auth.Authenticate(apiKeyRequest("", "", wrongAudience)); result != nil {
		t.Fatal("wrong audience was accepted")
	}

	wrongIssuer := signJWT(t, privateKey, "key-1", jwt.MapClaims{
		"sub": "usr_jwt",
		"iss": "https://evil.test",
		"aud": "gap",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if result, _ := auth.Authenticate(apiKeyRequest("", "", wrongIssuer)); result != nil {
		t.Fatal("wrong issuer was accepted")
	}

	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "usr_jwt",
		"aud": "gap",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	unsigned, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if result, _ := auth.Authenticate(apiKeyRequest("", "", unsigned)); result != nil {
		t.Fatal("alg=none token was accepted")
	}
}

func TestJWTAuthMapClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewJWTAuth(JWTAuthOptions{
		JWKS: jwksForRSA(t, &privateKey.PublicKey, "key-1"),
		MapClaims: func(claims map[string]any) (*Principal, error) {
			return &Principal{
				ID:     "mapped:" + stringClaim(claims["sub"]),
				Type:   PrincipalService,
				Scopes: []string{"mapped:read"},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signJWT(t, privateKey, "key-1", jwt.MapClaims{
		"sub": "abc",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	result, err := auth.Authenticate(apiKeyRequest("", "", token))
	if err != nil || result == nil {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if result.Principal.ID != "mapped:abc" || result.Principal.Type != PrincipalService {
		t.Fatalf("principal = %#v", result.Principal)
	}
}

func TestJWTAuthJWKSURI(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	document := jwksForRSA(t, &privateKey.PublicKey, "remote")
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	defer httpServer.Close()

	auth, err := NewJWTAuth(JWTAuthOptions{JWKSURI: httpServer.URL})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}
	token := signJWT(t, privateKey, "remote", jwt.MapClaims{
		"sub": "usr_remote",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	result, err := auth.Authenticate(apiKeyRequest("", "", token))
	if err != nil || result == nil || result.Principal.ID != "usr_remote" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestComposeAuth(t *testing.T) {
	apiKey := NewAPIKeyAuth(APIKeyAuthOptions{
		Keys: []APIKeyRecord{{Key: "key", Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_key"})}},
	})
	composed := ComposeAuth(apiKey, NewAPIKeyAuth(APIKeyAuthOptions{
		Keys: []APIKeyRecord{{Key: "other", Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_other"})}},
	}))
	result, err := composed.Authenticate(apiKeyRequest("X-API-Key", "other", ""))
	if err != nil || result == nil || result.Principal.ID != "usr_other" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if result, _ := composed.Authenticate(apiKeyRequest("X-API-Key", "missing", "")); result != nil {
		t.Fatal("composed auth accepted an unknown key")
	}
	if !strings.Contains(composed.(AuthChallenger).Challenge(), "Bearer") {
		t.Fatal("composed auth has no challenge")
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	document := ProtectedResourceMetadata(ProtectedResourceMetadataOptions{
		Resource:              "https://app.example.com",
		AuthorizationServers:  []string{"https://auth.example.com"},
		ScopesSupported:       []string{"invoices:read"},
		ResourceDocumentation: "https://app.example.com/docs",
	})
	if document["resource"] != "https://app.example.com" {
		t.Fatalf("document = %#v", document)
	}
	methods, _ := document["bearer_methods_supported"].([]string)
	if len(methods) != 1 || methods[0] != "header" {
		t.Fatalf("methods = %#v", document["bearer_methods_supported"])
	}
	servers, _ := document["authorization_servers"].([]string)
	if len(servers) != 1 {
		t.Fatalf("servers = %#v", servers)
	}
}

func TestBearerChallengeAndToken(t *testing.T) {
	challenge := BearerChallenge(BearerChallengeOptions{
		Realm:               `gap "quoted"`,
		Error:               "invalid_token",
		ResourceMetadataURL: "https://app.example.com/.well-known/oauth-protected-resource",
	})
	if !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, `realm="gap \"quoted\""`) {
		t.Fatalf("challenge = %q", challenge)
	}
	if !strings.Contains(challenge, `resource_metadata="https://app.example.com/.well-known/oauth-protected-resource"`) {
		t.Fatalf("challenge = %q", challenge)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "bEaReR token-value")
	if got := ReadBearerToken(request); got != "token-value" {
		t.Fatalf("ReadBearerToken = %q", got)
	}
	request.Header.Set("Authorization", "Basic abc")
	if got := ReadBearerToken(request); got != "" {
		t.Fatalf("ReadBearerToken = %q", got)
	}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func jwksForRSA(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
