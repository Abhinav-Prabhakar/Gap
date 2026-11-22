package gap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthProvider authenticates an HTTP request. Returning (nil, nil) means "no
// credentials matched"; an error means authentication could not be attempted
// and the request must fail closed.
type AuthProvider interface {
	Authenticate(*http.Request) (*AuthResult, error)
}

// AuthChallenger optionally supplies the WWW-Authenticate value on a 401.
type AuthChallenger interface {
	Challenge() string
}

// ProtectedResourceMetadataProvider optionally supplies an RFC 9728 document.
type ProtectedResourceMetadataProvider interface {
	ProtectedResourceMetadata() map[string]any
}

// APIKeyRecord is a static API key and the identity it authenticates.
type APIKeyRecord struct {
	Key       string    `json:"key"`
	Principal Principal `json:"principal"`
	Scopes    []string  `json:"scopes,omitempty"`
}

// APIKeyResolver resolves a key record for a request. Returning (nil, nil)
// rejects the request. Implementations normally look the key up by digest.
type APIKeyResolver func(*http.Request) (*APIKeyRecord, error)

// APIKeyAuthOptions configures APIKeyAuth.
type APIKeyAuthOptions struct {
	// Keys are static records. Empty keys are ignored.
	Keys []APIKeyRecord
	// Resolve can replace static lookup. It is called with the raw request.
	Resolve APIKeyResolver
	// Header restricts extraction. "" accepts both, "authorization" accepts
	// only Bearer, and "x-api-key" accepts only X-API-Key.
	Header string
	// Realm is used in the bearer challenge. Defaults to "gap".
	Realm string
}

type preparedAPIKey struct {
	record APIKeyRecord
	digest [32]byte
}

// APIKeyAuth authenticates API keys with constant-time digest comparison.
type APIKeyAuth struct {
	records []preparedAPIKey
	resolve APIKeyResolver
	header  string
	realm   string
}

// NewAPIKeyAuth builds an API key provider.
func NewAPIKeyAuth(options APIKeyAuthOptions) *APIKeyAuth {
	auth := &APIKeyAuth{
		resolve: options.Resolve,
		header:  strings.ToLower(strings.TrimSpace(options.Header)),
		realm:   options.Realm,
	}
	if auth.realm == "" {
		auth.realm = "gap"
	}
	if options.Header != "" && auth.header != "authorization" && auth.header != "x-api-key" {
		auth.header = ""
	}
	for _, record := range options.Keys {
		if record.Key == "" {
			continue
		}
		auth.records = append(auth.records, preparedAPIKey{record: cloneAPIKeyRecord(record), digest: sha256.Sum256([]byte(record.Key))})
	}
	return auth
}

func cloneAPIKeyRecord(record APIKeyRecord) APIKeyRecord {
	record.Principal = record.Principal.Clone()
	record.Scopes = append([]string(nil), record.Scopes...)
	return record
}

// Authenticate implements AuthProvider.
func (a *APIKeyAuth) Authenticate(request *http.Request) (*AuthResult, error) {
	if a == nil || request == nil {
		return nil, nil
	}
	candidates := apiKeyCandidates(request, a.header)
	if len(candidates) == 0 {
		return nil, nil
	}
	if a.resolve != nil {
		record, err := a.resolve(request)
		if err != nil {
			return nil, err
		}
		if record == nil || record.Key == "" {
			return nil, nil
		}
		expected := sha256.Sum256([]byte(record.Key))
		for _, candidate := range candidates {
			presented := sha256.Sum256([]byte(candidate))
			if subtle.ConstantTimeCompare(presented[:], expected[:]) == 1 {
				return apiKeyResult(cloneAPIKeyRecord(*record), candidate), nil
			}
		}
		return nil, nil
	}
	for _, candidate := range candidates {
		presented := sha256.Sum256([]byte(candidate))
		var matched *APIKeyRecord
		for index := range a.records {
			if subtle.ConstantTimeCompare(presented[:], a.records[index].digest[:]) == 1 && matched == nil {
				record := cloneAPIKeyRecord(a.records[index].record)
				matched = &record
			}
		}
		if matched != nil {
			return apiKeyResult(*matched, candidate), nil
		}
	}
	return nil, nil
}

// Challenge implements AuthChallenger.
func (a *APIKeyAuth) Challenge() string {
	realm := "gap"
	if a != nil && a.realm != "" {
		realm = a.realm
	}
	return BearerChallenge(BearerChallengeOptions{Realm: realm})
}

func apiKeyCandidates(request *http.Request, header string) []string {
	var out []string
	if header == "" || header == "authorization" {
		if token := ReadBearerToken(request); token != "" {
			out = append(out, token)
		}
	}
	if header == "" || header == "x-api-key" {
		if value := strings.TrimSpace(request.Header.Get("X-API-Key")); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func apiKeyResult(record APIKeyRecord, token string) *AuthResult {
	scopes := MergeScopes(record.Principal.Scopes, record.Scopes)
	principal := record.Principal.Clone()
	if len(record.Principal.Scopes) > 0 || len(record.Scopes) > 0 {
		principal.Scopes = scopes
	}
	return &AuthResult{Principal: principal, Token: token, ClientID: principal.ID, Scopes: scopes}
}

// JWTAuthOptions configures JWTAuth.
type JWTAuthOptions struct {
	// Issuer is required when set.
	Issuer string
	// Audience accepts any of the listed audiences.
	Audience []string
	// JWKSURI is an HTTPS JWKS document fetched once at construction.
	JWKSURI string
	// JWKS is a locally supplied JWKS document. It takes precedence.
	JWKS []byte
	// ClockTolerance permits clock skew for exp/nbf/iat.
	ClockTolerance time.Duration
	// MapClaims maps verified claims to a principal. Returning an error rejects
	// the token. When nil, standard claims are mapped.
	MapClaims func(map[string]any) (*Principal, error)
	// Keyfunc overrides JWKS key resolution entirely.
	Keyfunc jwt.Keyfunc
	// Realm is used in the bearer challenge. Defaults to "gap".
	Realm string
	// HTTPClient fetches JWKSURI. Defaults to a 10 second client.
	HTTPClient *http.Client
}

// JWTAuth verifies bearer JWTs with golang-jwt and a JWKS or custom keyfunc.
type JWTAuth struct {
	issuer    string
	audience  []string
	keyfunc   jwt.Keyfunc
	tolerance time.Duration
	mapClaims func(map[string]any) (*Principal, error)
	realm     string
}

// NewJWTAuth builds a JWT provider. It requires either Keyfunc, JWKS, or
// JWKSURI; JWKS is parsed eagerly so configuration mistakes surface at startup.
func NewJWTAuth(options JWTAuthOptions) (*JWTAuth, error) {
	auth := &JWTAuth{
		issuer:    options.Issuer,
		audience:  append([]string(nil), options.Audience...),
		keyfunc:   options.Keyfunc,
		tolerance: options.ClockTolerance,
		mapClaims: options.MapClaims,
		realm:     options.Realm,
	}
	if auth.realm == "" {
		auth.realm = "gap"
	}
	if auth.tolerance < 0 {
		auth.tolerance = 0
	}
	if auth.keyfunc == nil {
		var jwks []byte
		switch {
		case len(options.JWKS) > 0:
			jwks = options.JWKS
		case options.JWKSURI != "":
			client := options.HTTPClient
			if client == nil {
				client = &http.Client{Timeout: 10 * time.Second}
			}
			response, err := client.Get(options.JWKSURI)
			if err != nil {
				return nil, WrapError(err, "Failed to fetch the JWKS document.", CodeUnavailable)
			}
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return nil, UnavailableError(fmt.Sprintf("JWKS endpoint returned HTTP %d.", response.StatusCode))
			}
			decoder := json.NewDecoder(response.Body)
			var document any
			if err := decoder.Decode(&document); err != nil {
				return nil, WrapError(err, "The JWKS document is not valid JSON.", CodeUnavailable)
			}
			raw, err := json.Marshal(document)
			if err != nil {
				return nil, WrapError(err, "The JWKS document is not JSON-serializable.", CodeUnavailable)
			}
			jwks = raw
		default:
			return nil, InvalidInput("JWTAuth requires Keyfunc, JWKS, or JWKSURI.", nil)
		}
		keyfunc, err := keyfuncFromJWKS(jwks)
		if err != nil {
			return nil, err
		}
		auth.keyfunc = keyfunc
	}
	return auth, nil
}

// Authenticate implements AuthProvider.
func (a *JWTAuth) Authenticate(request *http.Request) (*AuthResult, error) {
	if a == nil || request == nil {
		return nil, nil
	}
	token := ReadBearerToken(request)
	if token == "" || len(token) > 64*1024 {
		return nil, nil
	}
	if strings.Count(token, ".") != 2 {
		return nil, nil
	}
	claims := jwt.MapClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(a.tolerance),
	}
	if a.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(a.issuer))
	}
	if len(a.audience) > 0 {
		parserOptions = append(parserOptions, jwt.WithAudience(a.audience...))
	}
	parsed, err := jwt.ParseWithClaims(token, claims, a.keyfunc, parserOptions...)
	if err != nil || !parsed.Valid {
		return nil, nil
	}
	rawClaims := map[string]any(claims)
	principal, err := a.principalFromClaims(rawClaims)
	if err != nil || principal == nil || strings.TrimSpace(principal.ID) == "" {
		return nil, nil
	}
	exp, ok := numericClaim(rawClaims["exp"])
	if !ok {
		return nil, nil
	}
	result := &AuthResult{
		Principal: principal.Clone(),
		Token:     token,
		ExpiresAt: exp * 1000,
		Scopes:    append([]string(nil), principal.Scopes...),
	}
	if clientID := stringClaim(rawClaims["client_id"]); clientID != "" {
		result.ClientID = clientID
	} else if azp := stringClaim(rawClaims["azp"]); azp != "" {
		result.ClientID = azp
	}
	return result, nil
}

// Challenge implements AuthChallenger.
func (a *JWTAuth) Challenge() string {
	realm := "gap"
	if a != nil && a.realm != "" {
		realm = a.realm
	}
	return BearerChallenge(BearerChallengeOptions{Realm: realm})
}

func (a *JWTAuth) principalFromClaims(claims map[string]any) (*Principal, error) {
	if a.mapClaims != nil {
		principal, err := a.mapClaims(claims)
		if err != nil {
			return nil, err
		}
		return normalizePrincipal(principal), nil
	}
	sub := stringClaim(claims["sub"])
	if sub == "" {
		return nil, nil
	}
	principal := &Principal{ID: sub}
	principal.Scopes = scopesFromClaims(claims)
	if tenant := stringClaim(claims["tenant_id"]); tenant != "" {
		principal.TenantID = tenant
	} else if tenant := stringClaim(claims["tenantId"]); tenant != "" {
		principal.TenantID = tenant
	}
	principal.Email = stringClaim(claims["email"])
	principal.Name = stringClaim(claims["name"])
	if kind := stringClaim(claims["type"]); kind == "user" || kind == "service" || kind == "anonymous" {
		principal.Type = PrincipalType(kind)
	}
	return principal, nil
}

func normalizePrincipal(principal *Principal) *Principal {
	if principal == nil {
		return nil
	}
	copy := principal.Clone()
	copy.Scopes = UniqueStrings(copy.Scopes)
	switch copy.Type {
	case PrincipalUser, PrincipalService, PrincipalAnonymous:
	default:
		copy.Type = ""
	}
	return &copy
}

func scopesFromClaims(claims map[string]any) []string {
	var scopes []string
	collectScopeClaim(claims["scope"], &scopes)
	collectScopeClaim(claims["scp"], &scopes)
	return UniqueStrings(scopes)
}

func collectScopeClaim(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		for _, scope := range strings.Fields(typed) {
			*out = append(*out, scope)
		}
	case []any:
		for _, item := range typed {
			if scope, ok := item.(string); ok && scope != "" {
				*out = append(*out, scope)
			}
		}
	case []string:
		*out = append(*out, typed...)
	}
}

func numericClaim(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	case int64:
		return typed, true
	default:
		return 0, false
	}
}

func stringClaim(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

// ComposeAuth tries providers in order and returns the first successful result.
// Challenge and metadata are taken from the first provider that implements them.
func ComposeAuth(providers ...AuthProvider) AuthProvider {
	return &composedAuth{providers: append([]AuthProvider(nil), providers...)}
}

type composedAuth struct {
	providers []AuthProvider
}

func (c *composedAuth) Authenticate(request *http.Request) (*AuthResult, error) {
	var lastErr error
	for _, provider := range c.providers {
		if provider == nil {
			continue
		}
		result, err := provider.Authenticate(request)
		if err != nil {
			lastErr = err
			continue
		}
		if result != nil {
			return result, nil
		}
	}
	return nil, lastErr
}

func (c *composedAuth) Challenge() string {
	for _, provider := range c.providers {
		if challenger, ok := provider.(AuthChallenger); ok {
			if challenge := challenger.Challenge(); challenge != "" {
				return challenge
			}
		}
	}
	return BearerChallenge(BearerChallengeOptions{})
}

func (c *composedAuth) ProtectedResourceMetadata() map[string]any {
	for _, provider := range c.providers {
		if provider, ok := provider.(ProtectedResourceMetadataProvider); ok {
			return provider.ProtectedResourceMetadata()
		}
	}
	return nil
}

// ProtectedResourceMetadataOptions configures the RFC 9728 metadata document.
type ProtectedResourceMetadataOptions struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}

// ProtectedResourceMetadata builds an RFC 9728 protected resource metadata
// document. Bearer tokens are accepted in the Authorization header only.
func ProtectedResourceMetadata(options ProtectedResourceMetadataOptions) map[string]any {
	servers := options.AuthorizationServers
	if servers == nil {
		servers = []string{}
	}
	scopes := options.ScopesSupported
	if scopes == nil {
		scopes = []string{}
	}
	documentation := options.ResourceDocumentation
	if documentation == "" {
		documentation = options.Resource
	}
	return map[string]any{
		"resource":                 options.Resource,
		"authorization_servers":    servers,
		"scopes_supported":         scopes,
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   documentation,
	}
}

// BearerChallengeOptions configures a WWW-Authenticate challenge.
type BearerChallengeOptions struct {
	Realm               string
	Error               string
	ResourceMetadataURL string
}

// BearerChallenge builds a correctly quoted Bearer challenge.
func BearerChallenge(options BearerChallengeOptions) string {
	realm := options.Realm
	if realm == "" {
		realm = "gap"
	}
	parts := []string{`realm="` + QuoteHeaderValue(realm) + `"`}
	if options.Error != "" {
		parts = append(parts, `error="`+QuoteHeaderValue(options.Error)+`"`)
	}
	if options.ResourceMetadataURL != "" {
		parts = append(parts, `resource_metadata="`+QuoteHeaderValue(options.ResourceMetadataURL)+`"`)
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// ReadBearerToken extracts a bearer token case-insensitively.
func ReadBearerToken(request *http.Request) string {
	if request == nil {
		return ""
	}
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

// keyfuncFromJWKS parses an RSA/EC/Ed25519 JWKS into a jwt.Keyfunc.
func keyfuncFromJWKS(document []byte) (jwt.Keyfunc, error) {
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(document, &jwks); err != nil {
		return nil, WrapError(err, "Invalid JWKS document.", CodeInvalidInput)
	}
	if len(jwks.Keys) == 0 {
		return nil, InvalidInput("JWKS document has no keys.", nil)
	}
	keys := make(map[string]any, len(jwks.Keys))
	var defaultKey any
	for _, entry := range jwks.Keys {
		publicKey, err := publicKeyFromJWK(entry)
		if err != nil {
			return nil, err
		}
		kid, _ := entry["kid"].(string)
		if kid == "" {
			kid = fmt.Sprintf("key-%d", len(keys))
		}
		keys[kid] = publicKey
		if defaultKey == nil {
			defaultKey = publicKey
		}
	}
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != "" {
			if key, ok := keys[kid]; ok {
				return key, nil
			}
			return nil, errors.New("unknown key id")
		}
		if len(keys) == 1 {
			return defaultKey, nil
		}
		return nil, errors.New("token has no key id")
	}, nil
}

func publicKeyFromJWK(entry map[string]any) (any, error) {
	kty, _ := entry["kty"].(string)
	switch kty {
	case "RSA":
		n, ok := decodeBase64URLBigInt(entry["n"])
		if !ok {
			return nil, InvalidInput("Invalid RSA JWK modulus.", nil)
		}
		e, ok := decodeBase64URLBigInt(entry["e"])
		if !ok {
			return nil, InvalidInput("Invalid RSA JWK exponent.", nil)
		}
		exponent := int(e.Int64())
		if exponent == 0 {
			return nil, InvalidInput("Invalid RSA JWK exponent.", nil)
		}
		return &rsa.PublicKey{N: n, E: exponent}, nil
	case "EC":
		curveName, _ := entry["crv"].(string)
		var curve elliptic.Curve
		switch curveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, InvalidInput("Unsupported EC curve in JWKS.", nil)
		}
		x, okX := decodeBase64URLBigInt(entry["x"])
		y, okY := decodeBase64URLBigInt(entry["y"])
		if !okX || !okY {
			return nil, InvalidInput("Invalid EC JWK coordinates.", nil)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		curve, _ := entry["crv"].(string)
		if curve != "Ed25519" {
			return nil, InvalidInput("Unsupported OKP curve in JWKS.", nil)
		}
		raw, ok := entry["x"].(string)
		if !ok {
			return nil, InvalidInput("Invalid Ed25519 JWK.", nil)
		}
		bytes, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(bytes) != ed25519.PublicKeySize {
			return nil, InvalidInput("Invalid Ed25519 JWK.", nil)
		}
		return ed25519.PublicKey(bytes), nil
	default:
		return nil, InvalidInput("Unsupported JWKS key type.", nil)
	}
}

func decodeBase64URLBigInt(value any) (*big.Int, bool) {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil, false
	}
	bytes, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, false
	}
	return new(big.Int).SetBytes(bytes), true
}
