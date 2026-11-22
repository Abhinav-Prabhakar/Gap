package gap

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// HandoffState is the signed payload carried in a `gap_state` query parameter.
// It binds a UI handoff to one action, its exact arguments and the principal
// that requested it.
type HandoffState struct {
	Version     int    `json:"v"`
	Action      string `json:"action"`
	Args        any    `json:"args"`
	ArgsHash    string `json:"argsHash"`
	PrincipalID string `json:"principalId"`
	TenantID    string `json:"tenantId,omitempty"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Nonce       string `json:"nonce"`
}

// HandoffLink is a signed deep link and its decoded metadata.
type HandoffLink struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// HandoffLinkOptions configures CreateHandoffLink.
type HandoffLinkOptions struct {
	Secret      string
	Action      string
	Args        any
	PrincipalID string
	TenantID    string
	// BaseURL is an absolute application origin such as
	// "https://app.example.com". It may be empty for a relative link.
	BaseURL string
	// Route is the UI route. Empty means "/".
	Route string
	// TTL is the token lifetime. Zero uses ten minutes.
	TTL time.Duration
	// Now is an injectable clock.
	Now func() time.Time
}

// CreateHandoffLink creates a v1.<payload>.<hmac> handoff token and URL. The
// signature covers the exact action, arguments and principal, so none of them
// can be changed without invalidating the link.
func CreateHandoffLink(options HandoffLinkOptions) (HandoffLink, error) {
	if strings.TrimSpace(options.Secret) == "" {
		return HandoffLink{}, InvalidInput("A handoff secret is required.", nil)
	}
	if strings.TrimSpace(options.Action) == "" {
		return HandoffLink{}, InvalidInput("A handoff action is required.", nil)
	}
	if strings.TrimSpace(options.PrincipalID) == "" {
		return HandoffLink{}, InvalidInput("A handoff principal is required.", nil)
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	args := options.Args
	if args == nil {
		args = map[string]any{}
	}
	argsHash, err := Hash(args)
	if err != nil {
		return HandoffLink{}, WrapError(err, "Handoff arguments must be JSON-serializable.", CodeInvalidInput)
	}
	issuedAt := now()
	state := HandoffState{
		Version:     1,
		Action:      options.Action,
		Args:        args,
		ArgsHash:    argsHash,
		PrincipalID: options.PrincipalID,
		TenantID:    options.TenantID,
		IssuedAt:    issuedAt.UnixMilli(),
		ExpiresAt:   issuedAt.Add(ttl).UnixMilli(),
		Nonce:       CreateID("hs"),
	}
	canonical, err := CanonicalJSON(state)
	if err != nil {
		return HandoffLink{}, WrapError(err, "Failed to encode the handoff state.", CodeInternal)
	}
	payload := base64.RawURLEncoding.EncodeToString(canonical)
	signingInput := "v1." + payload
	mac := hmac.New(sha256.New, []byte(options.Secret))
	mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	route := strings.TrimSpace(options.Route)
	if route == "" {
		route = "/"
	}
	resolved := resolveHandoffURL(options.BaseURL, route)
	return HandoffLink{
		URL:       appendHandoffState(resolved, token),
		Token:     token,
		ExpiresAt: state.ExpiresAt,
	}, nil
}

// HandoffVerifyOptions narrows a handoff token check.
type HandoffVerifyOptions struct {
	// Action requires the token to name this action.
	Action string
	// Args requires the token to bind these exact arguments.
	Args any
	// Now is an injectable clock.
	Now func() time.Time
}

// VerifyHandoffToken verifies a handoff token. It returns (nil, nil) for any
// malformed, tampered, expired or mismatched token; attacker-controlled input
// never causes a panic.
func VerifyHandoffToken(token, secret string, options HandoffVerifyOptions) (*HandoffState, error) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(secret) == "" {
		return nil, nil
	}
	if len(token) > 16*1024 {
		return nil, nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return nil, nil
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(provided) != sha256.Size {
		return nil, nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v1." + parts[1]))
	if subtle.ConstantTimeCompare(provided, mac.Sum(nil)) != 1 {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil
	}
	var state HandoffState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, nil
	}
	if state.Version != 1 || state.Action == "" || state.PrincipalID == "" || state.Nonce == "" || state.ArgsHash == "" {
		return nil, nil
	}
	if state.ExpiresAt <= state.IssuedAt {
		return nil, nil
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	if state.ExpiresAt <= now().UnixMilli() {
		return nil, nil
	}
	if options.Action != "" && state.Action != options.Action {
		return nil, nil
	}
	if options.Args != nil {
		expected, err := Hash(options.Args)
		if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(state.ArgsHash)) != 1 {
			return nil, nil
		}
	}
	return &state, nil
}

// HandoffStateFromURL extracts and verifies a gap_state parameter from a URL.
func HandoffStateFromURL(rawURL, secret string, options HandoffVerifyOptions) (*HandoffState, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}
	token := parsed.Query().Get("gap_state")
	if token == "" {
		return nil, nil
	}
	return VerifyHandoffToken(token, secret, options)
}

func resolveHandoffURL(baseURL, route string) string {
	if isAbsoluteURL(route) {
		return route
	}
	if strings.TrimSpace(baseURL) == "" {
		if strings.HasPrefix(route, "/") {
			return route
		}
		return "/" + route
	}
	base := strings.TrimRight(baseURL, "/")
	if strings.HasPrefix(route, "/") {
		return base + route
	}
	return base + "/" + route
}

func isAbsoluteURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func appendHandoffState(route, token string) string {
	hash := ""
	beforeHash := route
	if index := strings.IndexByte(route, '#'); index >= 0 {
		beforeHash = route[:index]
		hash = route[index:]
	}
	separator := "?"
	if strings.Contains(beforeHash, "?") {
		separator = "&"
	}
	return beforeHash + separator + "gap_state=" + url.QueryEscape(token) + hash
}
