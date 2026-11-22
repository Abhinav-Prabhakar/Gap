package gap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultSearchThreshold is the number of visible actions above which the
// server advertises gap.search so a large catalog does not flood the model's
// context with every tool definition.
const DefaultSearchThreshold = 12

// Reserved tool names owned by the server. Actions may not use them.
var ReservedNames = []string{
	"gap.tasks.get",
	"gap.tasks.cancel",
	"gap.receipts.get",
	"gap.undo",
	"gap.handoff",
	"gap.search",
}

// ServerOptions configures a Gap MCP server.
type ServerOptions struct {
	// Registry is required and becomes the server's action catalog.
	Registry *Registry
	// Name and Version identify the MCP implementation.
	Name    string
	Version string
	// Instructions are sent to the client during initialization.
	Instructions string
	// Auth authenticates HTTP requests. When nil, requests run as the
	// anonymous principal if AllowAnonymous is true (the default).
	Auth AuthProvider
	// Policy is evaluated before validation and execution. Nil allows all.
	Policy PolicyEngine
	// Audit is the primary audit sink. AuditSinks adds more sinks.
	Audit      AuditSink
	AuditSinks []AuditSink
	// Logger receives server warnings. Defaults to NopLogger.
	Logger Logger
	// Approvals is the optional signed-token approval gate. When set, a call
	// may pass `_meta["gap/approval"]` with a valid token.
	Approvals ApprovalGate
	// ApprovalStore stores pending approvals. Defaults to an in-memory store.
	ApprovalStore ApprovalStore
	// RateLimiter overrides the built-in limiter. When nil and
	// RateLimit.Limit > 0, a token bucket is built. Otherwise calls are
	// unlimited.
	RateLimiter RateLimiter
	// RateLimit configures the built-in token bucket.
	RateLimit RateLimitOptions
	// Idempotency caches results for idempotent actions and explicit keys.
	// Defaults to an in-memory store.
	Idempotency IdempotencyStore
	// BaseURL is the absolute public origin used for handoff and approval
	// links. When empty, links are derived from the request.
	BaseURL string
	// HandoffSecret enables gap.handoff and signs UI links.
	HandoffSecret string
	// EnableTasks controls background task actions. Nil means enabled.
	EnableTasks *bool
	// CallStoreLimit bounds retained receipts (default 500).
	CallStoreLimit int
	// Timeout is the default per-action execution budget (default 30s).
	Timeout time.Duration
	// ApprovalTTL is the lifetime of pending approvals (default 5m).
	ApprovalTTL time.Duration
	// HandoffTTL is the lifetime of handoff links (default 10m).
	HandoffTTL time.Duration
	// Redact lists extra dot/bracket paths removed from results.
	Redact []string
	// AllowAnonymous permits unauthenticated requests when the provider
	// returns no credentials. Nil means "allowed only when Auth is nil".
	AllowAnonymous *bool
	// SearchThreshold enables gap.search when a principal can see more than
	// this many actions. Zero uses DefaultSearchThreshold; negative disables.
	SearchThreshold int
	// OnCall observes every stored call after redaction. It must not panic or
	// block; failures are logged and ignored.
	OnCall func(CallRecord)
}

type resolvedOptions struct {
	name            string
	version         string
	instructions    string
	auth            AuthProvider
	policy          PolicyEngine
	logger          Logger
	approvals       ApprovalGate
	baseURL         string
	handoffSecret   string
	enableTasks     bool
	timeout         time.Duration
	approvalTTL     time.Duration
	handoffTTL      time.Duration
	redact          []string
	allowAnonymous  bool
	searchThreshold int
	onCall          func(CallRecord)
}

// Server is a production MCP server for a Gap action registry. It exposes a
// stateless Streamable HTTP handler, per-request scope filtering, the full
// authentication/policy/approval/execution pipeline, receipts, undo, tasks and
// audit.
type Server struct {
	registry      *Registry
	opts          resolvedOptions
	calls         *CallStore
	approvalStore ApprovalStore
	tasks         *TaskManager
	rateLimiter   RateLimiter
	idempotency   IdempotencyStore
	auditSinks    []AuditSink
	httpHandler   http.Handler
	startedAt     time.Time

	mu       sync.Mutex
	inFlight map[string]*inFlightCall
	closed   bool
}

type inFlightCall struct {
	done chan struct{}
}

type authContextKey struct{}

// NewServer validates options and builds a server. Configuration mistakes are
// returned as errors rather than deferred to the first request.
func NewServer(options ServerOptions) (*Server, error) {
	if options.Registry == nil {
		return nil, Internal("GapServer requires a registry.", nil)
	}
	name := strings.TrimSpace(options.Name)
	if name == "" {
		name = "gap"
	}
	version := strings.TrimSpace(options.Version)
	if version == "" {
		version = Version
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	approvalTTL := options.ApprovalTTL
	if approvalTTL <= 0 {
		approvalTTL = 5 * time.Minute
	}
	handoffTTL := options.HandoffTTL
	if handoffTTL <= 0 {
		handoffTTL = 10 * time.Minute
	}
	callLimit := options.CallStoreLimit
	if callLimit <= 0 {
		callLimit = 500
	}
	searchThreshold := options.SearchThreshold
	if searchThreshold == 0 {
		searchThreshold = DefaultSearchThreshold
	}
	enableTasks := true
	if options.EnableTasks != nil {
		enableTasks = *options.EnableTasks
	}
	allowAnonymous := options.Auth == nil
	if options.AllowAnonymous != nil {
		allowAnonymous = *options.AllowAnonymous
	}

	baseURL := strings.TrimRight(strings.TrimSpace(options.BaseURL), "/")
	if baseURL != "" {
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, Internal("BaseURL must be an absolute URL.", nil)
		}
	}

	for _, reserved := range ReservedNames {
		if options.Registry.Has(reserved) {
			return nil, Internal(fmt.Sprintf("Tool name %q is reserved by GapServer.", reserved), nil)
		}
	}

	policy := options.Policy
	if policy == nil {
		policy = allowAllPolicy{}
	}
	logger := options.Logger
	if logger == nil {
		logger = NopLogger
	}
	approvalStore := options.ApprovalStore
	if approvalStore == nil {
		approvalStore = NewMemoryApprovalStore(MemoryApprovalStoreOptions{TTL: approvalTTL})
	}
	idempotency := options.Idempotency
	if idempotency == nil {
		idempotency = NewMemoryIdempotencyStore()
	}
	rateLimiter := options.RateLimiter
	if rateLimiter == nil {
		if options.RateLimit.Limit > 0 {
			built, err := NewTokenBucketRateLimiter(options.RateLimit)
			if err != nil {
				return nil, err
			}
			rateLimiter = built
		} else {
			rateLimiter = UnlimitedRateLimiter{}
		}
	}

	sinks := make([]AuditSink, 0, len(options.AuditSinks)+1)
	if options.Audit != nil {
		sinks = append(sinks, options.Audit)
	}
	for _, sink := range options.AuditSinks {
		if sink != nil {
			sinks = append(sinks, sink)
		}
	}

	server := &Server{
		registry: options.Registry,
		opts: resolvedOptions{
			name:            name,
			version:         version,
			instructions:    options.Instructions,
			auth:            options.Auth,
			policy:          policy,
			logger:          logger,
			approvals:       options.Approvals,
			baseURL:         baseURL,
			handoffSecret:   options.HandoffSecret,
			enableTasks:     enableTasks,
			timeout:         timeout,
			approvalTTL:     approvalTTL,
			handoffTTL:      handoffTTL,
			redact:          append([]string(nil), options.Redact...),
			allowAnonymous:  allowAnonymous,
			searchThreshold: searchThreshold,
			onCall:          options.OnCall,
		},
		calls:         NewCallStore(callLimit),
		approvalStore: approvalStore,
		tasks:         NewTaskManager(1000),
		rateLimiter:   rateLimiter,
		idempotency:   idempotency,
		auditSinks:    sinks,
		startedAt:     time.Now(),
		inFlight:      make(map[string]*inFlightCall),
	}

	server.httpHandler = mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			auth := authFromRequest(request)
			if auth == nil {
				return nil
			}
			return server.newMCPServer(auth, request)
		},
		&mcp.StreamableHTTPOptions{
			Stateless:           true,
			JSONResponse:        true,
			MaxRequestBodyBytes: 4 << 20,
		},
	)
	return server, nil
}

// Registry returns the server's action catalog.
func (s *Server) Registry() *Registry {
	if s == nil {
		return nil
	}
	return s.registry
}

// Calls returns the receipt/call store.
func (s *Server) Calls() *CallStore {
	if s == nil {
		return nil
	}
	return s.calls
}

// ApprovalStore returns the approval store.
func (s *Server) ApprovalStore() ApprovalStore {
	if s == nil {
		return nil
	}
	return s.approvalStore
}

// Tasks returns the background task manager.
func (s *Server) Tasks() *TaskManager {
	if s == nil {
		return nil
	}
	return s.tasks
}

// RateLimiter returns the configured limiter.
func (s *Server) RateLimiter() RateLimiter {
	if s == nil {
		return nil
	}
	return s.rateLimiter
}

// Idempotency returns the idempotency store.
func (s *Server) Idempotency() IdempotencyStore {
	if s == nil {
		return nil
	}
	return s.idempotency
}

// Handler returns the server as a net/http handler.
func (s *Server) Handler() http.Handler { return s }

// ServeHTTP routes /mcp, /health and the protected-resource metadata document.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if s == nil {
		http.Error(w, "gap: nil server", http.StatusInternalServerError)
		return
	}
	if request == nil {
		http.Error(w, "gap: nil request", http.StatusBadRequest)
		return
	}
	path := normalizeHTTPPath(request.URL.Path)

	switch {
	case path == "/health":
		s.handleHealth(w, request)
		return
	case path == "/.well-known/oauth-protected-resource" || strings.HasPrefix(path, "/.well-known/oauth-protected-resource/"):
		s.handleMetadata(w, request)
		return
	case path == "/mcp":
		s.handleMCP(w, request)
		return
	default:
		writeJSON(w, request, http.StatusNotFound, map[string]any{
			"error":             "not_found",
			"error_description": "Route not found.",
		})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(w, request, "GET, HEAD")
		return
	}
	writeJSON(w, request, http.StatusOK, map[string]any{
		"status":   "ok",
		"name":     s.opts.name,
		"version":  s.opts.version,
		"uptimeMs": time.Since(s.startedAt).Milliseconds(),
		"sessions": 0,
		"actions":  s.registry.Size(),
	})
}

func (s *Server) handleMetadata(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(w, request, "GET, HEAD")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, request, http.StatusOK, s.metadataDocument(request))
}

func (s *Server) handleMCP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, request, http.StatusMethodNotAllowed, map[string]any{
			"error":             "method_not_allowed",
			"error_description": "The stateless MCP endpoint accepts POST only.",
		})
		return
	}
	auth, err := s.authenticate(request)
	if err != nil {
		s.opts.logger.Warn("Authentication provider failed; rejecting the request.", err.Error())
		s.writeUnauthorized(w, request)
		return
	}
	if auth == nil {
		s.writeUnauthorized(w, request)
		return
	}
	ctx := context.WithValue(request.Context(), authContextKey{}, auth)
	s.httpHandler.ServeHTTP(w, request.WithContext(ctx))
}

func (s *Server) authenticate(request *http.Request) (*AuthResult, error) {
	if s.opts.auth == nil {
		if !s.opts.allowAnonymous {
			return nil, nil
		}
		return anonymousAuthResult(), nil
	}
	result, err := s.opts.auth.Authenticate(request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		if !s.opts.allowAnonymous {
			return nil, nil
		}
		return anonymousAuthResult(), nil
	}
	return normalizeAuthResult(result)
}

func anonymousAuthResult() *AuthResult {
	principal := Principal{
		ID:     "anonymous",
		Type:   PrincipalAnonymous,
		Name:   "Anonymous",
		Scopes: []string{"*"},
	}
	return &AuthResult{Principal: principal, Scopes: []string{"*"}}
}

func normalizeAuthResult(result *AuthResult) (*AuthResult, error) {
	if result == nil {
		return nil, Unauthorized("")
	}
	principal := result.Principal.Clone()
	principal.ID = strings.TrimSpace(principal.ID)
	if principal.ID == "" {
		return nil, Unauthorized("")
	}
	scopes := MergeScopes(principal.Scopes, result.Scopes)
	principal.Scopes = scopes
	out := *result
	out.Principal = principal
	out.Scopes = scopes
	return &out, nil
}

func authFromRequest(request *http.Request) *AuthResult {
	if request == nil {
		return nil
	}
	auth, _ := request.Context().Value(authContextKey{}).(*AuthResult)
	return auth
}

func (s *Server) writeUnauthorized(w http.ResponseWriter, request *http.Request) {
	metadataURL := s.metadataURL(request)
	challenge := ""
	if challenger, ok := s.opts.auth.(AuthChallenger); ok && challenger != nil {
		challenge = challenger.Challenge()
	}
	if strings.TrimSpace(challenge) == "" {
		challenge = BearerChallenge(BearerChallengeOptions{Realm: "gap", ResourceMetadataURL: metadataURL})
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Link", "<"+metadataURL+`>; rel="http://www.rfc-editor.org/rfc/rfc9728#metadata"`)
	writeJSON(w, request, http.StatusUnauthorized, map[string]any{
		"error":                       "unauthorized",
		"error_description":           "Authentication required.",
		"resource_metadata":           metadataURL,
		"protected_resource_metadata": s.metadataDocument(request),
	})
}

func (s *Server) metadataDocument(request *http.Request) map[string]any {
	if provider, ok := s.opts.auth.(ProtectedResourceMetadataProvider); ok && provider != nil {
		if document := provider.ProtectedResourceMetadata(); document != nil {
			return document
		}
	}
	scopes := make(map[string]struct{})
	for _, action := range s.registry.List(nil) {
		for _, scope := range action.Scopes {
			if scope != "" && scope != "*" {
				scopes[scope] = struct{}{}
			}
		}
	}
	supported := make([]string, 0, len(scopes))
	for scope := range scopes {
		supported = append(supported, scope)
	}
	sort.Strings(supported)
	return ProtectedResourceMetadata(ProtectedResourceMetadataOptions{
		Resource:              s.baseURLFor(request),
		ScopesSupported:       supported,
		ResourceDocumentation: s.baseURLFor(request),
	})
}

func (s *Server) metadataURL(request *http.Request) string {
	return s.baseURLFor(request) + "/.well-known/oauth-protected-resource"
}

func (s *Server) baseURLFor(request *http.Request) string {
	if s.opts.baseURL != "" {
		return s.opts.baseURL
	}
	if request == nil {
		return ""
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	if request.Host == "" {
		return ""
	}
	return scheme + "://" + request.Host
}

// ListTools returns the descriptors visible to the supplied scopes, including
// the server-provided tools that are available. It is intended for inspectors
// and tests; MCP clients receive the same set through tools/list.
func (s *Server) ListTools(scopes []string) []ToolDescriptor {
	if s == nil {
		return nil
	}
	visible := s.registry.VisibleTo(scopes)
	out := make([]ToolDescriptor, 0, len(visible)+5)
	for _, action := range visible {
		out = append(out, ToToolDescriptor(action))
	}
	out = append(out, s.builtinDescriptors(scopes)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) builtinDescriptors(scopes []string) []ToolDescriptor {
	visible := s.registry.VisibleTo(scopes)
	available := make(map[string]bool)
	if s.opts.enableTasks {
		available["gap.tasks.get"] = true
		available["gap.tasks.cancel"] = true
	}
	available["gap.receipts.get"] = true
	hasUndo := false
	hasUI := false
	for _, action := range visible {
		if action.Undo != nil {
			hasUndo = true
		}
		if action.UI != nil {
			hasUI = true
		}
	}
	if hasUndo {
		available["gap.undo"] = true
	}
	if s.opts.handoffSecret != "" && hasUI {
		available["gap.handoff"] = true
	}
	if s.opts.searchThreshold >= 0 && len(visible) > s.opts.searchThreshold {
		available["gap.search"] = true
	}
	out := make([]ToolDescriptor, 0, len(available))
	for name := range available {
		out = append(out, builtinDescriptor(name))
	}
	return out
}

func builtinDescriptor(name string) ToolDescriptor {
	switch name {
	case "gap.tasks.get":
		return ToolDescriptor{
			Name:        "gap.tasks.get",
			Title:       "Get task",
			Description: "Read the status, result and receipt of a background task started by a task-backed action.",
			InputSchema: objectSchema(map[string]any{
				"taskId": property("string", "Task id returned when the action was accepted."),
			}, []string{"taskId"}),
			Annotations: readOnlyAnnotations("Get task"),
			Meta:        map[string]any{"gap/builtin": true},
		}
	case "gap.tasks.cancel":
		return ToolDescriptor{
			Name:        "gap.tasks.cancel",
			Title:       "Cancel task",
			Description: "Cancel a running background task. The task's abort signal is triggered immediately.",
			InputSchema: objectSchema(map[string]any{
				"taskId": property("string", "Task id to cancel."),
			}, []string{"taskId"}),
			Annotations: &ActionAnnotations{
				Title:           "Cancel task",
				ReadOnlyHint:    Ptr(false),
				DestructiveHint: Ptr(true),
				IdempotentHint:  Ptr(true),
				OpenWorldHint:   Ptr(false),
			},
			Meta: map[string]any{"gap/builtin": true},
		}
	case "gap.receipts.get":
		return ToolDescriptor{
			Name:        "gap.receipts.get",
			Title:       "Get receipt",
			Description: "Read the receipt, arguments and redacted result of an earlier successful action call.",
			InputSchema: objectSchema(map[string]any{
				"receiptId": property("string", "Receipt id from _meta[\"gap/receipt\"].id."),
			}, []string{"receiptId"}),
			Annotations: readOnlyAnnotations("Get receipt"),
			Meta:        map[string]any{"gap/builtin": true},
		}
	case "gap.undo":
		return ToolDescriptor{
			Name:        "gap.undo",
			Title:       "Undo action",
			Description: "Run the best-effort inverse of an action using a stored receipt. Returns a new receipt.",
			InputSchema: objectSchema(map[string]any{
				"receiptId": property("string", "Receipt id of the call to undo."),
			}, []string{"receiptId"}),
			Annotations: &ActionAnnotations{
				Title:           "Undo action",
				ReadOnlyHint:    Ptr(false),
				DestructiveHint: Ptr(true),
				IdempotentHint:  Ptr(false),
				OpenWorldHint:   Ptr(false),
			},
			Meta: map[string]any{"gap/builtin": true},
		}
	case "gap.handoff":
		return ToolDescriptor{
			Name:        "gap.handoff",
			Title:       "Hand off to UI",
			Description: "Create a signed deep link that opens an action in the application's UI with the given arguments.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": property("string", "Action name with a UI binding."),
					"args": map[string]any{
						"type":                 "object",
						"description":          "Arguments for the action; must satisfy the action's input schema.",
						"additionalProperties": true,
					},
				},
				"required":             []string{"action"},
				"additionalProperties": false,
			},
			Annotations: readOnlyAnnotations("Hand off to UI"),
			Meta:        map[string]any{"gap/builtin": true},
		}
	case "gap.search":
		return ToolDescriptor{
			Name:        "gap.search",
			Title:       "Search actions",
			Description: "Search the available actions by name, description, namespace or tag. Returns matching tool definitions with input schemas.",
			InputSchema: objectSchema(map[string]any{
				"query":     property("string", "Case-insensitive words matched against tool names and descriptions."),
				"namespace": property("string", "Only return actions whose name starts with this namespace."),
				"tags": map[string]any{
					"type":        "array",
					"description": "Only return actions carrying every one of these tags.",
					"items":       map[string]any{"type": "string"},
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": "Maximum results, from 1 to 50. Defaults to 10.",
					"minimum":     1,
					"maximum":     50,
				},
			}, nil),
			Annotations: readOnlyAnnotations("Search actions"),
			Meta:        map[string]any{"gap/builtin": true},
		}
	default:
		return ToolDescriptor{}
	}
}

func objectSchema(properties map[string]any, required []string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func property(kind, description string) map[string]any {
	return map[string]any{"type": kind, "description": description}
}

func readOnlyAnnotations(title string) *ActionAnnotations {
	return &ActionAnnotations{
		Title:           title,
		ReadOnlyHint:    Ptr(true),
		DestructiveHint: Ptr(false),
		IdempotentHint:  Ptr(true),
		OpenWorldHint:   Ptr(false),
	}
}

func (s *Server) newMCPServer(auth *AuthResult, request *http.Request) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: s.opts.name, Version: s.opts.version},
		&mcp.ServerOptions{Instructions: s.opts.instructions},
	)
	registered := make(map[string]bool)
	for _, descriptor := range s.ListTools(auth.Scopes) {
		tool := descriptorToMCP(descriptor)
		name := descriptor.Name
		registered[name] = true
		server.AddTool(tool, func(ctx context.Context, call *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, meta, err := decodeToolCall(call)
			if err != nil {
				return s.errorResult(Normalize(err), CreateID("trace")), nil
			}
			if isBuiltinName(name) {
				return s.handleBuiltin(ctx, auth, request, name, args, meta), nil
			}
			return s.handleActionCall(ctx, auth, request, name, args, meta), nil
		})
	}
	// Tools that are hidden from this principal (or unknown entirely) are not
	// registered with the SDK, which would otherwise answer with a JSON-RPC
	// error. Route those calls through Gap's pipeline so every failure is a
	// tool result with a gapError payload, mirroring the TypeScript server.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			call, ok := req.(*mcp.CallToolRequest)
			if !ok || call.Params == nil || registered[call.Params.Name] {
				return next(ctx, method, req)
			}
			args, meta, err := decodeToolCall(call)
			if err != nil {
				return s.errorResult(Normalize(err), CreateID("trace")), nil
			}
			if isBuiltinName(call.Params.Name) {
				return s.handleBuiltin(ctx, auth, request, call.Params.Name, args, meta), nil
			}
			return s.handleActionCall(ctx, auth, request, call.Params.Name, args, meta), nil
		}
	})
	return server
}

func descriptorToMCP(descriptor ToolDescriptor) *mcp.Tool {
	input := descriptor.InputSchema
	if input == nil || !IsObjectSchema(input) {
		if input == nil {
			input = emptyObjectSchema()
		} else {
			copy := make(map[string]any, len(input)+1)
			for key, value := range input {
				copy[key] = value
			}
			copy["type"] = "object"
			input = copy
		}
	}
	meta := make(map[string]any, len(descriptor.Meta)+1)
	for key, value := range descriptor.Meta {
		meta[key] = value
	}
	var output any
	if descriptor.OutputSchema != nil && IsObjectSchema(descriptor.OutputSchema) {
		output = descriptor.OutputSchema
	} else if descriptor.OutputSchema != nil {
		meta["gap/outputSchema"] = descriptor.OutputSchema
	}
	tool := &mcp.Tool{
		Name:        descriptor.Name,
		Title:       descriptor.Title,
		Description: descriptor.Description,
		InputSchema: input,
		Meta:        mcp.Meta(meta),
	}
	if output != nil {
		tool.OutputSchema = output
	}
	if descriptor.Annotations != nil {
		tool.Annotations = &mcp.ToolAnnotations{Title: descriptor.Annotations.Title}
		if descriptor.Annotations.ReadOnlyHint != nil {
			tool.Annotations.ReadOnlyHint = *descriptor.Annotations.ReadOnlyHint
		}
		if descriptor.Annotations.DestructiveHint != nil {
			tool.Annotations.DestructiveHint = descriptor.Annotations.DestructiveHint
		}
		if descriptor.Annotations.IdempotentHint != nil {
			tool.Annotations.IdempotentHint = *descriptor.Annotations.IdempotentHint
		}
		if descriptor.Annotations.OpenWorldHint != nil {
			tool.Annotations.OpenWorldHint = descriptor.Annotations.OpenWorldHint
		}
	}
	return tool
}

func decodeToolCall(call *mcp.CallToolRequest) (map[string]any, map[string]any, error) {
	if call == nil || call.Params == nil {
		return map[string]any{}, map[string]any{}, nil
	}
	meta := make(map[string]any, len(call.Params.Meta))
	for key, value := range call.Params.Meta {
		meta[key] = value
	}
	raw := call.Params.Arguments
	if len(raw) == 0 {
		return map[string]any{}, meta, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, meta, InvalidInput("Tool arguments must be valid JSON.", map[string]any{"error": err.Error()})
	}
	if value == nil {
		return map[string]any{}, meta, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, meta, InvalidInput("Tool arguments must be a JSON object.", nil)
	}
	return object, meta, nil
}

func isBuiltinName(name string) bool {
	switch name {
	case "gap.tasks.get", "gap.tasks.cancel", "gap.receipts.get", "gap.undo", "gap.handoff", "gap.search":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Action pipeline
// ---------------------------------------------------------------------------

type actionOutcome struct {
	response       *mcp.CallToolResult
	decision       AuditDecision
	status         CallStatus
	argsHash       string
	resultHash     string
	callArgs       any
	result         any
	redactedResult any
	receipt        *CallReceipt
	approvalID     string
	taskID         string
	metadata       map[string]any
	cacheable      bool
}

func (s *Server) handleActionCall(ctx context.Context, auth *AuthResult, request *http.Request, name string, args map[string]any, meta map[string]any) *mcp.CallToolResult {
	started := time.Now()
	traceID := CreateID("trace")
	callID := CreateID("rcpt")
	outcome, err := s.runActionPipeline(ctx, auth, request, name, args, meta, started, traceID, callID)
	if err != nil {
		failure := Normalize(err)
		decision := auditDecisionForError(failure.Code)
		argsHash, _ := Hash(args)
		s.recordCall(CallRecord{
			ID:          callID,
			Timestamp:   time.Now().UTC(),
			Action:      name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Status:      CallStatusError,
			Args:        args,
			Error: &CallError{
				Code:    failure.Code,
				Message: failure.PublicMessage(),
				Details: failure.PublicDetails(),
			},
			DurationMS: time.Since(started).Milliseconds(),
			TraceID:    traceID,
		})
		s.emitAudit(ctx, AuditEvent{
			Action:      name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Decision:    decision,
			ArgsHash:    argsHash,
			DurationMS:  time.Since(started).Milliseconds(),
			Scopes:      auth.Scopes,
			TraceID:     traceID,
			Error:       &AuditError{Code: failure.Code, Message: failure.PublicMessage()},
		})
		return s.errorResult(failure, traceID)
	}

	s.recordCall(CallRecord{
		ID:             callID,
		Timestamp:      time.Now().UTC(),
		Action:         name,
		PrincipalID:    auth.Principal.ID,
		TenantID:       auth.Principal.TenantID,
		Status:         outcome.status,
		Args:           outcome.callArgs,
		Result:         outcome.result,
		RedactedResult: outcome.redactedResult,
		DurationMS:     time.Since(started).Milliseconds(),
		Receipt:        outcome.receipt,
		ApprovalID:     outcome.approvalID,
		TraceID:        traceID,
		TaskID:         outcome.taskID,
		Metadata:       outcome.metadata,
	})
	s.emitAudit(ctx, AuditEvent{
		Action:      name,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		Decision:    outcome.decision,
		ArgsHash:    outcome.argsHash,
		ResultHash:  outcome.resultHash,
		DurationMS:  time.Since(started).Milliseconds(),
		Scopes:      auth.Scopes,
		ApprovalID:  outcome.approvalID,
		TraceID:     traceID,
		Metadata:    outcome.metadata,
	})
	return outcome.response
}

func (s *Server) runActionPipeline(ctx context.Context, auth *AuthResult, request *http.Request, name string, args map[string]any, meta map[string]any, started time.Time, traceID, callID string) (*actionOutcome, error) {
	action := s.registry.Get(name)
	if action == nil {
		return nil, NotFound(fmt.Sprintf("Unknown tool %q.", name))
	}
	argsHash, err := Hash(args)
	if err != nil {
		return nil, InvalidInput("Tool arguments must be JSON-serializable.", nil)
	}
	if missing := MissingScopes(auth.Scopes, action.Scopes); len(missing) > 0 {
		return nil, Forbidden(fmt.Sprintf("Missing required scope(s): %s.", strings.Join(missing, ", "))).
			WithDetails(map[string]any{"missingScopes": missing})
	}

	actx := &Context{
		Principal: auth.Principal.Clone(),
		Scopes:    append([]string(nil), auth.Scopes...),
		TenantID:  auth.Principal.TenantID,
		TraceID:   traceID,
		Logger:    s.opts.logger,
		ToolName:  name,
		Request:   request,
	}
	decision := s.evaluatePolicy(action, args, actx)
	if decision.Decision == "deny" {
		details := map[string]any{}
		if decision.Code != "" {
			details["policyCode"] = decision.Code
		}
		if decision.Limits != nil {
			details["limits"] = decision.Limits
		}
		reason := decision.Reason
		if reason == "" {
			reason = "Blocked by policy."
		}
		return nil, PolicyDenied(reason, details)
	}
	if decision.Metadata != nil {
		if dry, ok := decision.Metadata["dryRun"].(bool); ok && dry {
			actx.DryRun = true
		}
	}
	redactPaths := mergePathLists(decision.RedactPaths, s.opts.redact)

	limit := s.rateLimiter.Consume(auth.Principal.ID+":"+name, 1)
	if !limit.Allowed {
		err := RateLimited(fmt.Sprintf("Rate limit exceeded. Retry in %dms.", limit.RetryAfter.Milliseconds()), limit.RetryAfter.Milliseconds())
		return nil, err.WithDetails(map[string]any{
			"retryAfterMs": limit.RetryAfter.Milliseconds(),
			"limit":        limit.Limit,
			"remaining":    limit.Remaining,
			"resetAt":      limit.ResetAt.UTC().Format(time.RFC3339Nano),
		})
	}

	validated, issues := ValidateValue(action.InputSchema, args)
	if len(issues) > 0 {
		return nil, InvalidInput(fmt.Sprintf("Invalid input for %q.", name), map[string]any{"issues": issues})
	}
	input := validated
	actx.IdempotencyKey = ""

	explicitKey := readMetaString(meta, "idempotencyKey", "gap/idempotencyKey")
	idempotencyKey := ""
	if explicitKey != "" {
		idempotencyKey = auth.Principal.ID + ":" + explicitKey
		actx.IdempotencyKey = explicitKey
	} else if action.Idempotent {
		autoKey, err := Hash(map[string]any{"principalId": auth.Principal.ID, "action": name, "args": args})
		if err == nil {
			idempotencyKey = "auto:" + autoKey
			actx.IdempotencyKey = idempotencyKey
		}
	}

	if idempotencyKey != "" {
		if cached, ok := s.idempotency.Get(idempotencyKey); ok {
			if response, ok := cached.Value.(*mcp.CallToolResult); ok {
				return replayOutcome(response, argsHash, traceID), nil
			}
		}
		if wait := s.waitForInFlight(ctx, idempotencyKey); wait != nil {
			select {
			case <-wait.done:
				if cached, ok := s.idempotency.Get(idempotencyKey); ok {
					if response, ok := cached.Value.(*mcp.CallToolResult); ok {
						return replayOutcome(response, argsHash, traceID), nil
					}
				}
			case <-ctx.Done():
				return nil, timeoutFailure("The action was cancelled.")
			}
		}
		flight, owner := s.beginInFlight(idempotencyKey)
		if owner {
			defer s.endInFlight(idempotencyKey, flight)
		}
	}

	outcome, err := s.runResolvedAction(ctx, action, auth, request, name, args, input, argsHash, actx, meta, redactPaths, decision.Decision == "confirm", started, traceID, callID)
	if err != nil {
		return nil, err
	}
	if idempotencyKey != "" && outcome.cacheable && outcome.response != nil && !outcome.response.IsError {
		s.idempotency.Set(IdempotencyRecord{
			Key:   idempotencyKey,
			Value: outcome.response,
		})
	}
	return outcome, nil
}

func replayOutcome(response *mcp.CallToolResult, argsHash, traceID string) *actionOutcome {
	status := CallStatusSuccess
	decision := AuditAllowed
	if response.IsError {
		status = CallStatusError
		decision = AuditErrorDecision
	}
	return &actionOutcome{
		response:  response,
		decision:  decision,
		status:    status,
		argsHash:  argsHash,
		metadata:  map[string]any{"idempotentReplay": true},
		cacheable: false,
	}
}

func (s *Server) runResolvedAction(ctx context.Context, action *Action, auth *AuthResult, request *http.Request, name string, rawArgs map[string]any, input any, argsHash string, actx *Context, meta map[string]any, redactPaths []string, policyConfirm bool, started time.Time, traceID, callID string) (*actionOutcome, error) {
	if actx.DryRun {
		payload := map[string]any{
			"status": "dry_run",
			"action": name,
			"args":   Redact(input, redactPaths),
		}
		return &actionOutcome{
			response:       s.successResult(payload, nil, traceID, nil),
			decision:       AuditDryRun,
			status:         CallStatusDryRun,
			argsHash:       argsHash,
			callArgs:       input,
			result:         payload,
			redactedResult: payload,
			metadata:       map[string]any{"dryRun": true},
			cacheable:      false,
		}, nil
	}

	needsConfirm := policyConfirm || safeNeedsConfirm(action, ctx, input, actx)
	var grant *ApprovalGrant
	if needsConfirm {
		resolution, err := s.resolveApproval(ctx, action, name, rawArgs, argsHash, actx, meta)
		if err != nil {
			return nil, err
		}
		if resolution.pending != nil {
			record := resolution.pending
			approveURL := s.approvalURL(record.ID, request)
			payload := map[string]any{
				"status":     "approval_required",
				"action":     name,
				"approvalId": record.ID,
				"approveUrl": approveURL,
				"retry":      true,
				"argsHash":   argsHash,
				"expiresAt":  record.ExpiresAt.UTC().Format(time.RFC3339Nano),
			}
			text := fmt.Sprintf("Approval required for %s.\nApproval ID: %s\nApprove at: %s\nRetry the same call after approval.", name, record.ID, approveURL)
			return &actionOutcome{
				response:   s.structuredResult(payload, text, traceID),
				decision:   AuditApprovalRequired,
				status:     CallStatusApprovalRequired,
				argsHash:   argsHash,
				callArgs:   input,
				approvalID: record.ID,
				metadata:   map[string]any{"approvalId": record.ID},
				cacheable:  false,
			}, nil
		}
		grant = resolution.grant
		actx.Approval = grant
	}
	approvalID := ""
	if grant != nil {
		approvalID = grant.ID
	}

	if action.Task && s.opts.enableTasks {
		taskID := CreateID("task")
		taskCtx := *actx
		taskCtx.IdempotencyKey = ""
		task, err := s.tasks.Start(TaskRecord{
			ID:          taskID,
			Action:      name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			TraceID:     traceID,
			ApprovalID:  approvalID,
			CallID:      callID,
			Input:       input,
		}, func(runCtx context.Context) (any, *CallReceipt, error) {
			return s.runTask(runCtx, action, auth, input, argsHash, &taskCtx, redactPaths, approvalID, callID, traceID)
		})
		if err != nil {
			return nil, err
		}
		payload := map[string]any{"status": "working", "taskId": task.ID, "action": name}
		return &actionOutcome{
			response:   s.structuredResult(payload, fmt.Sprintf("Task started: %s. Poll gap.tasks.get to read the result.", task.ID), traceID),
			decision:   AuditAllowed,
			status:     CallStatusTask,
			argsHash:   argsHash,
			callArgs:   input,
			approvalID: approvalID,
			taskID:     task.ID,
			metadata:   map[string]any{"taskId": task.ID},
			cacheable:  true,
		}, nil
	}

	timeout := action.Timeout
	if timeout <= 0 {
		timeout = s.opts.timeout
	}
	raw, err := executeWithTimeout(ctx, timeout, func(execCtx context.Context) (any, error) {
		return action.Execute(execCtx, input, actx)
	})
	if err != nil {
		return nil, err
	}
	result, err := s.validateOutput(action, raw)
	if err != nil {
		return nil, err
	}
	redacted := Redact(result, redactPaths)
	duration := time.Since(started).Milliseconds()
	receipt, err := s.createReceipt(callID, action, auth, argsHash, result, duration, approvalID, traceID)
	if err != nil {
		return nil, err
	}
	return &actionOutcome{
		response:       s.successResult(redacted, receipt, traceID, nil),
		decision:       AuditAllowed,
		status:         CallStatusSuccess,
		argsHash:       argsHash,
		resultHash:     receipt.ResultHash,
		callArgs:       input,
		result:         result,
		redactedResult: redacted,
		receipt:        receipt,
		approvalID:     approvalID,
		cacheable:      true,
	}, nil
}

func safeNeedsConfirm(action *Action, ctx context.Context, input any, actx *Context) (needs bool) {
	defer func() {
		if recover() != nil {
			needs = true
		}
	}()
	return action.NeedsConfirm(ctx, input, actx)
}

func (s *Server) evaluatePolicy(action *Action, args any, actx *Context) (decision PolicyDecision) {
	defer func() {
		if recover() != nil {
			decision = PolicyDecision{Decision: "deny", Reason: "Policy evaluation failed.", Code: CodePolicyDenied}
		}
	}()
	decision = s.opts.policy.Evaluate(PolicyInput{Action: action, Args: args, Context: actx})
	switch decision.Decision {
	case "allow", "deny", "confirm":
		return decision
	default:
		return PolicyDecision{Decision: "deny", Reason: "Policy returned an invalid decision.", Code: CodePolicyDenied}
	}
}

func (s *Server) validateOutput(action *Action, raw any) (any, error) {
	if action.OutputSchema == nil {
		return raw, nil
	}
	value, err := ToJSONValue(raw)
	if err != nil {
		return nil, WrapError(err, "The action returned a result that is not JSON-serializable.", CodeInternal)
	}
	validated, issues := ValidateValue(action.OutputSchema, value)
	if len(issues) > 0 {
		return nil, Internal("The action returned a result that does not match its output schema.", nil).
			WithDetails(map[string]any{"issues": issues})
	}
	return validated, nil
}

func (s *Server) createReceipt(id string, action *Action, auth *AuthResult, argsHash string, result any, durationMS int64, approvalID, traceID string) (*CallReceipt, error) {
	resultHash, err := Hash(result)
	if err != nil {
		return nil, WrapError(err, "The action returned a result that is not JSON-serializable.", CodeInternal)
	}
	return &CallReceipt{
		ID:          id,
		Action:      action.Name,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		CreatedAt:   time.Now().UTC(),
		DurationMS:  durationMS,
		ArgsHash:    argsHash,
		ResultHash:  resultHash,
		Undoable:    action.Undo != nil,
		ApprovalID:  approvalID,
		TraceID:     traceID,
	}, nil
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

type approvalResolution struct {
	grant   *ApprovalGrant
	pending *ApprovalRecord
}

func (s *Server) resolveApproval(ctx context.Context, action *Action, name string, rawArgs map[string]any, argsHash string, actx *Context, meta map[string]any) (*approvalResolution, error) {
	principalID := actx.Principal.ID
	if token := readMetaString(meta, "gap/approval", "approvalToken"); token != "" && s.opts.approvals != nil {
		grant, err := s.opts.approvals.Verify(token, ApprovalRequest{
			Action:      name,
			Args:        rawArgs,
			PrincipalID: principalID,
		})
		if err != nil || grant == nil || grant.Action != name || grant.Expired(time.Now()) {
			return nil, ApprovalRequiredError("Invalid or expired approval token.", map[string]any{"reason": "invalid_token"})
		}
		return &approvalResolution{grant: grant}, nil
	}

	now := time.Now()
	records := s.approvalStore.List(&ApprovalFilter{PrincipalID: principalID, Action: name, ArgsHash: argsHash})
	var pending *ApprovalRecord
	var denied *ApprovalRecord
	for _, record := range records {
		if record == nil {
			continue
		}
		if record.Status == ApprovalApproved && record.ExpiresAt.After(now) {
			consumed, err := s.approvalStore.Consume(record.ID)
			if err != nil {
				if IsCode(err, CodeConflict) {
					return nil, ApprovalRequiredError("This approval has already been used.", map[string]any{
						"approvalId": record.ID,
						"status":     string(ApprovalConsumed),
					})
				}
				return nil, err
			}
			return &approvalResolution{grant: grantFromApprovalRecord(consumed)}, nil
		}
		if record.Status == ApprovalPending && record.ExpiresAt.After(now) && pending == nil {
			pending = record
		}
		if record.Status == ApprovalDenied && denied == nil {
			denied = record
		}
	}
	if pending != nil {
		return &approvalResolution{pending: pending}, nil
	}
	if denied != nil {
		return nil, ApprovalRequiredError("Approval was denied.", map[string]any{
			"approvalId": denied.ID,
			"status":     string(ApprovalDenied),
			"reason":     denied.Reason,
		})
	}

	created, err := s.approvalStore.Create(CreateApprovalInput{
		PrincipalID: principalID,
		Action:      name,
		ArgsHash:    argsHash,
		Args:        rawArgs,
		TTL:         s.opts.approvalTTL,
		Metadata:    map[string]any{"traceId": actx.TraceID},
	})
	if err != nil {
		return nil, err
	}
	return &approvalResolution{pending: created}, nil
}

func grantFromApprovalRecord(record *ApprovalRecord) *ApprovalGrant {
	if record == nil {
		return nil
	}
	approvedAt := record.CreatedAt
	if record.ApprovedAt != nil {
		approvedAt = *record.ApprovedAt
	}
	approvedBy := record.ApprovedBy
	if approvedBy == "" {
		approvedBy = "unknown"
	}
	return &ApprovalGrant{
		ID:         record.ID,
		Action:     record.Action,
		ArgsHash:   record.ArgsHash,
		ApprovedBy: approvedBy,
		IssuedAt:   approvedAt.UnixMilli(),
		ExpiresAt:  record.ExpiresAt.UnixMilli(),
	}
}

func (s *Server) approvalURL(id string, request *http.Request) string {
	base := s.baseURLFor(request)
	if base == "" {
		return "/approvals/" + url.PathEscape(id)
	}
	return base + "/approvals/" + url.PathEscape(id)
}

// ---------------------------------------------------------------------------
// Execution helpers
// ---------------------------------------------------------------------------

type executionResult struct {
	value any
	err   error
}

func executeWithTimeout(ctx context.Context, timeout time.Duration, run func(context.Context) (any, error)) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan executionResult, 1)
	go func() {
		var out executionResult
		defer func() {
			if recovered := recover(); recovered != nil {
				out = executionResult{err: Internal("The action panicked.", fmt.Errorf("panic: %v", recovered))}
			}
			done <- out
		}()
		out.value, out.err = run(execCtx)
	}()

	select {
	case out := <-done:
		if out.err != nil {
			return nil, out.err
		}
		if execCtx.Err() != nil {
			return nil, timeoutFailure("The action timed out or was cancelled.")
		}
		return out.value, nil
	case <-execCtx.Done():
		return nil, timeoutFailure("The action timed out or was cancelled.")
	}
}

func timeoutFailure(message string) *Error {
	err := NewError(message, CodeTimeout)
	err.Retryable = true
	return err
}

func (s *Server) runTask(ctx context.Context, action *Action, auth *AuthResult, input any, argsHash string, actx *Context, redactPaths []string, approvalID, callID, traceID string) (any, *CallReceipt, error) {
	started := time.Now()
	taskCtx := *actx
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = s.opts.timeout
	}
	raw, err := executeWithTimeout(ctx, timeout, func(execCtx context.Context) (any, error) {
		return action.Execute(execCtx, input, &taskCtx)
	})
	if err != nil {
		failure := Normalize(err)
		s.recordCall(CallRecord{
			ID:          callID,
			Timestamp:   time.Now().UTC(),
			Action:      action.Name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Status:      CallStatusError,
			Args:        input,
			Error:       &CallError{Code: failure.Code, Message: failure.PublicMessage(), Details: failure.PublicDetails()},
			DurationMS:  time.Since(started).Milliseconds(),
			ApprovalID:  approvalID,
			TraceID:     traceID,
		})
		s.emitAudit(ctx, AuditEvent{
			Action:      action.Name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Decision:    auditDecisionForError(failure.Code),
			ArgsHash:    argsHash,
			DurationMS:  time.Since(started).Milliseconds(),
			Scopes:      auth.Scopes,
			ApprovalID:  approvalID,
			TraceID:     traceID,
			Error:       &AuditError{Code: failure.Code, Message: failure.PublicMessage()},
			Metadata:    map[string]any{"background": true},
		})
		return nil, nil, failure
	}
	result, err := s.validateOutput(action, raw)
	if err != nil {
		return nil, nil, err
	}
	redacted := Redact(result, redactPaths)
	receipt, err := s.createReceipt(callID, action, auth, argsHash, result, time.Since(started).Milliseconds(), approvalID, traceID)
	if err != nil {
		return nil, nil, err
	}
	s.recordCall(CallRecord{
		ID:             callID,
		Timestamp:      time.Now().UTC(),
		Action:         action.Name,
		PrincipalID:    auth.Principal.ID,
		TenantID:       auth.Principal.TenantID,
		Status:         CallStatusSuccess,
		Args:           input,
		Result:         result,
		RedactedResult: redacted,
		DurationMS:     time.Since(started).Milliseconds(),
		Receipt:        receipt,
		ApprovalID:     approvalID,
		TraceID:        traceID,
		Metadata:       map[string]any{"background": true},
	})
	s.emitAudit(ctx, AuditEvent{
		Action:      action.Name,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		Decision:    AuditAllowed,
		ArgsHash:    argsHash,
		ResultHash:  receipt.ResultHash,
		DurationMS:  time.Since(started).Milliseconds(),
		Scopes:      auth.Scopes,
		ApprovalID:  approvalID,
		TraceID:     traceID,
		Metadata:    map[string]any{"background": true},
	})
	return redacted, receipt, nil
}

// ---------------------------------------------------------------------------
// Built-in tools
// ---------------------------------------------------------------------------

type builtinOutcome struct {
	response       *mcp.CallToolResult
	result         any
	redactedResult any
	receipt        *CallReceipt
	metadata       map[string]any
}

func (s *Server) handleBuiltin(ctx context.Context, auth *AuthResult, request *http.Request, name string, args map[string]any, meta map[string]any) *mcp.CallToolResult {
	started := time.Now()
	traceID := CreateID("trace")
	callID := CreateID("rcpt")
	descriptor := builtinDescriptor(name)
	if descriptor.Name == "" || !s.builtinAvailable(name, auth.Scopes) {
		return s.errorResult(NotFound(fmt.Sprintf("Tool %q is not available.", name)), traceID)
	}
	validated, issues := ValidateValue(descriptor.InputSchema, args)
	if len(issues) > 0 {
		return s.errorResult(InvalidInput(fmt.Sprintf("Invalid input for %q.", name), map[string]any{"issues": issues}), traceID)
	}
	input, _ := validated.(map[string]any)
	if input == nil {
		input = map[string]any{}
	}

	outcome, err := s.runBuiltin(ctx, auth, request, name, input, meta, traceID)
	if err != nil {
		failure := Normalize(err)
		s.recordCall(CallRecord{
			ID:          callID,
			Timestamp:   time.Now().UTC(),
			Action:      name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Status:      CallStatusError,
			Args:        input,
			Error:       &CallError{Code: failure.Code, Message: failure.PublicMessage(), Details: failure.PublicDetails()},
			DurationMS:  time.Since(started).Milliseconds(),
			TraceID:     traceID,
			Metadata:    map[string]any{"builtin": true},
		})
		s.emitAudit(ctx, AuditEvent{
			Action:      name,
			PrincipalID: auth.Principal.ID,
			TenantID:    auth.Principal.TenantID,
			Decision:    auditDecisionForError(failure.Code),
			DurationMS:  time.Since(started).Milliseconds(),
			Scopes:      auth.Scopes,
			TraceID:     traceID,
			Error:       &AuditError{Code: failure.Code, Message: failure.PublicMessage()},
			Metadata:    map[string]any{"builtin": true},
		})
		return s.errorResult(failure, traceID)
	}
	s.recordCall(CallRecord{
		ID:             callID,
		Timestamp:      time.Now().UTC(),
		Action:         name,
		PrincipalID:    auth.Principal.ID,
		TenantID:       auth.Principal.TenantID,
		Status:         CallStatusSuccess,
		Args:           input,
		Result:         outcome.result,
		RedactedResult: outcome.redactedResult,
		DurationMS:     time.Since(started).Milliseconds(),
		Receipt:        outcome.receipt,
		TraceID:        traceID,
		Metadata:       mergeMaps(map[string]any{"builtin": true}, outcome.metadata),
	})
	s.emitAudit(ctx, AuditEvent{
		Action:      name,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		Decision:    AuditAllowed,
		DurationMS:  time.Since(started).Milliseconds(),
		Scopes:      auth.Scopes,
		TraceID:     traceID,
		Metadata:    mergeMaps(map[string]any{"builtin": true}, outcome.metadata),
	})
	return outcome.response
}

func (s *Server) builtinAvailable(name string, scopes []string) bool {
	for _, descriptor := range s.builtinDescriptors(scopes) {
		if descriptor.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) runBuiltin(ctx context.Context, auth *AuthResult, request *http.Request, name string, input map[string]any, meta map[string]any, traceID string) (*builtinOutcome, error) {
	switch name {
	case "gap.tasks.get":
		return s.builtinTasksGet(input, auth, traceID)
	case "gap.tasks.cancel":
		return s.builtinTasksCancel(input, auth, traceID)
	case "gap.receipts.get":
		return s.builtinReceiptsGet(input, auth, traceID)
	case "gap.undo":
		return s.builtinUndo(ctx, input, auth, request, traceID)
	case "gap.handoff":
		return s.builtinHandoff(input, auth, request, traceID)
	case "gap.search":
		return s.builtinSearch(input, auth, traceID)
	default:
		return nil, NotFound(fmt.Sprintf("Unknown tool %q.", name))
	}
}

func (s *Server) builtinTasksGet(input map[string]any, auth *AuthResult, traceID string) (*builtinOutcome, error) {
	taskID, _ := input["taskId"].(string)
	if taskID == "" {
		return nil, InvalidInput("A taskId is required.", nil)
	}
	task, ok := s.tasks.Get(taskID)
	if !ok || task.PrincipalID != auth.Principal.ID {
		return nil, NotFound("Task not found.")
	}
	return &builtinOutcome{
		response:       s.successResult(task, task.Receipt, traceID, nil),
		result:         task,
		redactedResult: task,
		receipt:        task.Receipt,
		metadata:       map[string]any{"taskId": task.ID, "taskStatus": string(task.Status)},
	}, nil
}

func (s *Server) builtinTasksCancel(input map[string]any, auth *AuthResult, traceID string) (*builtinOutcome, error) {
	taskID, _ := input["taskId"].(string)
	if taskID == "" {
		return nil, InvalidInput("A taskId is required.", nil)
	}
	existing, ok := s.tasks.Get(taskID)
	if !ok || existing.PrincipalID != auth.Principal.ID {
		return nil, NotFound("Task not found.")
	}
	task, err := s.tasks.Cancel(taskID)
	if err != nil {
		return nil, err
	}
	return &builtinOutcome{
		response:       s.successResult(task, task.Receipt, traceID, nil),
		result:         task,
		redactedResult: task,
		receipt:        task.Receipt,
		metadata:       map[string]any{"taskId": task.ID, "taskStatus": string(task.Status)},
	}, nil
}

func (s *Server) builtinReceiptsGet(input map[string]any, auth *AuthResult, traceID string) (*builtinOutcome, error) {
	receiptID, _ := input["receiptId"].(string)
	if receiptID == "" {
		return nil, InvalidInput("A receiptId is required.", nil)
	}
	call, ok := s.calls.Get(receiptID)
	if !ok || call.Receipt == nil || call.PrincipalID != auth.Principal.ID {
		return nil, NotFound("Receipt not found.")
	}
	result := call.RedactedResult
	if result == nil {
		result = call.Result
	}
	payload := map[string]any{
		"receipt":       call.Receipt,
		"args":          call.Args,
		"result":        result,
		"undoneAt":      call.UndoneAt,
		"undoReceiptId": call.UndoReceiptID,
	}
	return &builtinOutcome{
		response:       s.successResult(payload, call.Receipt, traceID, nil),
		result:         payload,
		redactedResult: payload,
		receipt:        call.Receipt,
		metadata:       map[string]any{"receiptId": call.Receipt.ID},
	}, nil
}

func (s *Server) builtinUndo(ctx context.Context, input map[string]any, auth *AuthResult, request *http.Request, traceID string) (*builtinOutcome, error) {
	receiptID, _ := input["receiptId"].(string)
	if receiptID == "" {
		return nil, InvalidInput("A receiptId is required.", nil)
	}
	call, ok := s.calls.Get(receiptID)
	if !ok || call.Receipt == nil || call.PrincipalID != auth.Principal.ID {
		return nil, NotFound("Receipt not found.")
	}
	if call.UndoneAt != nil {
		return nil, Conflict("This receipt has already been undone.", map[string]any{
			"receiptId":     receiptID,
			"undoReceiptId": call.UndoReceiptID,
		})
	}
	action := s.registry.Get(call.Receipt.Action)
	if action == nil {
		return nil, NotFound(fmt.Sprintf("Action %q is no longer registered.", call.Receipt.Action))
	}
	if action.Undo == nil {
		return nil, InvalidInput("This action does not define an undo handler.", nil)
	}

	undoID := CreateID("rcpt")
	undoTraceID := CreateID("trace")
	started := time.Now()
	actx := &Context{
		Principal: auth.Principal.Clone(),
		Scopes:    append([]string(nil), auth.Scopes...),
		TenantID:  auth.Principal.TenantID,
		Approval:  call.Approval,
		TraceID:   undoTraceID,
		Logger:    s.opts.logger,
		ToolName:  "gap.undo",
		Request:   request,
	}
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = s.opts.timeout
	}
	_, err := executeWithTimeout(ctx, timeout, func(execCtx context.Context) (any, error) {
		return nil, action.Undo(execCtx, call.Result, call.Args, actx)
	})
	if err != nil {
		return nil, err
	}
	undoResult := map[string]any{"undone": call.Receipt.ID}
	resultHash, err := Hash(undoResult)
	if err != nil {
		return nil, Internal("Failed to hash the undo receipt.", err)
	}
	receipt := &CallReceipt{
		ID:          undoID,
		Action:      action.Name,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		CreatedAt:   time.Now().UTC(),
		DurationMS:  time.Since(started).Milliseconds(),
		ArgsHash:    call.Receipt.ArgsHash,
		ResultHash:  resultHash,
		Undoable:    false,
		ApprovalID:  call.ApprovalID,
		TraceID:     undoTraceID,
		UndoOf:      call.Receipt.ID,
	}
	s.calls.MarkUndone(call.Receipt.ID, undoID, time.Now().UTC())
	payload := map[string]any{"undone": true, "receipt": receipt, "undoOf": call.Receipt.ID}
	return &builtinOutcome{
		response:       s.successResult(payload, receipt, traceID, nil),
		result:         payload,
		redactedResult: payload,
		receipt:        receipt,
		metadata:       map[string]any{"receiptId": undoID, "undoOf": call.Receipt.ID},
	}, nil
}

func (s *Server) builtinHandoff(input map[string]any, auth *AuthResult, request *http.Request, traceID string) (*builtinOutcome, error) {
	actionName, _ := input["action"].(string)
	if actionName == "" {
		return nil, InvalidInput("An action is required.", nil)
	}
	action := s.registry.Get(actionName)
	if action == nil {
		return nil, NotFound(fmt.Sprintf("Unknown action %q.", actionName))
	}
	if missing := MissingScopes(auth.Scopes, action.Scopes); len(missing) > 0 {
		return nil, Forbidden(fmt.Sprintf("Missing required scope(s): %s.", strings.Join(missing, ", "))).
			WithDetails(map[string]any{"missingScopes": missing})
	}
	if action.UI == nil || s.opts.handoffSecret == "" {
		return nil, InvalidInput(fmt.Sprintf("Action %q has no UI binding.", actionName), nil)
	}
	rawArgs := map[string]any{}
	if value, ok := input["args"].(map[string]any); ok {
		rawArgs = value
	}
	var handoffArgs any = rawArgs
	if action.InputSchema != nil {
		validated, issues := ValidateValue(action.InputSchema, rawArgs)
		if len(issues) > 0 {
			return nil, InvalidInput(fmt.Sprintf("Invalid arguments for %q.", actionName), map[string]any{"issues": issues})
		}
		handoffArgs = validated
	}
	route := action.UI.Route
	if route == "" {
		route = "/"
	}
	link, err := CreateHandoffLink(HandoffLinkOptions{
		Secret:      s.opts.handoffSecret,
		Action:      action.Name,
		Args:        handoffArgs,
		PrincipalID: auth.Principal.ID,
		TenantID:    auth.Principal.TenantID,
		BaseURL:     s.baseURLFor(request),
		Route:       route,
		TTL:         s.opts.handoffTTL,
	})
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"action":    action.Name,
		"url":       link.URL,
		"expiresAt": link.ExpiresAt,
	}
	return &builtinOutcome{
		response:       s.successResult(payload, nil, traceID, map[string]any{"token": link.Token}),
		result:         payload,
		redactedResult: payload,
		metadata:       map[string]any{"handoffAction": action.Name},
	}, nil
}

func (s *Server) builtinSearch(input map[string]any, auth *AuthResult, traceID string) (*builtinOutcome, error) {
	query, _ := input["query"].(string)
	namespace, _ := input["namespace"].(string)
	limit := 10
	if raw, ok := numericValue(input["limit"]); ok {
		limit = int(raw)
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	tags := make([]string, 0)
	if values, ok := input["tags"].([]any); ok {
		for _, value := range values {
			if tag, ok := value.(string); ok {
				tags = append(tags, tag)
			}
		}
	}
	terms := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	namespace = strings.TrimSpace(strings.TrimSuffix(namespace, "."))

	matches := make([]ToolDescriptor, 0)
	for _, action := range s.registry.VisibleTo(auth.Scopes) {
		if namespace != "" && !strings.HasPrefix(action.Name, namespace+".") && action.Name != namespace {
			continue
		}
		if !hasAllTags(action.Tags, tags) {
			continue
		}
		haystack := strings.ToLower(action.Name + " " + action.Description + " " + strings.Join(action.Tags, " "))
		matched := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		matches = append(matches, ToToolDescriptor(action))
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Name < matches[j].Name })
	total := len(matches)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	tools := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		tools = append(tools, map[string]any{
			"name":        match.Name,
			"title":       match.Title,
			"description": match.Description,
			"inputSchema": match.InputSchema,
			"annotations": match.Annotations,
			"_meta":       match.Meta,
		})
	}
	payload := map[string]any{"tools": tools, "total": total}
	return &builtinOutcome{
		response:       s.successResult(payload, nil, traceID, nil),
		result:         payload,
		redactedResult: payload,
		metadata:       map[string]any{"matched": total},
	}, nil
}

func hasAllTags(available, required []string) bool {
	for _, want := range required {
		found := false
		for _, tag := range available {
			if tag == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Stores, results and audit
// ---------------------------------------------------------------------------

func (s *Server) recordCall(record CallRecord) {
	if s == nil {
		return
	}
	stored := s.calls.Put(record)
	if s.opts.onCall == nil || stored == nil {
		return
	}
	callback := *stored
	if callback.RedactedResult != nil {
		callback.Result = callback.RedactedResult
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.opts.logger.Warn("OnCall callback panicked.", fmt.Sprint(recovered))
			}
		}()
		s.opts.onCall(callback)
	}()
}

func (s *Server) emitAudit(ctx context.Context, event AuditEvent) {
	if s == nil || len(s.auditSinks) == 0 {
		return
	}
	event = NewAuditEvent(event)
	for _, sink := range s.auditSinks {
		if err := sink.Record(ctx, event); err != nil {
			s.opts.logger.Warn("Audit sink failed.", err.Error())
		}
	}
}

func (s *Server) successResult(value any, receipt *CallReceipt, traceID string, extras map[string]any) *mcp.CallToolResult {
	jsonValue, err := ToJSONValue(value)
	if err != nil {
		return s.errorResult(Internal("Failed to encode the action result.", err), traceID)
	}
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: renderText(jsonValue)}},
	}
	structured, isObject := jsonValue.(map[string]any)
	if isObject {
		if len(extras) > 0 {
			merged := make(map[string]any, len(structured)+len(extras))
			for key, item := range structured {
				merged[key] = item
			}
			for key, item := range extras {
				merged[key] = item
			}
			structured = merged
		}
		result.StructuredContent = structured
	} else if len(extras) > 0 {
		merged := make(map[string]any, len(extras)+1)
		for key, item := range extras {
			merged[key] = item
		}
		merged["result"] = jsonValue
		result.StructuredContent = merged
	}
	meta := mcp.Meta{}
	if receipt != nil {
		meta["gap/receipt"] = map[string]any{
			"id":         receipt.ID,
			"action":     receipt.Action,
			"undoable":   receipt.Undoable,
			"durationMs": receipt.DurationMS,
		}
	}
	if traceID != "" {
		meta["gap/traceId"] = traceID
	}
	if len(meta) > 0 {
		result.Meta = meta
	}
	return result
}

func (s *Server) structuredResult(payload map[string]any, text, traceID string) *mcp.CallToolResult {
	result := &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: text}},
		StructuredContent: payload,
	}
	if traceID != "" {
		result.Meta = mcp.Meta{"gap/traceId": traceID}
	}
	return result
}

func (s *Server) errorResult(err *Error, traceID string) *mcp.CallToolResult {
	if err == nil {
		err = Internal("Internal error.", nil)
	}
	payload := err.Payload()
	text := err.PublicMessage()
	if details := err.PublicDetails(); details != nil {
		text += "\n\n" + renderText(details)
	}
	result := &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: text}},
		IsError:           true,
		StructuredContent: map[string]any{"gapError": payload},
	}
	if traceID != "" {
		result.Meta = mcp.Meta{"gap/traceId": traceID}
	}
	return result
}

func renderText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if value == nil {
		return "OK"
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(raw)
}

func auditDecisionForError(code string) AuditDecision {
	switch code {
	case CodeForbidden, CodePolicyDenied, CodeRateLimited, CodeApprovalRequired:
		return AuditDenied
	default:
		return AuditErrorDecision
	}
}

func readMetaString(meta map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := meta[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func mergeMaps(groups ...map[string]any) map[string]any {
	var out map[string]any
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(group))
		}
		for key, value := range group {
			out[key] = value
		}
	}
	return out
}

func (s *Server) waitForInFlight(ctx context.Context, key string) *inFlightCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight[key]
}

func (s *Server) beginInFlight(key string) (*inFlightCall, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.inFlight[key]; ok {
		return existing, false
	}
	flight := &inFlightCall{done: make(chan struct{})}
	s.inFlight[key] = flight
	return flight, true
}

func (s *Server) endInFlight(key string, flight *inFlightCall) {
	s.mu.Lock()
	if current, ok := s.inFlight[key]; ok && current == flight {
		delete(s.inFlight, key)
	}
	s.mu.Unlock()
	close(flight.done)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Close aborts background tasks and waits up to ctx for them to settle.
func (s *Server) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.tasks.Close(ctx)
}

// ServeStdio serves MCP over stdin/stdout as the anonymous principal. It blocks
// until ctx is cancelled or the transport closes.
func (s *Server) ServeStdio(ctx context.Context) error {
	if s == nil {
		return Internal("GapServer is nil.", nil)
	}
	return s.serveTransport(ctx, &mcp.StdioTransport{})
}

// ServeStdio serves an existing server over stdin/stdout.
func ServeStdio(ctx context.Context, server *Server) error {
	if server == nil {
		return Internal("GapServer is nil.", nil)
	}
	return server.ServeStdio(ctx)
}

func (s *Server) serveTransport(ctx context.Context, transport mcp.Transport) error {
	auth := anonymousAuthResult()
	protocolServer := s.newMCPServer(auth, nil)
	return protocolServer.Run(ctx, transport)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

type allowAllPolicy struct{}

func (allowAllPolicy) Evaluate(PolicyInput) PolicyDecision {
	return PolicyDecision{Decision: "allow"}
}

func normalizeHTTPPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if len(trimmed) > 1 && strings.HasSuffix(trimmed, "/") {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

func writeJSON(w http.ResponseWriter, request *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if request != nil && request.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter, request *http.Request, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, request, http.StatusMethodNotAllowed, map[string]any{
		"error":             "method_not_allowed",
		"error_description": "Method not allowed.",
	})
}
