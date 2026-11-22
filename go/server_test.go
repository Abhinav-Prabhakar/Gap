package gap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testRegistry(t *testing.T, actions ...*Action) *Registry {
	t.Helper()
	registry := NewRegistry()
	for _, action := range actions {
		if err := registry.Add(action); err != nil {
			t.Fatalf("add action %s: %v", action.Name, err)
		}
	}
	return registry
}

func startTestServer(t *testing.T, options ServerOptions) (*Server, *httptest.Server) {
	t.Helper()
	if options.Registry == nil {
		options.Registry = NewRegistry()
	}
	server, err := NewServer(options)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	httpServer := httptest.NewServer(server)
	t.Cleanup(func() {
		httpServer.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Close(ctx)
	})
	return server, httpServer
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	for key, value := range h.headers {
		clone.Header.Set(key, value)
	}
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

func bearerHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func connectSession(t *testing.T, httpServer *httptest.Server, headers map[string]string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "gap-test-client", Version: "1.0.0"}, nil)
	base := httpServer.Client().Transport
	httpClient := &http.Client{Transport: base}
	if len(headers) > 0 {
		httpClient.Transport = headerTransport{base: base, headers: headers}
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:             httpServer.URL + "/mcp",
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func listToolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, meta map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	params := &mcp.CallToolParams{Name: name, Arguments: args}
	if len(meta) > 0 {
		params.Meta = mcp.Meta(meta)
	}
	result, err := session.CallTool(ctx, params)
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return result
}

func structuredMap(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	value, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content is %T, want map[string]any", result.StructuredContent)
	}
	return value
}

func gapError(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if !result.IsError {
		t.Fatalf("result is not an error: %#v", result)
	}
	payload := structuredMap(t, result)
	errorValue, ok := payload["gapError"].(map[string]any)
	if !ok {
		t.Fatalf("gapError missing from %#v", payload)
	}
	return errorValue
}

func gapErrorCode(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	code, _ := gapError(t, result)["code"].(string)
	return code
}

func receiptID(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result.Meta == nil {
		t.Fatalf("result has no meta: %#v", result)
	}
	value, ok := result.Meta["gap/receipt"].(map[string]any)
	if !ok {
		t.Fatalf("gap/receipt missing from %#v", result.Meta)
	}
	id, _ := value["id"].(string)
	if id == "" {
		t.Fatalf("receipt id missing from %#v", value)
	}
	return id
}

func resultText(result *mcp.CallToolResult) string {
	var builder strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			builder.WriteString(text.Text)
		}
	}
	return builder.String()
}

func echoAction(name string, counter *int32) *Action {
	return DefineAction(Action{
		Name:        name,
		Description: "Echo the supplied message back to the caller for testing.",
		InputSchema: objectSchema(map[string]any{
			"message": property("string", "Message to echo."),
		}, []string{"message"}),
		Execute: func(_ context.Context, input any, _ *Context) (any, error) {
			if counter != nil {
				*counter++
			}
			values, _ := input.(map[string]any)
			message, _ := values["message"].(string)
			return map[string]any{"message": message}, nil
		},
	})
}

func apiKeyProvider(records ...APIKeyRecord) *APIKeyAuth {
	return NewAPIKeyAuth(APIKeyAuthOptions{Keys: records})
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func waitForTask(t *testing.T, session *mcp.ClientSession, taskID string, want TaskStatus) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last map[string]any
	for time.Now().Before(deadline) {
		result := callTool(t, session, "gap.tasks.get", map[string]any{"taskId": taskID}, nil)
		last = structuredMap(t, result)
		if last["status"] == string(want) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s; last = %#v", taskID, want, last)
	return nil
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

func TestServerHealthAndMetadata(t *testing.T) {
	_, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil)),
	})

	response, err := http.Get(httpServer.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
	var health map[string]any
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "ok" || health["actions"] != float64(1) {
		t.Fatalf("health = %#v", health)
	}

	response, err = http.Get(httpServer.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d", response.StatusCode)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("metadata cache-control = %q", response.Header.Get("Cache-Control"))
	}

	response, err = http.Post(httpServer.URL+"/health", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /health status = %d", response.StatusCode)
	}

	response, err = http.Get(httpServer.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != "POST" {
		t.Fatalf("GET /mcp = %d, allow = %q", response.StatusCode, response.Header.Get("Allow"))
	}

	response, err = http.Get(httpServer.URL + "/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", response.StatusCode)
	}
}

func TestServerUnauthorizedChallenge(t *testing.T) {
	auth := apiKeyProvider(APIKeyRecord{Key: "key", Principal: TestPrincipal()})
	_, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil)),
		Auth:     auth,
	})

	request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("challenge = %q", response.Header.Get("WWW-Authenticate"))
	}
	if !strings.Contains(response.Header.Get("Link"), "oauth-protected-resource") {
		t.Fatalf("link = %q", response.Header.Get("Link"))
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "unauthorized" {
		t.Fatalf("body = %#v", body)
	}
	if body["resource_metadata"] == "" {
		t.Fatalf("body = %#v", body)
	}
}

func TestServerAnonymous(t *testing.T) {
	registry := testRegistry(t, echoAction("test.echo", nil))

	_, httpServer := startTestServer(t, ServerOptions{Registry: registry})
	session := connectSession(t, httpServer, nil)
	if names := listToolNames(t, session); !containsName(names, "test.echo") {
		t.Fatalf("tools = %v", names)
	}

	_, deniedServer := startTestServer(t, ServerOptions{
		Registry:       registry,
		AllowAnonymous: Ptr(false),
	})
	request, _ := http.NewRequest(http.MethodPost, deniedServer.URL+"/mcp", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestServerMetadataProvider(t *testing.T) {
	provider := testMetadataAuth{document: map[string]any{
		"resource":              "https://custom.example.com",
		"authorization_servers": []any{"https://auth.example.com"},
	}}
	_, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil)),
		Auth:     provider,
	})
	response, err := http.Get(httpServer.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document["resource"] != "https://custom.example.com" {
		t.Fatalf("document = %#v", document)
	}

	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/mcp", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Header.Get("WWW-Authenticate") != `Bearer realm="custom"` {
		t.Fatalf("challenge = %q", response.Header.Get("WWW-Authenticate"))
	}
}

type testMetadataAuth struct {
	document map[string]any
}

func (a testMetadataAuth) Authenticate(*http.Request) (*AuthResult, error) { return nil, nil }
func (a testMetadataAuth) Challenge() string                               { return `Bearer realm="custom"` }
func (a testMetadataAuth) ProtectedResourceMetadata() map[string]any       { return a.document }

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

func TestServerMCPEchoAndScopes(t *testing.T) {
	admin := echoAction("admin.secret", nil)
	admin.Scopes = []string{"admin:write"}
	auth := apiKeyProvider(
		APIKeyRecord{
			Key:       "read-key",
			Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_read", Scopes: []string{"test:read"}}),
		},
		APIKeyRecord{
			Key:       "admin-key",
			Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_admin", Scopes: []string{"admin:write"}}),
		},
	)
	server, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil), admin),
		Auth:     auth,
		Audit:    NewMemoryAuditLog(),
	})
	session := connectSession(t, httpServer, bearerHeaders("read-key"))

	names := listToolNames(t, session)
	if !containsName(names, "test.echo") || !containsName(names, "gap.receipts.get") {
		t.Fatalf("tools = %v", names)
	}
	if containsName(names, "admin.secret") {
		t.Fatalf("out-of-scope tool was listed: %v", names)
	}

	result := callTool(t, session, "test.echo", map[string]any{"message": "hello"}, nil)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	payload := structuredMap(t, result)
	if payload["message"] != "hello" {
		t.Fatalf("payload = %#v", payload)
	}
	if resultText(result) == "" {
		t.Fatal("text content is empty")
	}
	receiptID(t, result)
	if len(server.Calls().List(nil)) != 1 {
		t.Fatalf("calls = %d", len(server.Calls().List(nil)))
	}

	forbidden := callTool(t, session, "admin.secret", map[string]any{"message": "x"}, nil)
	if code := gapErrorCode(t, forbidden); code != CodeForbidden {
		t.Fatalf("code = %s", code)
	}

	unknown := callTool(t, session, "missing.tool", map[string]any{}, nil)
	if code := gapErrorCode(t, unknown); code != CodeNotFound {
		t.Fatalf("code = %s", code)
	}

	invalid := callTool(t, session, "test.echo", map[string]any{}, nil)
	if code := gapErrorCode(t, invalid); code != CodeInvalidInput {
		t.Fatalf("code = %s", code)
	}
	if !strings.Contains(resultText(invalid), "Invalid input") {
		t.Fatalf("text = %q", resultText(invalid))
	}

	adminSession := connectSession(t, httpServer, bearerHeaders("admin-key"))
	if names := listToolNames(t, adminSession); !containsName(names, "admin.secret") {
		t.Fatalf("admin tools = %v", names)
	}
}

func TestServerOutputValidationAndRedaction(t *testing.T) {
	secret := DefineAction(Action{
		Name:        "test.secret",
		Description: "Return a secret-bearing record for redaction testing.",
		InputSchema: objectSchema(nil, nil),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"user": map[string]any{"ssn": "123-45-6789", "name": "Ada"}}, nil
		},
	})
	badOutput := DefineAction(Action{
		Name:        "test.badOutput",
		Description: "Return a value that violates the action output schema.",
		InputSchema: objectSchema(nil, nil),
		OutputSchema: objectSchema(map[string]any{
			"ok": property("boolean", "Whether it worked."),
		}, []string{"ok"}),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"nope": true}, nil
		},
	})
	unserializable := DefineAction(Action{
		Name:        "test.unserializable",
		Description: "Return a value that cannot be encoded as JSON at all.",
		InputSchema: objectSchema(nil, nil),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"channel": make(chan int)}, nil
		},
	})
	var observed *CallRecord
	var observedMu sync.Mutex
	server, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, secret, badOutput, unserializable),
		Redact:   []string{"user.ssn"},
		OnCall: func(record CallRecord) {
			observedMu.Lock()
			copy := record
			observed = &copy
			observedMu.Unlock()
		},
	})
	session := connectSession(t, httpServer, nil)

	result := callTool(t, session, "test.secret", map[string]any{}, nil)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	payload := structuredMap(t, result)
	user := payload["user"].(map[string]any)
	if user["ssn"] != REDACTED {
		t.Fatalf("user = %#v", user)
	}
	if strings.Contains(resultText(result), "123-45-6789") {
		t.Fatalf("text leaked the secret: %s", resultText(result))
	}
	receipt := receiptID(t, result)
	stored, ok := server.Calls().Get(receipt)
	if !ok {
		t.Fatal("call record missing")
	}
	if stored.Result.(map[string]any)["user"].(map[string]any)["ssn"] != "123-45-6789" {
		t.Fatalf("raw result was lost: %#v", stored.Result)
	}
	observedMu.Lock()
	if observed == nil || observed.Result.(map[string]any)["user"].(map[string]any)["ssn"] != REDACTED {
		t.Fatalf("OnCall did not receive the redacted result: %#v", observed)
	}
	observedMu.Unlock()

	bad := callTool(t, session, "test.badOutput", map[string]any{}, nil)
	if code := gapErrorCode(t, bad); code != CodeInternal {
		t.Fatalf("code = %s", code)
	}
	if !strings.Contains(resultText(bad), "Internal error") {
		t.Fatalf("text = %q", resultText(bad))
	}
	if _, ok := gapError(t, bad)["details"]; ok {
		t.Fatalf("internal details leaked: %#v", gapError(t, bad))
	}

	unencodable := callTool(t, session, "test.unserializable", map[string]any{}, nil)
	if code := gapErrorCode(t, unencodable); code != CodeInternal {
		t.Fatalf("code = %s", code)
	}
}

func TestServerDryRunPipeline(t *testing.T) {
	var calls int32
	policy, err := NewGapPolicy(&PolicyDocument{
		Version: 1,
		Rules: []PolicyRule{{
			Tools:  []string{"test.echo"},
			DryRun: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", &calls)),
		Policy:   policy,
		Redact:   []string{"message"},
	})
	session := connectSession(t, httpServer, nil)
	result := callTool(t, session, "test.echo", map[string]any{"message": "very secret"}, nil)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	payload := structuredMap(t, result)
	if payload["status"] != "dry_run" {
		t.Fatalf("payload = %#v", payload)
	}
	args := payload["args"].(map[string]any)
	if args["message"] != REDACTED {
		t.Fatalf("dry-run args = %#v", args)
	}
	if calls != 0 {
		t.Fatalf("action executed during dry run: %d", calls)
	}
	records := server.Calls().List(nil)
	if len(records) != 1 || records[0].Status != CallStatusDryRun {
		t.Fatalf("records = %#v", records)
	}
}

func TestServerApprovalStoreFlow(t *testing.T) {
	var charges int32
	charge := DefineAction(Action{
		Name:        "billing.charge",
		Description: "Charge a customer after a human has approved the amount.",
		Confirm:     true,
		InputSchema: objectSchema(map[string]any{
			"amount": property("number", "Amount to charge in cents."),
		}, []string{"amount"}),
		Execute: func(_ context.Context, input any, _ *Context) (any, error) {
			charges++
			return map[string]any{"charged": input.(map[string]any)["amount"]}, nil
		},
	})
	server, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, charge),
	})
	session := connectSession(t, httpServer, nil)

	first := callTool(t, session, "billing.charge", map[string]any{"amount": 500}, nil)
	if first.IsError {
		t.Fatalf("unexpected error: %s", resultText(first))
	}
	payload := structuredMap(t, first)
	if payload["status"] != "approval_required" {
		t.Fatalf("payload = %#v", payload)
	}
	approvalID, _ := payload["approvalId"].(string)
	if approvalID == "" {
		t.Fatalf("payload = %#v", payload)
	}
	if charges != 0 {
		t.Fatalf("action ran before approval: %d", charges)
	}

	if _, err := server.ApprovalStore().Approve(approvalID, ResolveApprovalOptions{Actor: "admin"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	second := callTool(t, session, "billing.charge", map[string]any{"amount": 500}, nil)
	if second.IsError {
		t.Fatalf("unexpected error after approval: %s", resultText(second))
	}
	if charges != 1 {
		t.Fatalf("charges = %d", charges)
	}
	if structuredMap(t, second)["charged"] != float64(500) {
		t.Fatalf("payload = %#v", structuredMap(t, second))
	}

	third := callTool(t, session, "billing.charge", map[string]any{"amount": 700}, nil)
	if third.IsError || structuredMap(t, third)["status"] != "approval_required" {
		t.Fatalf("third = %#v %s", third.StructuredContent, resultText(third))
	}
}

func TestServerApprovalDenied(t *testing.T) {
	refund := DefineAction(Action{
		Name:        "billing.refund",
		Description: "Refund a payment after a human has approved the refund.",
		Confirm:     true,
		InputSchema: objectSchema(map[string]any{
			"amount": property("number", "Amount to refund in cents."),
		}, []string{"amount"}),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"refunded": true}, nil
		},
	})
	server, httpServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, refund)})
	session := connectSession(t, httpServer, nil)

	first := callTool(t, session, "billing.refund", map[string]any{"amount": 100}, nil)
	approvalID := structuredMap(t, first)["approvalId"].(string)
	if _, err := server.ApprovalStore().Deny(approvalID, ResolveApprovalOptions{Actor: "admin", Reason: "fraud"}); err != nil {
		t.Fatal(err)
	}
	second := callTool(t, session, "billing.refund", map[string]any{"amount": 100}, nil)
	if code := gapErrorCode(t, second); code != CodeApprovalRequired {
		t.Fatalf("code = %s", code)
	}
	details, _ := gapError(t, second)["details"].(map[string]any)
	if details["status"] != "denied" {
		t.Fatalf("details = %#v", details)
	}
}

func TestServerApprovalToken(t *testing.T) {
	action := DefineAction(Action{
		Name:        "billing.charge",
		Description: "Charge a customer with a signed approval token.",
		Confirm:     true,
		InputSchema: objectSchema(map[string]any{
			"amount": property("number", "Amount to charge in cents."),
		}, []string{"amount"}),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"charged": true}, nil
		},
	})
	gate, err := NewHMACApprovalGate(HmacApprovalGateOptions{Secret: "approval-secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, httpServer := startTestServer(t, ServerOptions{
		Registry:  testRegistry(t, action),
		Approvals: gate,
	})
	session := connectSession(t, httpServer, nil)

	issued, err := gate.Issue(ApprovalRequest{
		Action:      "billing.charge",
		Args:        map[string]any{"amount": 500},
		PrincipalID: "anonymous",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := callTool(t, session, "billing.charge", map[string]any{"amount": 500}, map[string]any{
		"gap/approval": issued.Token,
	})
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	if structuredMap(t, result)["charged"] != true {
		t.Fatalf("payload = %#v", structuredMap(t, result))
	}

	bad := callTool(t, session, "billing.charge", map[string]any{"amount": 500}, map[string]any{
		"gap/approval": "v1.bad.bad",
	})
	if code := gapErrorCode(t, bad); code != CodeApprovalRequired {
		t.Fatalf("code = %s", code)
	}
	mismatched := callTool(t, session, "billing.charge", map[string]any{"amount": 900}, map[string]any{
		"gap/approval": issued.Token,
	})
	if code := gapErrorCode(t, mismatched); code != CodeApprovalRequired {
		t.Fatalf("code = %s", code)
	}
}

func TestServerIdempotency(t *testing.T) {
	var counter int32
	idempotent := echoAction("test.idempotent", &counter)
	idempotent.Idempotent = true
	_, httpServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, idempotent)})
	session := connectSession(t, httpServer, nil)

	first := callTool(t, session, "test.idempotent", map[string]any{"message": "once"}, nil)
	second := callTool(t, session, "test.idempotent", map[string]any{"message": "once"}, nil)
	if counter != 1 {
		t.Fatalf("counter = %d, want 1", counter)
	}
	if receiptID(t, first) != receiptID(t, second) {
		t.Fatal("idempotent replay changed the receipt id")
	}

	explicit := callTool(t, session, "test.idempotent", map[string]any{"message": "first"}, map[string]any{"idempotencyKey": "key-1"})
	replay := callTool(t, session, "test.idempotent", map[string]any{"message": "second"}, map[string]any{"idempotencyKey": "key-1"})
	if structuredMap(t, replay)["message"] != "first" {
		t.Fatalf("explicit replay = %#v", structuredMap(t, replay))
	}
	if receiptID(t, explicit) != receiptID(t, replay) {
		t.Fatal("explicit replay changed the receipt id")
	}
}

func TestServerRateLimit(t *testing.T) {
	_, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil)),
		RateLimit: RateLimitOptions{
			Limit:  1,
			Window: time.Hour,
		},
	})
	session := connectSession(t, httpServer, nil)
	first := callTool(t, session, "test.echo", map[string]any{"message": "one"}, nil)
	if first.IsError {
		t.Fatalf("unexpected error: %s", resultText(first))
	}
	second := callTool(t, session, "test.echo", map[string]any{"message": "two"}, nil)
	if code := gapErrorCode(t, second); code != CodeRateLimited {
		t.Fatalf("code = %s", code)
	}
	details, _ := gapError(t, second)["details"].(map[string]any)
	if details["retryAfterMs"] == nil {
		t.Fatalf("details = %#v", details)
	}
}

func TestServerReceiptsAndUndo(t *testing.T) {
	var undoCount int32
	action := DefineAction(Action{
		Name:        "widgets.create",
		Description: "Create a widget and support a best-effort inverse.",
		InputSchema: objectSchema(map[string]any{
			"name": property("string", "Widget name."),
		}, []string{"name"}),
		Execute: func(_ context.Context, input any, _ *Context) (any, error) {
			name := input.(map[string]any)["name"]
			return map[string]any{"id": "wdg_1", "name": name}, nil
		},
		Undo: func(_ context.Context, output any, input any, _ *Context) error {
			undoCount++
			return nil
		},
	})
	auth := apiKeyProvider(
		APIKeyRecord{Key: "owner", Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_owner"})},
		APIKeyRecord{Key: "other", Principal: TestPrincipal(TestPrincipalOptions{ID: "usr_other"})},
	)
	server, httpServer := startTestServer(t, ServerOptions{
		Registry: testRegistry(t, action),
		Auth:     auth,
	})
	owner := connectSession(t, httpServer, bearerHeaders("owner"))
	other := connectSession(t, httpServer, bearerHeaders("other"))

	created := callTool(t, owner, "widgets.create", map[string]any{"name": "gizmo"}, nil)
	id := receiptID(t, created)

	receipt := callTool(t, owner, "gap.receipts.get", map[string]any{"receiptId": id}, nil)
	payload := structuredMap(t, receipt)
	if payload["receipt"] == nil {
		t.Fatalf("payload = %#v", payload)
	}
	result := payload["result"].(map[string]any)
	if result["name"] != "gizmo" {
		t.Fatalf("result = %#v", result)
	}

	if hidden := callTool(t, other, "gap.receipts.get", map[string]any{"receiptId": id}, nil); gapErrorCode(t, hidden) != CodeNotFound {
		t.Fatal("another principal could read the receipt")
	}
	if hidden := callTool(t, other, "gap.undo", map[string]any{"receiptId": id}, nil); gapErrorCode(t, hidden) != CodeNotFound {
		t.Fatal("another principal could undo the call")
	}

	undone := callTool(t, owner, "gap.undo", map[string]any{"receiptId": id}, nil)
	if undone.IsError {
		t.Fatalf("unexpected error: %s", resultText(undone))
	}
	if structuredMap(t, undone)["undone"] != true {
		t.Fatalf("payload = %#v", structuredMap(t, undone))
	}
	if undoCount != 1 {
		t.Fatalf("undoCount = %d", undoCount)
	}
	if again := callTool(t, owner, "gap.undo", map[string]any{"receiptId": id}, nil); gapErrorCode(t, again) != CodeConflict {
		t.Fatal("undo was not idempotent")
	}
	stored, _ := server.Calls().Get(id)
	if stored == nil || stored.UndoneAt == nil || stored.UndoReceiptID == "" {
		t.Fatalf("stored = %#v", stored)
	}
	after := callTool(t, owner, "gap.receipts.get", map[string]any{"receiptId": id}, nil)
	if structuredMap(t, after)["undoneAt"] == nil {
		t.Fatalf("payload = %#v", structuredMap(t, after))
	}
}

func TestServerTasks(t *testing.T) {
	var runs int32
	taskAction := DefineAction(Action{
		Name:        "reports.generate",
		Description: "Generate a report in the background and return a task id.",
		Task:        true,
		InputSchema: objectSchema(map[string]any{
			"name": property("string", "Report name."),
		}, []string{"name"}),
		Execute: func(_ context.Context, input any, _ *Context) (any, error) {
			runs++
			return map[string]any{"report": input.(map[string]any)["name"]}, nil
		},
	})
	_, httpServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, taskAction)})
	session := connectSession(t, httpServer, nil)

	if names := listToolNames(t, session); !containsName(names, "gap.tasks.get") {
		t.Fatalf("tools = %v", names)
	}
	started := callTool(t, session, "reports.generate", map[string]any{"name": "weekly"}, nil)
	payload := structuredMap(t, started)
	if payload["status"] != "working" {
		t.Fatalf("payload = %#v", payload)
	}
	taskID, _ := payload["taskId"].(string)
	completed := waitForTask(t, session, taskID, TaskCompleted)
	result := completed["result"].(map[string]any)
	if result["report"] != "weekly" {
		t.Fatalf("result = %#v", result)
	}
	if completed["receipt"] == nil {
		t.Fatalf("task has no receipt: %#v", completed)
	}
	if runs != 1 {
		t.Fatalf("runs = %d", runs)
	}
}

func TestServerTaskCancellation(t *testing.T) {
	blocking := DefineAction(Action{
		Name:        "reports.slow",
		Description: "Run until cancelled so task cancellation can be tested.",
		Task:        true,
		InputSchema: objectSchema(nil, nil),
		Execute: func(ctx context.Context, _ any, _ *Context) (any, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	_, httpServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, blocking)})
	session := connectSession(t, httpServer, nil)

	started := callTool(t, session, "reports.slow", map[string]any{}, nil)
	taskID := structuredMap(t, started)["taskId"].(string)
	cancelled := callTool(t, session, "gap.tasks.cancel", map[string]any{"taskId": taskID}, nil)
	if cancelled.IsError {
		t.Fatalf("unexpected error: %s", resultText(cancelled))
	}
	if structuredMap(t, cancelled)["status"] != string(TaskCancelled) {
		t.Fatalf("payload = %#v", structuredMap(t, cancelled))
	}
	waitForTask(t, session, taskID, TaskCancelled)
}

func TestServerTasksDisabled(t *testing.T) {
	taskAction := DefineAction(Action{
		Name:        "reports.generate",
		Description: "Generate a report synchronously when tasks are disabled.",
		Task:        true,
		InputSchema: objectSchema(nil, nil),
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})
	_, httpServer := startTestServer(t, ServerOptions{
		Registry:    testRegistry(t, taskAction),
		EnableTasks: Ptr(false),
	})
	session := connectSession(t, httpServer, nil)
	if names := listToolNames(t, session); containsName(names, "gap.tasks.get") {
		t.Fatalf("task tools should be hidden: %v", names)
	}
	result := callTool(t, session, "reports.generate", map[string]any{}, nil)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	if structuredMap(t, result)["ok"] != true {
		t.Fatalf("payload = %#v", structuredMap(t, result))
	}
	if unavailable := callTool(t, session, "gap.tasks.get", map[string]any{"taskId": "x"}, nil); gapErrorCode(t, unavailable) != CodeNotFound {
		t.Fatal("gap.tasks.get should be unavailable")
	}
}

func TestServerSearch(t *testing.T) {
	actions := make([]*Action, 0, 13)
	for index := 0; index < 13; index++ {
		name := fmt.Sprintf("catalog.item%d", index)
		tags := []string{"reports"}
		if index%2 == 0 {
			tags = []string{"billing"}
		}
		actions = append(actions, DefineAction(Action{
			Name:        name,
			Description: fmt.Sprintf("Manage catalog item number %d with a useful description.", index),
			Tags:        tags,
			InputSchema: objectSchema(nil, nil),
			Execute:     func(context.Context, any, *Context) (any, error) { return map[string]any{"ok": true}, nil },
		}))
	}
	_, httpServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, actions...)})
	session := connectSession(t, httpServer, nil)
	if names := listToolNames(t, session); !containsName(names, "gap.search") {
		t.Fatalf("gap.search missing from %v", names)
	}

	found := callTool(t, session, "gap.search", map[string]any{"query": "item1"}, nil)
	payload := structuredMap(t, found)
	if payload["total"] != float64(4) {
		t.Fatalf("payload = %#v", payload)
	}
	tools := payload["tools"].([]any)
	for _, tool := range tools {
		name := tool.(map[string]any)["name"].(string)
		if !strings.Contains(name, "item1") {
			t.Fatalf("unexpected match %q", name)
		}
	}

	namespaced := callTool(t, session, "gap.search", map[string]any{"namespace": "catalog", "limit": 5}, nil)
	namespacedPayload := structuredMap(t, namespaced)
	if namespacedPayload["total"] != float64(13) || len(namespacedPayload["tools"].([]any)) != 5 {
		t.Fatalf("payload = %#v", namespacedPayload)
	}

	tagged := callTool(t, session, "gap.search", map[string]any{"tags": []any{"billing"}}, nil)
	if structuredMap(t, tagged)["total"] != float64(7) {
		t.Fatalf("payload = %#v", structuredMap(t, tagged))
	}

	_, disabledServer := startTestServer(t, ServerOptions{
		Registry:        testRegistry(t, actions...),
		SearchThreshold: -1,
	})
	disabledSession := connectSession(t, disabledServer, nil)
	if names := listToolNames(t, disabledSession); containsName(names, "gap.search") {
		t.Fatalf("gap.search should be disabled: %v", names)
	}
}

func TestServerHandoff(t *testing.T) {
	uiAction := DefineAction(Action{
		Name:        "invoices.create",
		Description: "Open the invoice creation form with prefilled arguments.",
		InputSchema: objectSchema(map[string]any{
			"customer": property("string", "Customer id."),
		}, []string{"customer"}),
		UI: &ActionUI{Route: "/invoices/new"},
		Execute: func(context.Context, any, *Context) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})
	_, httpServer := startTestServer(t, ServerOptions{
		Registry:      testRegistry(t, uiAction, echoAction("test.echo", nil)),
		HandoffSecret: "handoff-secret",
		BaseURL:       "https://app.example.com",
	})
	session := connectSession(t, httpServer, nil)
	if names := listToolNames(t, session); !containsName(names, "gap.handoff") {
		t.Fatalf("gap.handoff missing from %v", names)
	}

	result := callTool(t, session, "gap.handoff", map[string]any{
		"action": "invoices.create",
		"args":   map[string]any{"customer": "cus_1"},
	}, nil)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(result))
	}
	payload := structuredMap(t, result)
	rawURL, _ := payload["url"].(string)
	if !strings.HasPrefix(rawURL, "https://app.example.com/invoices/new?gap_state=") {
		t.Fatalf("url = %q", rawURL)
	}
	state, err := HandoffStateFromURL(rawURL, "handoff-secret", HandoffVerifyOptions{Action: "invoices.create"})
	if err != nil || state == nil {
		t.Fatalf("state = %#v, err = %v", state, err)
	}
	if state.PrincipalID != "anonymous" {
		t.Fatalf("principal = %q", state.PrincipalID)
	}

	invalid := callTool(t, session, "gap.handoff", map[string]any{
		"action": "invoices.create",
		"args":   map[string]any{},
	}, nil)
	if code := gapErrorCode(t, invalid); code != CodeInvalidInput {
		t.Fatalf("code = %s", code)
	}
	noUI := callTool(t, session, "gap.handoff", map[string]any{"action": "test.echo"}, nil)
	if code := gapErrorCode(t, noUI); code != CodeInvalidInput {
		t.Fatalf("code = %s", code)
	}

	_, noSecretServer := startTestServer(t, ServerOptions{Registry: testRegistry(t, uiAction)})
	noSecretSession := connectSession(t, noSecretServer, nil)
	if names := listToolNames(t, noSecretSession); containsName(names, "gap.handoff") {
		t.Fatalf("gap.handoff should be hidden without a secret: %v", names)
	}
}

func TestServerAuditSink(t *testing.T) {
	first := NewMemoryAuditLog()
	second := NewMemoryAuditLog()
	policy, err := NewGapPolicy(&PolicyDocument{
		Version: 1,
		Rules: []PolicyRule{{
			Tools: []string{"billing.*"},
			Deny:  true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	failing := DefineAction(Action{
		Name:        "test.fail",
		Description: "Fail deliberately so the audit error path is exercised.",
		InputSchema: objectSchema(nil, nil),
		Execute: func(context.Context, any, *Context) (any, error) {
			return nil, errors.New("boom")
		},
	})
	_, httpServer := startTestServer(t, ServerOptions{
		Registry:   testRegistry(t, echoAction("test.echo", nil), echoAction("billing.charge", nil), failing),
		Policy:     policy,
		AuditSinks: []AuditSink{first, second},
	})
	session := connectSession(t, httpServer, nil)

	callTool(t, session, "test.echo", map[string]any{"message": "super-secret"}, nil)
	callTool(t, session, "billing.charge", map[string]any{"message": "nope"}, nil)
	callTool(t, session, "test.fail", map[string]any{}, nil)

	for _, sink := range []*MemoryAuditLog{first, second} {
		events := sink.List()
		if len(events) != 3 {
			t.Fatalf("events = %d", len(events))
		}
		decisions := make(map[AuditDecision]bool)
		for _, event := range events {
			decisions[event.Decision] = true
			if event.ArgsHash == "" {
				t.Fatalf("missing args hash: %#v", event)
			}
			if event.TraceID == "" {
				t.Fatalf("missing trace id: %#v", event)
			}
			raw, _ := json.Marshal(event)
			if strings.Contains(string(raw), "super-secret") {
				t.Fatalf("audit leaked raw arguments: %s", raw)
			}
		}
		if !decisions[AuditAllowed] || !decisions[AuditDenied] || !decisions[AuditErrorDecision] {
			t.Fatalf("decisions = %#v", decisions)
		}
	}
}

func TestServerStdioInMemoryTransport(t *testing.T) {
	server, err := NewServer(ServerOptions{
		Registry: testRegistry(t, echoAction("test.echo", nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.serveTransport(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("no tools")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test.echo",
		Arguments: map[string]any{"message": "stdio"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if result.IsError {
		t.Fatalf("stdio call failed: %s", resultText(result))
	}
	if structuredMap(t, result)["message"] != "stdio" {
		t.Fatalf("payload = %#v", structuredMap(t, result))
	}

	_ = session.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveTransport did not return")
	}
}

func TestNewServerConfigurationErrors(t *testing.T) {
	if _, err := NewServer(ServerOptions{}); err == nil {
		t.Fatal("nil registry should fail")
	}

	reserved := DefineAction(Action{
		Name:        "gap.undo",
		Description: "This action tries to steal a reserved tool name.",
		Execute:     func(context.Context, any, *Context) (any, error) { return nil, nil },
	})
	if _, err := NewServer(ServerOptions{Registry: testRegistry(t, reserved)}); err == nil {
		t.Fatal("reserved name should fail")
	}

	if _, err := NewServer(ServerOptions{
		Registry: NewRegistry(),
		BaseURL:  "not a url",
	}); err == nil {
		t.Fatal("invalid base URL should fail")
	}

	if _, err := NewServer(ServerOptions{
		Registry:  NewRegistry(),
		RateLimit: RateLimitOptions{Limit: 1},
	}); err == nil {
		t.Fatal("invalid rate limit window should fail")
	}

	server, err := NewServer(ServerOptions{
		Registry: NewRegistry(),
		Name:     "custom-name",
		Version:  "9.9.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if server == nil {
		t.Fatal("server is nil")
	}
}

func TestServerListToolsDescriptors(t *testing.T) {
	undoable := DefineAction(Action{
		Name:        "widgets.create",
		Description: "Create a widget and expose a UI binding for handoff.",
		Scopes:      []string{"widgets:write"},
		InputSchema: objectSchema(nil, nil),
		UI:          &ActionUI{Route: "/widgets/new"},
		Undo:        func(context.Context, any, any, *Context) error { return nil },
		Execute:     func(context.Context, any, *Context) (any, error) { return nil, nil },
	})
	server, err := NewServer(ServerOptions{
		Registry:      testRegistry(t, undoable),
		HandoffSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptors := server.ListTools([]string{"*"})
	names := make(map[string]bool)
	for _, descriptor := range descriptors {
		names[descriptor.Name] = true
		if descriptor.Name == "widgets.create" && descriptor.Meta["gap/ui"] == nil {
			t.Fatal("UI metadata missing")
		}
	}
	for _, want := range []string{"widgets.create", "gap.receipts.get", "gap.tasks.get", "gap.tasks.cancel", "gap.undo", "gap.handoff"} {
		if !names[want] {
			t.Fatalf("missing %q in %#v", want, names)
		}
	}
	if hidden := server.ListTools([]string{"nothing"}); len(hidden) != 3 || hidden[0].Name != "gap.receipts.get" {
		t.Fatalf("hidden = %#v", hidden)
	}
}
