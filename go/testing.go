package gap

import (
	"context"
	"net/http"
)

// TestPrincipalOptions overrides the defaults used by TestPrincipal.
type TestPrincipalOptions struct {
	ID       string
	Type     PrincipalType
	TenantID string
	Scopes   []string
	Email    string
	Name     string
	Metadata map[string]any
}

// TestPrincipal returns a principal suitable for unit tests. It grants every
// scope by default.
func TestPrincipal(options ...TestPrincipalOptions) Principal {
	principal := Principal{
		ID:     "usr_test",
		Type:   PrincipalUser,
		Name:   "Test User",
		Email:  "test@example.com",
		Scopes: []string{"*"},
	}
	if len(options) == 0 {
		return principal
	}
	overrides := options[0]
	if overrides.ID != "" {
		principal.ID = overrides.ID
	}
	if overrides.Type != "" {
		principal.Type = overrides.Type
	}
	if overrides.TenantID != "" {
		principal.TenantID = overrides.TenantID
	}
	if overrides.Scopes != nil {
		principal.Scopes = append([]string(nil), overrides.Scopes...)
	}
	if overrides.Email != "" {
		principal.Email = overrides.Email
	}
	if overrides.Name != "" {
		principal.Name = overrides.Name
	}
	if overrides.Metadata != nil {
		principal.Metadata = make(map[string]any, len(overrides.Metadata))
		for key, value := range overrides.Metadata {
			principal.Metadata[key] = value
		}
	}
	return principal
}

// TestContextOptions overrides the defaults used by TestContext.
type TestContextOptions struct {
	Principal      *Principal
	Scopes         []string
	TenantID       string
	DryRun         bool
	IdempotencyKey string
	Approval       *ApprovalGrant
	TraceID        string
	Logger         Logger
	Request        *http.Request
	Services       map[string]any
	ToolName       string
}

// TestContext returns a fully formed action context for direct action tests.
func TestContext(options ...TestContextOptions) *Context {
	overrides := TestContextOptions{}
	if len(options) > 0 {
		overrides = options[0]
	}
	principal := TestPrincipal()
	if overrides.Principal != nil {
		principal = overrides.Principal.Clone()
	}
	scopes := overrides.Scopes
	if scopes == nil {
		scopes = append([]string(nil), principal.Scopes...)
	}
	tenantID := overrides.TenantID
	if tenantID == "" {
		tenantID = principal.TenantID
	}
	traceID := overrides.TraceID
	if traceID == "" {
		traceID = CreateID("trace")
	}
	logger := overrides.Logger
	if logger == nil {
		logger = NopLogger
	}
	return &Context{
		Principal:      principal,
		Scopes:         scopes,
		TenantID:       tenantID,
		DryRun:         overrides.DryRun,
		IdempotencyKey: overrides.IdempotencyKey,
		Approval:       overrides.Approval,
		TraceID:        traceID,
		Logger:         logger,
		Request:        overrides.Request,
		Services:       overrides.Services,
		ToolName:       overrides.ToolName,
	}
}

// CallAction validates and executes an action directly, without the MCP layer.
// It is the Go equivalent of the testing package's callAction and is useful for
// unit-testing action bodies.
func CallAction(action *Action, input any, options ...TestContextOptions) (any, error) {
	return CallActionContext(context.Background(), action, input, options...)
}

// CallActionContext is CallAction with an explicit context.
func CallActionContext(ctx context.Context, action *Action, input any, options ...TestContextOptions) (any, error) {
	if action == nil {
		return nil, Internal("Cannot call a nil action.", nil)
	}
	if action.Execute == nil {
		return nil, Internal("The action has no execute function.", nil)
	}
	validated, issues := ValidateValue(action.InputSchema, input)
	if len(issues) > 0 {
		return nil, InvalidInput("Invalid input.", map[string]any{"issues": issues})
	}
	actx := TestContext(options...)
	if actx.ToolName == "" {
		actx.ToolName = action.Name
	}
	output, err := action.Execute(ctx, validated, actx)
	if err != nil {
		return nil, err
	}
	if action.OutputSchema != nil {
		value, err := ToJSONValue(output)
		if err != nil {
			return nil, WrapError(err, "The action returned a non-JSON result.", CodeInternal)
		}
		validatedOutput, issues := ValidateValue(action.OutputSchema, value)
		if len(issues) > 0 {
			return nil, Internal("The action returned a result that does not match its output schema.", nil).
				WithDetails(map[string]any{"issues": issues})
		}
		return validatedOutput, nil
	}
	return output, nil
}

// NewTestRegistry builds a registry and panics on invalid actions, which keeps
// test setup to one line.
func NewTestRegistry(actions ...*Action) *Registry { return NewRegistry(actions...) }
