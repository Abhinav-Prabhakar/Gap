// Package gap is a typed action layer for agents. An action is defined once
// and served as an MCP tool through one authentication, policy, approval,
// audit and receipt pipeline.
package gap

import (
	"context"
	"net/http"
	"time"
)

// Version is the Go package version.
const Version = "0.1.0"

// RiskLevel describes the blast radius of an action.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// Valid reports whether the risk level is one of the four known values.
func (r RiskLevel) Valid() bool {
	switch r {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return true
	default:
		return false
	}
}

// PrincipalType identifies what kind of caller a Principal represents.
type PrincipalType string

const (
	PrincipalUser      PrincipalType = "user"
	PrincipalService   PrincipalType = "service"
	PrincipalAnonymous PrincipalType = "anonymous"
)

// Principal is the identity an action runs as. Gap never uses ambient service
// credentials: every invocation carries the principal it is executed for.
type Principal struct {
	ID       string         `json:"id"`
	Type     PrincipalType  `json:"type,omitempty"`
	TenantID string         `json:"tenantId,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	Email    string         `json:"email,omitempty"`
	Name     string         `json:"name,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Clone returns a deep-enough copy of the principal. Slices and metadata maps
// are copied so callers cannot mutate shared identity state.
func (p Principal) Clone() Principal {
	out := p
	out.Scopes = append([]string(nil), p.Scopes...)
	if p.Metadata != nil {
		out.Metadata = make(map[string]any, len(p.Metadata))
		for k, v := range p.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

// AuthResult is the outcome of authenticating a request.
type AuthResult struct {
	Principal Principal      `json:"principal"`
	Token     string         `json:"-"` // never serialized or logged
	ClientID  string         `json:"clientId,omitempty"`
	Scopes    []string       `json:"scopes,omitempty"`
	ExpiresAt int64          `json:"expiresAt,omitempty"` // Unix milliseconds
	Extra     map[string]any `json:"extra,omitempty"`
}

// ApprovalGrant is a signed grant proving a human approved one specific
// action invocation.
type ApprovalGrant struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	ArgsHash   string `json:"argsHash"`
	ApprovedBy string `json:"approvedBy"`
	IssuedAt   int64  `json:"issuedAt"`  // Unix milliseconds
	ExpiresAt  int64  `json:"expiresAt"` // Unix milliseconds
	Scope      string `json:"scope,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

// Expired reports whether the grant is past its expiry at now.
func (g ApprovalGrant) Expired(now time.Time) bool {
	return now.UnixMilli() >= g.ExpiresAt
}

// ApprovalRequest asks a gate to issue or verify a grant for one invocation.
type ApprovalRequest struct {
	Action      string
	Args        any
	PrincipalID string
	ApprovedBy  string
	// TTL bounds the grant lifetime. Zero uses the gate default.
	TTL time.Duration
}

// IssuedApproval is a signed approval token and its parsed grant.
type IssuedApproval struct {
	Token string        `json:"token"`
	Grant ApprovalGrant `json:"grant"`
}

// ApprovalGate issues and verifies approval tokens. Implementations must bind
// the token to the action, principal and a hash of the exact arguments.
type ApprovalGate interface {
	Issue(ApprovalRequest) (IssuedApproval, error)
	Verify(token string, request ApprovalRequest) (*ApprovalGrant, error)
}

// Context is the delegated execution context passed to every action.
type Context struct {
	Principal      Principal
	Scopes         []string
	TenantID       string
	DryRun         bool
	IdempotencyKey string
	Approval       *ApprovalGrant
	TraceID        string
	Logger         Logger
	// Request is the transport request that reached the adapter, when any.
	Request *http.Request
	// Services is application-provided state passed through untouched.
	Services map[string]any
	// ToolName is the MCP tool being invoked (including gap.* meta tools).
	ToolName string
}

// Logger is the small logging surface actions receive. Implementations must
// never log tokens, secrets or raw personal data.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// NopLogger discards every message. It is the default when no logger is set.
var NopLogger Logger = nopLogger{}

// AuditDecision is the terminal outcome recorded for a call.
type AuditDecision string

const (
	AuditAllowed          AuditDecision = "allowed"
	AuditDenied           AuditDecision = "denied"
	AuditErrorDecision    AuditDecision = "error"
	AuditApprovalRequired AuditDecision = "approval_required"
	AuditDryRun           AuditDecision = "dry_run"
)

// AuditError is the safe error summary stored on an audit event.
type AuditError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AuditEvent is one append-only record of an invocation decision. It contains
// hashes rather than raw arguments or results.
type AuditEvent struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Action      string         `json:"action"`
	PrincipalID string         `json:"principalId"`
	TenantID    string         `json:"tenantId,omitempty"`
	Decision    AuditDecision  `json:"decision"`
	ArgsHash    string         `json:"argsHash,omitempty"`
	ResultHash  string         `json:"resultHash,omitempty"`
	DurationMS  int64          `json:"durationMs,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	ApprovalID  string         `json:"approvalId,omitempty"`
	TraceID     string         `json:"traceId,omitempty"`
	Error       *AuditError    `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// AuditSink receives audit events. Implementations should be append-only and
// must not fail the originating call.
type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

// PolicyInput is the data a policy engine evaluates.
type PolicyInput struct {
	Action  *Action
	Args    any
	Context *Context
}

// PolicyDecision is the result of policy evaluation. Normal denials are
// returned as decisions rather than errors so they reach the audit trail.
type PolicyDecision struct {
	Decision    string         `json:"decision"` // allow, deny or confirm
	Reason      string         `json:"reason,omitempty"`
	Code        string         `json:"code,omitempty"`
	RedactPaths []string       `json:"redactPaths,omitempty"`
	Limits      map[string]any `json:"limits,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// PolicyEngine evaluates policy before input validation and execution.
type PolicyEngine interface {
	Evaluate(PolicyInput) PolicyDecision
}

// ActionExample is an example invocation surfaced in documentation. Examples
// must never contain secrets.
type ActionExample struct {
	Input       any    `json:"input"`
	Description string `json:"description,omitempty"`
}

// ActionAnnotations are MCP tool behavior hints.
type ActionAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// ActionUI describes a semantic DOM binding for human or browser fallback.
type ActionUI struct {
	Route   string            `json:"route,omitempty"`
	Action  string            `json:"action,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Submit  string            `json:"submit,omitempty"`
	Result  string            `json:"result,omitempty"`
	WaitFor string            `json:"waitFor,omitempty"`
}

// ToolDescriptor is the MCP-facing projection of an action.
type ToolDescriptor struct {
	Name         string             `json:"name"`
	Title        string             `json:"title,omitempty"`
	Description  string             `json:"description"`
	InputSchema  map[string]any     `json:"inputSchema"`
	OutputSchema map[string]any     `json:"outputSchema,omitempty"`
	Annotations  *ActionAnnotations `json:"annotations,omitempty"`
	Meta         map[string]any     `json:"_meta,omitempty"`
}

// RegistryIssue is one contract-check finding from Registry.Validate.
type RegistryIssue struct {
	Level   string `json:"level"` // error or warn
	Code    string `json:"code"`
	Action  string `json:"action,omitempty"`
	Message string `json:"message"`
}

// ActionFilter narrows registry listings.
type ActionFilter struct {
	Names     []string
	Namespace string
	Tags      []string
	Scopes    []string
	Include   func(*Action) bool
}

// ToolDescriptorOptions controls descriptor visibility.
type ToolDescriptorOptions struct {
	Scopes []string
	Filter *ActionFilter
}

// ValidationIssue is one JSON Schema validation problem.
type ValidationIssue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// ValidationResult is the outcome of schema validation. Data is the decoded
// value on success.
type ValidationResult struct {
	Success bool
	Data    any
	Issues  []ValidationIssue
}
