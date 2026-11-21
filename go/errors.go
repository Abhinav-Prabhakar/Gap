package gap

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Error codes used across the action boundary.
const (
	CodeUnauthenticated  = "UNAUTHENTICATED"
	CodeForbidden        = "FORBIDDEN"
	CodeInvalidInput     = "INVALID_INPUT"
	CodeNotFound         = "NOT_FOUND"
	CodeConflict         = "CONFLICT"
	CodeRateLimited      = "RATE_LIMITED"
	CodeApprovalRequired = "APPROVAL_REQUIRED"
	CodePolicyDenied     = "POLICY_DENIED"
	CodeTimeout          = "TIMEOUT"
	CodeUnavailable      = "UNAVAILABLE"
	CodeInternal         = "INTERNAL"
)

var defaultStatus = map[string]int{
	CodeUnauthenticated:  401,
	CodeForbidden:        403,
	CodeInvalidInput:     400,
	CodeNotFound:         404,
	CodeConflict:         409,
	CodeRateLimited:      429,
	CodeApprovalRequired: 428,
	CodePolicyDenied:     403,
	CodeTimeout:          504,
	CodeUnavailable:      503,
	CodeInternal:         500,
}

// Error is the single error type that crosses the action boundary. Everything
// an agent sees is derived from it, so messages stay safe and machine-readable.
type Error struct {
	Code      string
	Message   string
	Status    int
	Retryable bool
	Details   any
	Expose    bool

	cause error
}

// NewError builds an Error with defaults derived from the code.
func NewError(message string, code string) *Error {
	status, ok := defaultStatus[code]
	if !ok {
		status = 500
		code = CodeInternal
	}
	return &Error{
		Code:      code,
		Message:   message,
		Status:    status,
		Retryable: code == CodeRateLimited || code == CodeUnavailable,
		Expose:    true,
	}
}

// WrapError adds a cause without exposing it to clients.
func WrapError(err error, message string, code string) *Error {
	e := NewError(message, code)
	e.cause = err
	return e
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped application error, if any.
func (e *Error) Unwrap() error { return e.cause }

// WithDetails returns a copy carrying structured details.
func (e *Error) WithDetails(details any) *Error {
	out := *e
	out.Details = details
	return &out
}

// WithStatus overrides the HTTP status.
func (e *Error) WithStatus(status int) *Error {
	out := *e
	out.Status = status
	return &out
}

// PublicMessage is the message safe to send to a client.
func (e *Error) PublicMessage() string {
	if e == nil {
		return ""
	}
	if !e.Expose {
		return "Internal error."
	}
	return e.Message
}

// PublicDetails returns details only when they are safe to expose.
func (e *Error) PublicDetails() any {
	if e == nil || !e.Expose {
		return nil
	}
	return e.Details
}

// Payload returns the wire representation used inside gapError.
func (e *Error) Payload() map[string]any {
	if e == nil {
		e = Internal("Internal error.", nil)
	}
	payload := map[string]any{
		"name":      "GapError",
		"code":      e.Code,
		"message":   e.PublicMessage(),
		"status":    e.Status,
		"retryable": e.Retryable,
	}
	if details := e.PublicDetails(); details != nil {
		payload["details"] = details
	}
	return payload
}

// Is allows errors.Is to match on the code as well as the concrete type.
func (e *Error) Is(target error) bool {
	var other *Error
	if errors.As(target, &other) {
		return e.Code == other.Code
	}
	return false
}

// Errorf builds an Error with a formatted message.
func Errorf(code string, format string, args ...any) *Error {
	return NewError(fmt.Sprintf(format, args...), code)
}

// Unauthorized returns an UNAUTHENTICATED error.
func Unauthorized(message string) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Authentication required."
	}
	return NewError(message, CodeUnauthenticated)
}

// Forbidden returns a FORBIDDEN error.
func Forbidden(message string) *Error {
	if strings.TrimSpace(message) == "" {
		message = "You do not have permission to perform this action."
	}
	return NewError(message, CodeForbidden)
}

// InvalidInput returns an INVALID_INPUT error with optional details.
func InvalidInput(message string, details any) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Invalid input."
	}
	e := NewError(message, CodeInvalidInput)
	e.Details = details
	return e
}

// NotFound returns a NOT_FOUND error.
func NotFound(message string) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Not found."
	}
	return NewError(message, CodeNotFound)
}

// Conflict returns a CONFLICT error with optional details.
func Conflict(message string, details any) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Conflict."
	}
	e := NewError(message, CodeConflict)
	e.Details = details
	return e
}

// RateLimited returns a RATE_LIMITED error. retryAfter is in milliseconds.
func RateLimited(message string, retryAfterMS int64) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Rate limit exceeded."
	}
	e := NewError(message, CodeRateLimited)
	if retryAfterMS > 0 {
		e.Details = map[string]any{"retryAfterMs": retryAfterMS}
	}
	return e
}

// ApprovalRequiredError returns an APPROVAL_REQUIRED error.
func ApprovalRequiredError(message string, details any) *Error {
	if strings.TrimSpace(message) == "" {
		message = "This action requires human approval."
	}
	e := NewError(message, CodeApprovalRequired)
	e.Details = details
	return e
}

// PolicyDenied returns a POLICY_DENIED error.
func PolicyDenied(message string, details any) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Blocked by policy."
	}
	e := NewError(message, CodePolicyDenied)
	e.Details = details
	return e
}

// TimeoutError returns a TIMEOUT error.
func TimeoutError(message string) *Error {
	if strings.TrimSpace(message) == "" {
		message = "The action timed out."
	}
	return NewError(message, CodeTimeout)
}

// UnavailableError returns an UNAVAILABLE error.
func UnavailableError(message string) *Error {
	if strings.TrimSpace(message) == "" {
		message = "The action is temporarily unavailable."
	}
	return NewError(message, CodeUnavailable)
}

// Internal returns an INTERNAL error. The cause is retained for logs but is
// never exposed to clients.
func Internal(message string, cause error) *Error {
	if strings.TrimSpace(message) == "" {
		message = "Internal error."
	}
	e := NewError(message, CodeInternal)
	e.Expose = false
	e.cause = cause
	return e
}

// Normalize turns anything thrown by application code into an Error. Unknown
// errors are deliberately opaque to clients; the raw error is kept as cause
// for server logs.
func Normalize(err error) *Error {
	if err == nil {
		return nil
	}
	var gapErr *Error
	if errors.As(err, &gapErr) {
		return gapErr
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return TimeoutError("The action was aborted or timed out.")
	}
	return Internal("Internal error.", err)
}

// AsError returns the *Error in err, if any.
func AsError(err error) (*Error, bool) {
	var gapErr *Error
	if errors.As(err, &gapErr) {
		return gapErr, true
	}
	return nil, false
}

// IsCode reports whether err is a Gap error with the given code.
func IsCode(err error, code string) bool {
	gapErr, ok := AsError(err)
	return ok && gapErr.Code == code
}

// StatusFor returns the HTTP status for an error.
func StatusFor(err error) int {
	if gapErr, ok := AsError(err); ok {
		return gapErr.Status
	}
	return 500
}
