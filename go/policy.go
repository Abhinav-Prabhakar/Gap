package gap

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// DefaultAmountPaths are the recursive key names inspected by maxAmount when a
// rule does not set amountPaths.
var DefaultAmountPaths = []string{"amount", "total", "value", "price", "cost"}

// PolicyRule is one declarative rule. Omitted tool patterns apply to every tool;
// an explicitly empty list matches no tools. Scope wildcards follow HasScopes.
type PolicyRule struct {
	// Tools are exact names or namespace globs such as "invoices.*" or "*".
	Tools []string `json:"tools,omitempty"`
	// Scopes are required for this rule to apply; all must be held.
	Scopes []string `json:"scopes,omitempty"`
	// Deny hard-denies every matching invocation.
	Deny bool `json:"deny,omitempty"`
	// Confirm requires human approval.
	Confirm bool `json:"confirm,omitempty"`
	// DryRun sets Context.DryRun for matching invocations.
	DryRun bool `json:"dryRun,omitempty"`
	// MaxAmount denies when a numeric amount exceeds it.
	MaxAmount *float64 `json:"maxAmount,omitempty"`
	// AmountPaths selects amount paths. Nil uses DefaultAmountPaths; an empty
	// non-nil slice disables amount checks.
	AmountPaths []string `json:"amountPaths,omitempty"`
	// MaxArrayLength denies when an array is longer than it.
	MaxArrayLength *int `json:"maxArrayLength,omitempty"`
	// ArrayPaths selects array paths. Nil checks every array; an empty non-nil
	// slice disables array checks.
	ArrayPaths []string `json:"arrayPaths,omitempty"`
	// Redact lists dot/bracket paths removed from arguments and results.
	Redact []string `json:"redact,omitempty"`
	// Reason explains a deny or confirm decision.
	Reason string `json:"reason,omitempty"`
}

// PolicyDocument is a complete, versioned policy.
type PolicyDocument struct {
	// Version must be 1.
	Version int `json:"version"`
	// Default is "allow" (the default) or "deny".
	Default string `json:"default,omitempty"`
	// Rules are ordered. The first matching deny wins.
	Rules []PolicyRule `json:"rules"`
	// Redact lists paths always redacted when not denied.
	Redact []string `json:"redact,omitempty"`
	// Confirm lists tool globs that always require approval.
	Confirm []string `json:"confirm,omitempty"`
	// Deny lists tool globs that are always denied.
	Deny []string `json:"deny,omitempty"`
}

// DefinePolicy validates a document and returns a normalized copy. It is the
// Go equivalent of definePolicy: mistakes fail at definition time.
func DefinePolicy(document PolicyDocument) (*PolicyDocument, error) {
	return normalizePolicy(&document)
}

// ParsePolicy parses and validates a JSON policy document.
func ParsePolicy(data []byte) (*PolicyDocument, error) {
	var document PolicyDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, invalidPolicy("Policy must be valid JSON.", []ValidationIssue{{
			Path:    "(root)",
			Message: "Invalid JSON: " + err.Error(),
			Code:    "invalid_json",
		}})
	}
	return normalizePolicy(&document)
}

// ParsePolicyString parses policy text.
func ParsePolicyString(text string) (*PolicyDocument, error) { return ParsePolicy([]byte(text)) }

// LoadPolicy accepts a JSON string, []byte, PolicyDocument or *PolicyDocument.
// It is a convenience for configuration loaders.
func LoadPolicy(input any) (*PolicyDocument, error) {
	switch value := input.(type) {
	case string:
		return ParsePolicyString(value)
	case []byte:
		return ParsePolicy(value)
	case PolicyDocument:
		return DefinePolicy(value)
	case *PolicyDocument:
		if value == nil {
			return nil, invalidPolicy("Invalid policy document.", nil)
		}
		return DefinePolicy(*value)
	default:
		return nil, invalidPolicy("Policy must be JSON text or a document.", []ValidationIssue{{
			Path:    "(root)",
			Message: "Unsupported policy input type.",
			Code:    "invalid_type",
		}})
	}
}

func invalidPolicy(message string, issues []ValidationIssue) *Error {
	return InvalidInput(message, map[string]any{"issues": issues})
}

func normalizePolicy(document *PolicyDocument) (*PolicyDocument, error) {
	if document == nil {
		return nil, invalidPolicy("Invalid policy document.", []ValidationIssue{{Path: "(root)", Message: "Policy must be an object.", Code: "invalid_type"}})
	}
	var issues []ValidationIssue
	issue := func(path, message, code string) {
		issues = append(issues, ValidationIssue{Path: path, Message: message, Code: code})
	}
	if document.Version != 1 {
		if document.Version == 0 {
			issue("version", "Policy version is required; expected 1.", "required")
		} else {
			issue("version", fmt.Sprintf("Unsupported policy version %d; expected 1.", document.Version), "invalid_value")
		}
	}
	if document.Default != "" && document.Default != "allow" && document.Default != "deny" {
		issue("default", `Expected "allow" or "deny".`, "invalid_value")
	}
	validateStringArray(document.Redact, "redact", issue)
	validateStringArray(document.Confirm, "confirm", issue)
	validateStringArray(document.Deny, "deny", issue)
	if document.Rules == nil {
		issue("rules", "Policy rules are required.", "required")
	}
	for index, rule := range document.Rules {
		path := fmt.Sprintf("rules[%d]", index)
		validateStringArray(rule.Tools, path+".tools", issue)
		validateStringArray(rule.Scopes, path+".scopes", issue)
		validateStringArray(rule.AmountPaths, path+".amountPaths", issue)
		validateStringArray(rule.ArrayPaths, path+".arrayPaths", issue)
		validateStringArray(rule.Redact, path+".redact", issue)
		if rule.MaxAmount != nil && (math.IsNaN(*rule.MaxAmount) || math.IsInf(*rule.MaxAmount, 0) || *rule.MaxAmount < 0) {
			issue(path+".maxAmount", "Expected a finite, non-negative number.", "invalid_value")
		}
		if rule.MaxArrayLength != nil && *rule.MaxArrayLength < 0 {
			issue(path+".maxArrayLength", "Expected a non-negative integer.", "invalid_value")
		}
	}
	if len(issues) > 0 {
		return nil, invalidPolicy("Invalid policy document.", issues)
	}

	out := &PolicyDocument{
		Version: 1,
		Default: document.Default,
		Rules:   make([]PolicyRule, len(document.Rules)),
	}
	for index, rule := range document.Rules {
		out.Rules[index] = clonePolicyRule(rule)
	}
	out.Redact = cloneStrings(document.Redact)
	out.Confirm = cloneStrings(document.Confirm)
	out.Deny = cloneStrings(document.Deny)
	return out, nil
}

func validateStringArray(values []string, path string, issue func(string, string, string)) {
	for index, value := range values {
		if strings.TrimSpace(value) == "" {
			issue(fmt.Sprintf("%s[%d]", path, index), "Expected a non-empty string.", "invalid_value")
		}
	}
}

func clonePolicyRule(rule PolicyRule) PolicyRule {
	out := rule
	out.Tools = cloneStrings(rule.Tools)
	out.Scopes = cloneStrings(rule.Scopes)
	out.Redact = cloneStrings(rule.Redact)
	if rule.AmountPaths != nil {
		out.AmountPaths = cloneStrings(rule.AmountPaths)
	}
	if rule.ArrayPaths != nil {
		out.ArrayPaths = cloneStrings(rule.ArrayPaths)
	}
	if rule.MaxAmount != nil {
		value := *rule.MaxAmount
		out.MaxAmount = &value
	}
	if rule.MaxArrayLength != nil {
		value := *rule.MaxArrayLength
		out.MaxArrayLength = &value
	}
	return out
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

// GapPolicy is a declarative PolicyEngine. Its document is immutable after
// construction, so it is safe for concurrent use.
type GapPolicy struct {
	document PolicyDocument
}

// NewGapPolicy creates a policy engine from a validated document.
func NewGapPolicy(document *PolicyDocument) (*GapPolicy, error) {
	normalized, err := normalizePolicy(document)
	if err != nil {
		return nil, err
	}
	return &GapPolicy{document: *normalized}, nil
}

// NewGapPolicyJSON creates a policy engine from JSON text.
func NewGapPolicyJSON(text string) (*GapPolicy, error) {
	document, err := ParsePolicyString(text)
	if err != nil {
		return nil, err
	}
	return &GapPolicy{document: *document}, nil
}

// Document returns a defensive copy of the policy document.
func (p *GapPolicy) Document() PolicyDocument {
	if p == nil {
		return PolicyDocument{}
	}
	return *p.document.Clone()
}

// Clone returns a deep copy.
func (d PolicyDocument) Clone() *PolicyDocument {
	out := d
	out.Rules = make([]PolicyRule, len(d.Rules))
	for index, rule := range d.Rules {
		out.Rules[index] = clonePolicyRule(rule)
	}
	out.Redact = cloneStrings(d.Redact)
	out.Confirm = cloneStrings(d.Confirm)
	out.Deny = cloneStrings(d.Deny)
	return &out
}

// Evaluate implements PolicyEngine.
func (p *GapPolicy) Evaluate(input PolicyInput) PolicyDecision {
	if p == nil || input.Action == nil {
		return PolicyDecision{Decision: "deny", Reason: "Policy evaluation failed.", Code: "POLICY_DENIED"}
	}
	action := input.Action
	scopes := []string(nil)
	if input.Context != nil {
		scopes = input.Context.Scopes
		if scopes == nil {
			scopes = input.Context.Principal.Scopes
		}
	}

	matching := make([]PolicyRule, 0)
	for _, rule := range p.document.Rules {
		if ruleMatches(rule, action.Name, scopes) {
			matching = append(matching, rule)
		}
	}

	if matchesAnyTool(p.document.Deny, action.Name) {
		return PolicyDecision{Decision: "deny", Reason: "Denied by the policy document.", Code: "POLICY_DENIED"}
	}

	var confirmReason string
	confirmMatched := false
	for _, rule := range matching {
		if rule.Deny {
			reason := rule.Reason
			if reason == "" {
				reason = "Denied by policy."
			}
			return PolicyDecision{Decision: "deny", Reason: reason, Code: "POLICY_DENIED"}
		}
		if rule.MaxAmount != nil {
			if violation := findAmountViolation(input.Args, rule.AmountPaths, *rule.MaxAmount); violation != nil {
				reason := rule.Reason
				if reason == "" {
					reason = fmt.Sprintf("Amount %v at %q exceeds the max amount of %v.", violation.Value, violation.Path, *rule.MaxAmount)
				}
				return limitDeny(reason, *rule.MaxAmount, violation)
			}
		}
		if rule.MaxArrayLength != nil {
			if violation := findArrayViolation(input.Args, rule.ArrayPaths, *rule.MaxArrayLength); violation != nil {
				reason := rule.Reason
				if reason == "" {
					reason = fmt.Sprintf("Array at %q has %v items, exceeding the max length of %d.", violation.Path, violation.Value, *rule.MaxArrayLength)
				}
				return limitDeny(reason, *rule.MaxArrayLength, violation)
			}
		}
		if rule.Confirm && !confirmMatched {
			confirmMatched = true
			confirmReason = rule.Reason
		}
	}

	documentConfirm := matchesAnyTool(p.document.Confirm, action.Name)
	redactPaths := mergePathLists(p.document.Redact)
	for _, rule := range matching {
		redactPaths = mergePathLists(redactPaths, rule.Redact)
	}
	dryRun := false
	for _, rule := range matching {
		if rule.DryRun {
			dryRun = true
			break
		}
	}

	allowRule := (*PolicyRule)(nil)
	for index := range matching {
		if !matching[index].Deny && !matching[index].Confirm {
			allowRule = &matching[index]
			break
		}
	}

	if confirmMatched || documentConfirm {
		if input.Context != nil {
			input.Context.DryRun = dryRun
		}
		if confirmReason == "" {
			confirmReason = "Confirmation required by the policy document."
		}
		return PolicyDecision{
			Decision:    "confirm",
			Reason:      confirmReason,
			RedactPaths: redactPaths,
			Metadata:    dryRunMetadata(dryRun),
		}
	}

	if p.document.Default == "deny" && allowRule == nil {
		return PolicyDecision{Decision: "deny", Reason: "Denied by default policy.", Code: "POLICY_DENIED"}
	}
	if input.Context != nil {
		input.Context.DryRun = dryRun
	}
	decision := PolicyDecision{Decision: "allow", RedactPaths: redactPaths, Metadata: dryRunMetadata(dryRun)}
	if allowRule != nil {
		decision.Reason = allowRule.Reason
	}
	return decision
}

func dryRunMetadata(dryRun bool) map[string]any {
	if !dryRun {
		return nil
	}
	return map[string]any{"dryRun": true}
}

func limitDeny(reason string, limit any, violation *LimitViolation) PolicyDecision {
	return PolicyDecision{
		Decision: "deny",
		Reason:   reason,
		Code:     "LIMIT_EXCEEDED",
		Metadata: map[string]any{"limit": limit, "path": violation.Path, "value": violation.Value},
	}
}

func mergePathLists(groups ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, group := range groups {
		for _, path := range group {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

func ruleMatches(rule PolicyRule, actionName string, scopes []string) bool {
	if !HasScopes(scopes, rule.Scopes) {
		return false
	}
	if rule.Tools == nil {
		return true
	}
	return matchesAnyTool(rule.Tools, actionName)
}

func matchesAnyTool(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if matchesTool(pattern, name) {
			return true
		}
	}
	return false
}

func matchesTool(pattern, name string) bool {
	if pattern == "*" || pattern == name {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// LimitViolation identifies the path and offending value of a policy limit.
type LimitViolation struct {
	Path  string
	Value any
}

func findAmountViolation(value any, configured []string, maxAmount float64) *LimitViolation {
	paths := configured
	if paths == nil {
		paths = DefaultAmountPaths
	}
	simple := make(map[string]struct{})
	var complex []string
	for _, path := range paths {
		if isSimplePath(path) {
			simple[path] = struct{}{}
		} else {
			complex = append(complex, path)
		}
	}

	if len(simple) > 0 {
		var visit func(node any, path string) *LimitViolation
		visit = func(node any, path string) *LimitViolation {
			switch typed := node.(type) {
			case []any:
				for index, item := range typed {
					childPath := fmt.Sprintf("%s[%d]", path, index)
					if violation := visit(item, childPath); violation != nil {
						return violation
					}
				}
			case map[string]any:
				keys := make([]string, 0, len(typed))
				for key := range typed {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					child := typed[key]
					childPath := key
					if path != "" {
						childPath = path + "." + key
					}
					if _, ok := simple[key]; ok {
						if number, ok := numericValue(child); ok && number > maxAmount {
							return &LimitViolation{Path: childPath, Value: child}
						}
					}
					if violation := visit(child, childPath); violation != nil {
						return violation
					}
				}
			}
			return nil
		}
		if violation := visit(value, ""); violation != nil {
			return violation
		}
	}

	for _, path := range complex {
		for _, candidate := range resolvePathValues(value, path) {
			if number, ok := numericValue(candidate); ok && number > maxAmount {
				return &LimitViolation{Path: path, Value: candidate}
			}
		}
	}
	return nil
}

func findArrayViolation(value any, configured []string, maxLength int) *LimitViolation {
	if configured != nil {
		for _, path := range configured {
			for _, candidate := range resolvePathValues(value, path) {
				if array, ok := candidate.([]any); ok && len(array) > maxLength {
					return &LimitViolation{Path: path, Value: len(array)}
				}
			}
		}
		return nil
	}

	var visit func(node any, path string) *LimitViolation
	visit = func(node any, path string) *LimitViolation {
		switch typed := node.(type) {
		case []any:
			if len(typed) > maxLength {
				if path == "" {
					path = "(root)"
				}
				return &LimitViolation{Path: path, Value: len(typed)}
			}
			for index, item := range typed {
				if violation := visit(item, fmt.Sprintf("%s[%d]", path, index)); violation != nil {
					return violation
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				if violation := visit(typed[key], childPath); violation != nil {
					return violation
				}
			}
		}
		return nil
	}
	return visit(value, "")
}

func isSimplePath(path string) bool {
	return !strings.ContainsAny(path, ".[")
}

func pathSegments(path string) []string {
	var out []string
	current := strings.Builder{}
	flush := func() {
		part := strings.TrimSpace(current.String())
		if part != "" {
			out = append(out, part)
		}
		current.Reset()
	}
	for index := 0; index < len(path); index++ {
		switch path[index] {
		case '.':
			flush()
		case '[':
			flush()
			end := strings.IndexByte(path[index:], ']')
			if end < 0 {
				current.WriteString(path[index:])
				index = len(path)
				continue
			}
			inner := path[index+1 : index+end]
			if inner == "" || inner == "*" {
				out = append(out, "*")
			} else {
				out = append(out, inner)
			}
			index += end
		default:
			current.WriteByte(path[index])
		}
	}
	flush()
	return out
}

func resolvePathValues(value any, path string) []any {
	current := []any{value}
	for _, segment := range pathSegments(path) {
		var next []any
		for _, node := range current {
			switch typed := node.(type) {
			case []any:
				if segment == "*" {
					next = append(next, typed...)
					continue
				}
				index, err := strconv.Atoi(segment)
				if err == nil && index >= 0 && index < len(typed) {
					next = append(next, typed[index])
				}
			case map[string]any:
				if segment == "*" {
					keys := make([]string, 0, len(typed))
					for key := range typed {
						keys = append(keys, key)
					}
					sort.Strings(keys)
					for _, key := range keys {
						next = append(next, typed[key])
					}
					continue
				}
				if child, ok := typed[segment]; ok {
					next = append(next, child)
				}
			}
		}
		current = next
	}
	return current
}

func numericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case float32:
		number := float64(typed)
		return number, !math.IsNaN(number) && !math.IsInf(number, 0)
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}
