package gap

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

var scopePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9:_-]*$`)
var destructiveVerbPattern = regexp.MustCompile(`(^|[.:_-])(delete|remove|destroy|refund|charge|transfer|send|cancel|revoke|drop|purge)([.:_-]|$)`)

// Registry is a concurrency-safe set of actions. Visibility is scope-aware,
// which is what prevents an agent from even discovering tools it cannot call.
type Registry struct {
	mu      sync.RWMutex
	actions map[string]*Action
}

// NewRegistry constructs a registry and adds the supplied actions. It panics
// when an action is invalid, mirroring must-style constructors; use Add when
// actions come from an untrusted source.
func NewRegistry(actions ...*Action) *Registry {
	registry := &Registry{actions: make(map[string]*Action, len(actions))}
	if err := registry.Add(actions...); err != nil {
		panic(err)
	}
	return registry
}

// Add registers actions. Names are normalized before validation. Any invalid
// action rolls the whole call back so a partial catalog cannot leak out.
func (r *Registry) Add(actions ...*Action) error {
	if r == nil {
		return Internal("Registry is nil.", nil)
	}
	prepared := make([]*Action, 0, len(actions))
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if action == nil {
			return Internal("Cannot register a nil action.", nil)
		}
		copy := cloneAction(action)
		if !validActionName(copy.Name) {
			return Internal(fmt.Sprintf("Invalid action name %q. Use a dot-namespaced name such as \"invoices.create\".", copy.Name), nil)
		}
		if copy.Execute == nil {
			return Internal(fmt.Sprintf("Action %q has no execute function.", copy.Name), nil)
		}
		if _, duplicate := seen[copy.Name]; duplicate {
			return Conflict(fmt.Sprintf("Action %q is already registered.", copy.Name), nil)
		}
		seen[copy.Name] = struct{}{}
		prepared = append(prepared, copy)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, action := range prepared {
		if _, exists := r.actions[action.Name]; exists {
			return Conflict(fmt.Sprintf("Action %q is already registered.", action.Name), nil)
		}
	}
	for _, action := range prepared {
		r.actions[action.Name] = action
	}
	return nil
}

// Remove deletes an action by name and reports whether it existed.
func (r *Registry) Remove(name string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.actions[name]
	delete(r.actions, name)
	return ok
}

// Clear removes every action. It is used by gateways refreshing an upstream
// catalog.
func (r *Registry) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = make(map[string]*Action)
}

// Get returns a copy of an action or nil when it is unknown.
func (r *Registry) Get(name string) *Action {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneAction(r.actions[name])
}

// Require returns an action or a NOT_FOUND error.
func (r *Registry) Require(name string) (*Action, error) {
	action := r.Get(name)
	if action == nil {
		return nil, NotFound(fmt.Sprintf("Unknown action %q.", name))
	}
	return action, nil
}

// Has reports whether an action is registered.
func (r *Registry) Has(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.actions[name]
	return ok
}

// Size returns the number of registered actions.
func (r *Registry) Size() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.actions)
}

// Len is an alias for Size.
func (r *Registry) Len() int { return r.Size() }

// List returns a name-sorted snapshot, optionally filtered.
func (r *Registry) List(filter *ActionFilter) []*Action {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	actions := make([]*Action, 0, len(r.actions))
	for _, action := range r.actions {
		actions = append(actions, cloneAction(action))
	}
	r.mu.RUnlock()

	out := make([]*Action, 0, len(actions))
	for _, action := range actions {
		if matchesFilter(action, filter) {
			out = append(out, action)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func matchesFilter(action *Action, filter *ActionFilter) bool {
	if filter == nil {
		return true
	}
	if len(filter.Names) > 0 {
		found := false
		for _, name := range filter.Names {
			if name == action.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filter.Namespace != "" && !strings.HasPrefix(action.Name, filter.Namespace+".") {
		return false
	}
	if len(filter.Tags) > 0 {
		for _, tag := range filter.Tags {
			found := false
			for _, actionTag := range action.Tags {
				if actionTag == tag {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	if len(filter.Scopes) > 0 && !HasScopes(action.Scopes, filter.Scopes) {
		return false
	}
	if filter.Include != nil && !filter.Include(action) {
		return false
	}
	return true
}

// VisibleTo returns the actions a principal with the supplied scopes may
// discover, sorted by name.
func (r *Registry) VisibleTo(scopes []string) []*Action {
	var actions []*Action
	for _, action := range r.List(nil) {
		if HasScopes(scopes, action.Scopes) {
			actions = append(actions, action)
		}
	}
	return actions
}

// Namespaces returns the sorted first segments of every action name.
func (r *Registry) Namespaces() []string {
	seen := make(map[string]struct{})
	for _, action := range r.List(nil) {
		namespace := action.Name
		if index := strings.IndexByte(action.Name, '.'); index >= 0 {
			namespace = action.Name[:index]
		}
		if namespace != "" {
			seen[namespace] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for namespace := range seen {
		out = append(out, namespace)
	}
	sort.Strings(out)
	return out
}

// ToToolDescriptors projects actions into MCP-facing descriptors. When
// opts.Scopes is non-nil the result is scope-filtered; a nil slice means "all
// actions" and an empty non-nil slice means "public actions only".
func (r *Registry) ToToolDescriptors(opts ToolDescriptorOptions) []ToolDescriptor {
	var actions []*Action
	if opts.Scopes != nil {
		actions = r.VisibleTo(opts.Scopes)
		if opts.Filter != nil {
			filtered := make([]*Action, 0, len(actions))
			for _, action := range actions {
				if matchesFilter(action, opts.Filter) {
					filtered = append(filtered, action)
				}
			}
			actions = filtered
		}
	} else {
		actions = r.List(opts.Filter)
	}
	out := make([]ToolDescriptor, 0, len(actions))
	for _, action := range actions {
		out = append(out, ToToolDescriptor(action))
	}
	return out
}

// ToToolDescriptor projects one action into an MCP descriptor.
func ToToolDescriptor(action *Action) ToolDescriptor {
	if action == nil {
		return ToolDescriptor{}
	}
	title := action.Title
	if title == "" && action.Annotations != nil {
		title = action.Annotations.Title
	}
	if title == "" {
		title = action.Name
	}
	readOnly := hasTag(action.Tags, "read-only")
	destructive := action.Risk == RiskHigh || action.Risk == RiskCritical
	idempotent := action.Idempotent
	var openWorld bool
	if action.Annotations != nil {
		if action.Annotations.ReadOnlyHint != nil {
			readOnly = *action.Annotations.ReadOnlyHint
		}
		if action.Annotations.DestructiveHint != nil {
			destructive = *action.Annotations.DestructiveHint
		}
		if action.Annotations.IdempotentHint != nil {
			idempotent = *action.Annotations.IdempotentHint
		}
		if action.Annotations.OpenWorldHint != nil {
			openWorld = *action.Annotations.OpenWorldHint
		}
	}
	annotations := &ActionAnnotations{
		Title:           title,
		ReadOnlyHint:    Ptr(readOnly),
		DestructiveHint: Ptr(destructive),
		IdempotentHint:  Ptr(idempotent),
		OpenWorldHint:   Ptr(openWorld),
	}

	meta := make(map[string]any, len(action.Meta)+7)
	meta["gap/risk"] = action.Risk
	meta["gap/scopes"] = append([]string(nil), action.Scopes...)
	meta["gap/version"] = action.Version
	meta["gap/idempotent"] = action.Idempotent
	if len(action.Tags) > 0 {
		meta["gap/tags"] = append([]string(nil), action.Tags...)
	}
	if action.UI != nil {
		meta["gap/ui"] = action.UI
	}
	if action.Task {
		meta["gap/task"] = true
	}
	if action.Deprecated {
		if action.DeprecatedMessage != "" {
			meta["gap/deprecated"] = action.DeprecatedMessage
		} else {
			meta["gap/deprecated"] = true
		}
	}
	for key, value := range action.Meta {
		meta[key] = value
	}

	input := action.InputSchema
	if input == nil {
		input = emptyObjectSchema()
	} else if !IsObjectSchema(input) {
		copy := make(map[string]any, len(input)+1)
		for key, value := range input {
			copy[key] = value
		}
		copy["type"] = "object"
		input = copy
	}

	descriptor := ToolDescriptor{
		Name:        action.Name,
		Title:       title,
		Description: action.Description,
		InputSchema: input,
		Annotations: annotations,
		Meta:        meta,
	}
	if action.OutputSchema != nil {
		descriptor.OutputSchema = action.OutputSchema
	}
	return descriptor
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// Validate performs CI-friendly contract checks. Errors should fail a build;
// warnings are advice. It never mutates the registry.
func (r *Registry) Validate() []RegistryIssue {
	issues := make([]RegistryIssue, 0)
	for _, action := range r.List(nil) {
		issues = append(issues, validateAction(action)...)
	}
	return issues
}

func validateAction(action *Action) []RegistryIssue {
	var issues []RegistryIssue
	add := func(level, code, message string) {
		issues = append(issues, RegistryIssue{Level: level, Code: code, Action: action.Name, Message: message})
	}

	if !validActionName(action.Name) {
		add("error", "name", "Invalid tool name.")
	}
	length := utf8.RuneCountInString(action.Description)
	if strings.TrimSpace(action.Description) == "" {
		add("error", "description.missing", "Every action needs a description written for the model.")
	} else if length < 30 {
		add("warn", "description.short", "Description is shorter than 30 characters; models select tools by description.")
	} else if length > 2000 {
		add("warn", "description.long", "Description exceeds 2000 characters and spends context budget.")
	}

	if action.InputSchema != nil {
		if !IsObjectSchema(action.InputSchema) {
			add("error", "input.not_object", "MCP tool input must be an object schema.")
		}
		if err := ValidateSchema(action.InputSchema); err != nil {
			add("error", "input.invalid_schema", "Input schema does not compile: "+err.Error())
		}
		missing := SchemaPathsWithoutDescriptions(action.InputSchema)
		if len(missing) > 0 {
			shown := missing
			if len(shown) > 8 {
				shown = shown[:8]
			}
			add("warn", "input.undescribed", "Undescribed input field(s): "+strings.Join(shown, ", ")+".")
		}
	}
	if action.OutputSchema != nil {
		if err := ValidateSchema(action.OutputSchema); err != nil {
			add("error", "output.invalid_schema", "Output schema does not compile: "+err.Error())
		}
	}

	for _, scope := range action.Scopes {
		if !scopePattern.MatchString(scope) {
			add("warn", "scope.format", fmt.Sprintf("Scope %q does not follow the resource:verb convention.", scope))
		}
	}

	risky := action.Risk == RiskHigh || action.Risk == RiskCritical
	if risky && !action.Confirm && action.ConfirmFunc == nil {
		add("warn", "risk.no_confirmation", fmt.Sprintf("%s risk action does not require confirmation.", action.Risk))
	}
	if destructiveVerbPattern.MatchString(action.Name) && !action.Confirm && action.ConfirmFunc == nil {
		add("warn", "destructive.no_confirmation", "Name looks destructive but the action does not require confirmation.")
	}
	if risky && !action.Idempotent {
		add("warn", "risk.not_idempotent", "High-risk action is not idempotent; retries can duplicate effects.")
	}
	if action.Deprecated {
		message := action.DeprecatedMessage
		if message == "" {
			message = "Action is deprecated."
		}
		add("warn", "deprecated", message)
	}
	if action.UI != nil && action.UI.Route == "" && action.UI.Action == "" {
		add("warn", "ui.incomplete", "UI binding has neither a route nor an action id.")
	}
	if action.Timeout < 0 {
		add("error", "timeout.invalid", "Action timeout must not be negative.")
	}
	return issues
}
