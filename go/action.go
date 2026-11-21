package gap

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
)

// ExecuteFunc is the untyped action body the server pipeline invokes. Input has
// already been validated against the action's input schema.
type ExecuteFunc func(ctx context.Context, input any, actx *Context) (any, error)

// UndoFunc is a best-effort inverse for an action. It receives the validated
// input and the unredacted result of the original call.
type UndoFunc func(ctx context.Context, output any, input any, actx *Context) error

// ConfirmFunc decides per invocation whether a human must approve the call.
type ConfirmFunc func(ctx context.Context, input any, actx *Context) bool

// Action is the single definition that becomes an MCP tool. Define actions with
// Define or DefineAction; the server derives descriptors, validation and the
// execution pipeline from this struct.
type Action struct {
	// Name is the stable, dot-namespaced tool name, for example "invoices.create".
	Name string
	// Description is written for a model, not a human. Be precise about effects.
	Description string
	// Version is a monotonic contract version surfaced in tool metadata.
	Version int
	// Title is an optional human-readable display name.
	Title string
	// InputSchema is a draft 2020-12 JSON Schema object. Define derives it when
	// omitted. It must be an object schema for MCP.
	InputSchema map[string]any
	// OutputSchema is optional. When set, results are validated before they are
	// returned and the tool advertises an output schema.
	OutputSchema map[string]any
	// Scopes are OAuth-style scopes required to see or call the action. Empty
	// means any authenticated principal.
	Scopes []string
	// Risk describes the blast radius. Defaults to low.
	Risk RiskLevel
	// Idempotent promises that repeating the same call with the same principal
	// has no additional effect. The server automatically caches these calls.
	Idempotent bool
	// Confirm asks for human approval for every invocation.
	Confirm bool
	// ConfirmFunc asks for human approval when it returns true.
	ConfirmFunc ConfirmFunc
	// Tags are free-form labels used by search and the read-only annotation.
	Tags []string
	// Examples are documentation examples. Never put secrets in them.
	Examples []ActionExample
	// Annotations override the MCP tool behavior hints derived from Risk/Tags.
	Annotations *ActionAnnotations
	// UI describes a semantic DOM binding used by handoff links.
	UI *ActionUI
	// Undo is a best-effort inverse used by gap.undo.
	Undo UndoFunc
	// Execute is required and contains the action body.
	Execute ExecuteFunc
	// Meta is framework metadata copied into the MCP tool's _meta. It must not
	// contain secrets.
	Meta map[string]any
	// Timeout is the per-action execution budget. Zero uses the server default.
	Timeout time.Duration
	// Task runs the action in the background and returns a pollable task id.
	Task bool
	// Deprecated marks the action as deprecated in tool metadata.
	Deprecated bool
	// DeprecatedMessage is an optional replacement/deprecation notice.
	DeprecatedMessage string
}

// NeedsConfirm reports whether this invocation requires human approval.
func (a *Action) NeedsConfirm(ctx context.Context, input any, actx *Context) bool {
	if a == nil {
		return false
	}
	if a.Confirm {
		return true
	}
	return a.ConfirmFunc != nil && a.ConfirmFunc(ctx, input, actx)
}

// DefineAction normalizes and returns a shallow copy of the supplied definition.
// It does not validate the action; Registry.Add and Registry.Validate do that.
// The name is trimmed and internal whitespace is replaced with dots.
func DefineAction(spec Action) *Action {
	spec = normalizeAction(spec)
	return &spec
}

// Define builds a typed action. The input and output Go types become draft
// 2020-12 JSON Schemas via github.com/invopop/jsonschema. Document schemas with
// `json` tags for property names and `jsonschema` tags for descriptions,
// required fields and constraints, for example:
//
//	type CreateInvoiceInput struct {
//	    Customer string  `json:"customer" jsonschema:"description=Customer id,required"`
//	    Total    float64 `json:"total" jsonschema:"description=Amount in cents,minimum=0"`
//	}
//
// The handler is only ever called with a value that already passed schema
// validation. Output is validated by the server when an output schema exists.
func Define[I, O any](spec Action, fn func(ctx context.Context, input I, actx *Context) (O, error)) *Action {
	if spec.InputSchema == nil {
		spec.InputSchema = SchemaFromType(reflect.TypeFor[I]())
	}
	if spec.OutputSchema == nil {
		spec.OutputSchema = outputSchemaForType(reflect.TypeFor[O]())
	}
	spec.Execute = func(ctx context.Context, input any, actx *Context) (any, error) {
		var typed I
		typeOfI := reflect.TypeFor[I]()
		if typeOfI == nil || typeOfI == reflect.TypeOf((*any)(nil)).Elem() {
			// I is any; pass the decoded JSON value through untouched.
			var ok bool
			typed, ok = input.(I)
			if !ok {
				raw, err := json.Marshal(input)
				if err != nil {
					return nil, InvalidInput("Invalid input.", map[string]any{"error": err.Error()})
				}
				if err := json.Unmarshal(raw, &typed); err != nil {
					return nil, InvalidInput("Invalid input.", map[string]any{"error": err.Error()})
				}
			}
		} else if existing, ok := input.(I); ok {
			typed = existing
		} else {
			raw, err := json.Marshal(input)
			if err != nil {
				return nil, InvalidInput("Invalid input.", map[string]any{"error": err.Error()})
			}
			if err := json.Unmarshal(raw, &typed); err != nil {
				return nil, InvalidInput("Invalid input.", map[string]any{"error": err.Error()})
			}
		}
		if fn == nil {
			return nil, Internal("The action has no execute function.", nil)
		}
		return fn(ctx, typed, actx)
	}
	return DefineAction(spec)
}

// SchemaForType is the untyped form of Define's schema inference. It returns an
// object schema for struct/map inputs and strips document-level identifiers.
func SchemaForType(t reflect.Type) map[string]any {
	if t == nil {
		return emptyObjectSchema()
	}
	reflector := &jsonschema.Reflector{
		DoNotReference:             true,
		RequiredFromJSONSchemaTags: true,
		Anonymous:                  true,
	}
	schema := reflector.ReflectFromType(t)
	return schemaToMap(schema, true)
}

// SchemaFromType is an alias for SchemaForType.
func SchemaFromType(t reflect.Type) map[string]any { return SchemaForType(t) }

func outputSchemaForType(t reflect.Type) map[string]any {
	if t == nil {
		return nil
	}
	if t == reflect.TypeOf((*any)(nil)).Elem() {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Struct && t.NumField() == 0 {
		return nil
	}
	schema := SchemaForType(t)
	return schema
}

func schemaToMap(schema *jsonschema.Schema, input bool) map[string]any {
	if schema == nil {
		if input {
			return emptyObjectSchema()
		}
		return nil
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		if input {
			return emptyObjectSchema()
		}
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		if input {
			return emptyObjectSchema()
		}
		return nil
	}
	delete(out, "$schema")
	delete(out, "$id")
	if input {
		if _, ok := out["type"]; !ok {
			out["type"] = "object"
		}
		if out["type"] != "object" {
			out["type"] = "object"
		}
	}
	if len(out) == 0 && !input {
		return nil
	}
	return out
}

func emptyObjectSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"properties":           map[string]any{},
		"additionalProperties": false,
	}
}

var actionNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$`)
var whitespacePattern = regexp.MustCompile(`\s+`)

func normalizeActionName(name string) string {
	trimmed := strings.TrimSpace(name)
	return whitespacePattern.ReplaceAllString(trimmed, ".")
}

func normalizeAction(spec Action) Action {
	spec.Name = normalizeActionName(spec.Name)
	if spec.Risk == "" {
		spec.Risk = RiskLow
	}
	if spec.Version == 0 {
		spec.Version = 1
	}
	if spec.InputSchema == nil {
		spec.InputSchema = emptyObjectSchema()
	}
	if spec.Scopes != nil {
		spec.Scopes = append([]string(nil), spec.Scopes...)
	}
	if spec.Tags != nil {
		spec.Tags = append([]string(nil), spec.Tags...)
	}
	if spec.Examples != nil {
		spec.Examples = append([]ActionExample(nil), spec.Examples...)
	}
	if spec.Meta != nil {
		meta := make(map[string]any, len(spec.Meta))
		for key, value := range spec.Meta {
			meta[key] = value
		}
		spec.Meta = meta
	}
	if spec.UI != nil {
		ui := *spec.UI
		if spec.UI.Fields != nil {
			ui.Fields = make(map[string]string, len(spec.UI.Fields))
			for key, value := range spec.UI.Fields {
				ui.Fields[key] = value
			}
		}
		spec.UI = &ui
	}
	if spec.Annotations != nil {
		annotations := *spec.Annotations
		spec.Annotations = &annotations
	}
	return spec
}

func cloneAction(action *Action) *Action {
	if action == nil {
		return nil
	}
	copy := normalizeAction(*action)
	return &copy
}

// NameError reports whether name is a valid MCP tool name.
func validActionName(name string) bool { return actionNamePattern.MatchString(name) }

func describeAction(action *Action) string {
	if action == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (risk=%s)", action.Name, action.Risk)
}
