package gap

import (
	"context"
	"strings"
	"testing"
)

type addInput struct {
	A int `json:"a" jsonschema:"description=First number,required"`
	B int `json:"b" jsonschema:"description=Second number,required"`
}

type addOutput struct {
	Sum int `json:"sum" jsonschema:"description=Sum of both numbers,required"`
}

func TestDefineInfersAndExecutes(t *testing.T) {
	action := Define[addInput, addOutput](Action{
		Name:        "math.add",
		Description: "Add two integers and return their sum for the caller.",
	}, func(_ context.Context, input addInput, _ *Context) (addOutput, error) {
		return addOutput{Sum: input.A + input.B}, nil
	})

	if action.InputSchema == nil {
		t.Fatal("input schema was not inferred")
	}
	properties, ok := action.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties = %#v", action.InputSchema["properties"])
	}
	for _, field := range []string{"a", "b"} {
		definition, ok := properties[field].(map[string]any)
		if !ok {
			t.Fatalf("property %s = %#v", field, properties[field])
		}
		if definition["description"] == "" {
			t.Fatalf("property %s has no description", field)
		}
	}
	required, _ := action.InputSchema["required"].([]any)
	if len(required) != 2 {
		t.Fatalf("required = %#v, want a and b", action.InputSchema["required"])
	}
	if action.OutputSchema == nil {
		t.Fatal("output schema was not inferred")
	}

	output, err := CallAction(action, map[string]any{"a": 2, "b": 3})
	if err != nil {
		t.Fatalf("CallAction: %v", err)
	}
	values, ok := output.(map[string]any)
	if !ok {
		t.Fatalf("output = %T", output)
	}
	if values["sum"] != float64(5) && values["sum"] != 5 {
		t.Fatalf("sum = %#v", values["sum"])
	}
}

func TestDefineValidatesInput(t *testing.T) {
	action := Define[addInput, addOutput](Action{
		Name:        "math.add",
		Description: "Add two integers and return their sum for the caller.",
	}, func(_ context.Context, input addInput, _ *Context) (addOutput, error) {
		return addOutput{Sum: input.A + input.B}, nil
	})
	_, err := CallAction(action, map[string]any{"a": 2})
	if !IsCode(err, CodeInvalidInput) {
		t.Fatalf("err = %v, want INVALID_INPUT", err)
	}
	details, ok := AsErrorOrNil(err)
	if !ok {
		t.Fatal("expected a Gap error")
	}
	payload, _ := details.Details.(map[string]any)
	issues, _ := payload["issues"].([]ValidationIssue)
	if len(issues) == 0 {
		t.Fatalf("details = %#v", details.Details)
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue.Path, "b") {
			found = true
		}
	}
	if !found {
		t.Fatalf("issues = %#v, want a path for b", issues)
	}
}

func TestDefineActionNormalizes(t *testing.T) {
	action := DefineAction(Action{
		Name:    "  invoices   create ",
		Execute: func(context.Context, any, *Context) (any, error) { return nil, nil },
	})
	if action.Name != "invoices.create" {
		t.Fatalf("name = %q", action.Name)
	}
	if action.Risk != RiskLow {
		t.Fatalf("risk = %q", action.Risk)
	}
	if action.Version != 1 {
		t.Fatalf("version = %d", action.Version)
	}
	if action.InputSchema == nil {
		t.Fatal("expected an empty object schema")
	}
	if !IsObjectSchema(action.InputSchema) {
		t.Fatalf("input schema = %#v", action.InputSchema)
	}
}

func TestValidateValueTable(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":  map[string]any{"type": "string", "minLength": 2},
			"count": map[string]any{"type": "integer", "minimum": 1},
		},
		"required":             []string{"name"},
		"additionalProperties": false,
	}
	tests := []struct {
		name       string
		value      any
		wantIssues bool
		wantPath   string
	}{
		{name: "valid", value: map[string]any{"name": "ok", "count": 2}},
		{name: "missing", value: map[string]any{"count": 2}, wantIssues: true, wantPath: "name"},
		{name: "too short", value: map[string]any{"name": "x"}, wantIssues: true, wantPath: "name"},
		{name: "wrong type", value: map[string]any{"name": "ok", "count": "two"}, wantIssues: true, wantPath: "count"},
		{name: "extra", value: map[string]any{"name": "ok", "extra": true}, wantIssues: true, wantPath: "(root)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, issues := ValidateValue(schema, test.value)
			if test.wantIssues && len(issues) == 0 {
				t.Fatalf("expected issues for %#v", test.value)
			}
			if !test.wantIssues && len(issues) > 0 {
				t.Fatalf("unexpected issues: %#v", issues)
			}
			if test.wantPath != "" && len(issues) > 0 {
				found := false
				for _, issue := range issues {
					if issue.Path == test.wantPath || strings.Contains(issue.Path, test.wantPath) {
						found = true
					}
				}
				if !found {
					t.Fatalf("issues = %#v, want path %q", issues, test.wantPath)
				}
			}
		})
	}
}

func TestValidateValueNilSchemaAcceptsEverything(t *testing.T) {
	value := map[string]any{"anything": []any{1, 2, 3}}
	got, issues := ValidateValue(nil, value)
	if len(issues) > 0 {
		t.Fatalf("issues = %#v", issues)
	}
	if got == nil {
		t.Fatal("value was dropped")
	}
}

func TestRegistryAddAndVisibility(t *testing.T) {
	read := echoAction("invoices.read", nil)
	read.Scopes = []string{"invoices:read"}
	write := echoAction("invoices.write", nil)
	write.Scopes = []string{"invoices:write"}
	registry := testRegistry(t, read, write)

	if registry.Size() != 2 {
		t.Fatalf("size = %d", registry.Size())
	}
	if !registry.Has("invoices.read") {
		t.Fatal("missing invoices.read")
	}
	visible := registry.VisibleTo([]string{"invoices:read"})
	if len(visible) != 1 || visible[0].Name != "invoices.read" {
		t.Fatalf("visible = %#v", visible)
	}
	all := registry.VisibleTo([]string{"*"})
	if len(all) != 2 {
		t.Fatalf("all = %#v", all)
	}
	if names := registry.Namespaces(); len(names) != 1 || names[0] != "invoices" {
		t.Fatalf("namespaces = %#v", names)
	}
}

func TestRegistryRejectsInvalidActions(t *testing.T) {
	tests := []struct {
		name   string
		action *Action
	}{
		{name: "nil action", action: nil},
		{name: "missing execute", action: &Action{Name: "test.echo"}},
		{name: "invalid name", action: &Action{Name: "1 bad!", Execute: func(context.Context, any, *Context) (any, error) { return nil, nil }}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry()
			if err := registry.Add(test.action); err == nil {
				t.Fatal("expected an error")
			}
			if registry.Size() != 0 {
				t.Fatalf("registry was mutated: %d", registry.Size())
			}
		})
	}

	registry := NewRegistry()
	action := echoAction("test.echo", nil)
	if err := registry.Add(action); err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(action); !IsCode(err, CodeConflict) {
		t.Fatalf("duplicate err = %v", err)
	}
}

func TestRegistryValidateIssues(t *testing.T) {
	action := &Action{
		Name:    "invoices.delete",
		Scopes:  []string{"Invoices Write"},
		Risk:    RiskHigh,
		Execute: func(context.Context, any, *Context) (any, error) { return nil, nil },
	}
	registry := NewRegistry(action)
	issues := registry.Validate()
	codes := make(map[string]bool)
	for _, issue := range issues {
		codes[issue.Code] = true
	}
	for _, want := range []string{"description.missing", "risk.no_confirmation", "destructive.no_confirmation", "risk.not_idempotent", "scope.format"} {
		if !codes[want] {
			t.Fatalf("missing issue %q in %#v", want, issues)
		}
	}
}

func TestToToolDescriptor(t *testing.T) {
	action := DefineAction(Action{
		Name:        "reports.read",
		Description: "Read a report without changing any server state.",
		Tags:        []string{"read-only"},
		InputSchema: objectSchema(map[string]any{"id": property("string", "Report id.")}, []string{"id"}),
		Execute:     func(context.Context, any, *Context) (any, error) { return nil, nil },
	})
	descriptor := ToToolDescriptor(action)
	if descriptor.Name != "reports.read" {
		t.Fatalf("name = %q", descriptor.Name)
	}
	if descriptor.Annotations == nil || descriptor.Annotations.ReadOnlyHint == nil || !*descriptor.Annotations.ReadOnlyHint {
		t.Fatalf("annotations = %#v", descriptor.Annotations)
	}
	if descriptor.Annotations.DestructiveHint == nil || *descriptor.Annotations.DestructiveHint {
		t.Fatalf("destructive = %#v", descriptor.Annotations)
	}
	if descriptor.Meta["gap/risk"] != RiskLow {
		t.Fatalf("meta = %#v", descriptor.Meta)
	}
}

func TestSchemaWithoutDescriptions(t *testing.T) {
	schema := objectSchema(map[string]any{
		"outer": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"inner": map[string]any{"type": "string"},
			},
		},
		"described": property("string", "Has a description."),
	}, nil)
	missing := SchemaPathsWithoutDescriptions(schema)
	if !containsString(missing, "outer") || !containsString(missing, "outer.inner") {
		t.Fatalf("missing = %#v", missing)
	}
	if containsString(missing, "described") {
		t.Fatalf("described property was reported: %#v", missing)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// AsErrorOrNil is a tiny test helper mirroring AsError without shadowing it.
func AsErrorOrNil(err error) (*Error, bool) { return AsError(err) }
