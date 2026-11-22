package gap

import (
	"testing"
)

func TestPolicyEvaluationTable(t *testing.T) {
	invoice := echoAction("invoices.create", nil)
	invoice.Scopes = []string{"invoices:write"}

	tests := []struct {
		name         string
		document     PolicyDocument
		args         any
		scopes       []string
		wantDecision string
		wantCode     string
	}{
		{
			name:         "allow by default",
			document:     PolicyDocument{Version: 1, Rules: []PolicyRule{}},
			wantDecision: "allow",
		},
		{
			name: "deny rule",
			document: PolicyDocument{Version: 1, Rules: []PolicyRule{{
				Tools:  []string{"invoices.*"},
				Deny:   true,
				Reason: "Invoices are frozen.",
			}}},
			wantDecision: "deny",
			wantCode:     CodePolicyDenied,
		},
		{
			name: "default deny without allow",
			document: PolicyDocument{Version: 1, Default: "deny", Rules: []PolicyRule{{
				Tools: []string{"reports.*"},
			}}},
			wantDecision: "deny",
			wantCode:     CodePolicyDenied,
		},
		{
			name: "confirm rule",
			document: PolicyDocument{Version: 1, Rules: []PolicyRule{{
				Tools:   []string{"invoices.create"},
				Confirm: true,
				Reason:  "Creating invoices needs a human.",
			}}},
			wantDecision: "confirm",
		},
		{
			name: "max amount nested",
			document: PolicyDocument{Version: 1, Rules: []PolicyRule{{
				Tools:     []string{"invoices.*"},
				MaxAmount: Ptr(100.0),
			}}},
			args:         map[string]any{"lineItems": []any{map[string]any{"amount": 250}}},
			wantDecision: "deny",
			wantCode:     "LIMIT_EXCEEDED",
		},
		{
			name: "max array length",
			document: PolicyDocument{Version: 1, Rules: []PolicyRule{{
				Tools:          []string{"invoices.*"},
				MaxArrayLength: Ptr(2),
				ArrayPaths:     []string{"lineItems"},
			}}},
			args:         map[string]any{"lineItems": []any{1, 2, 3}},
			wantDecision: "deny",
			wantCode:     "LIMIT_EXCEEDED",
		},
		{
			name: "rule scopes exclude",
			document: PolicyDocument{Version: 1, Rules: []PolicyRule{{
				Tools:  []string{"invoices.*"},
				Scopes: []string{"invoices:admin"},
				Deny:   true,
			}}},
			scopes:       []string{"invoices:write"},
			wantDecision: "allow",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, err := NewGapPolicy(&test.document)
			if err != nil {
				t.Fatalf("NewGapPolicy: %v", err)
			}
			scopes := test.scopes
			if scopes == nil {
				scopes = []string{"*"}
			}
			actx := TestContext(TestContextOptions{Scopes: scopes})
			decision := engine.Evaluate(PolicyInput{Action: invoice, Args: test.args, Context: actx})
			if decision.Decision != test.wantDecision {
				t.Fatalf("decision = %#v, want %s", decision, test.wantDecision)
			}
			if test.wantCode != "" && decision.Code != test.wantCode {
				t.Fatalf("code = %q, want %q", decision.Code, test.wantCode)
			}
		})
	}
}

func TestPolicyDryRunAndRedaction(t *testing.T) {
	action := echoAction("reports.export", nil)
	initial := TestContext(TestContextOptions{Principal: Ptr(TestPrincipal())})
	engine, err := NewGapPolicy(&PolicyDocument{
		Version: 1,
		Redact:  []string{"secret"},
		Rules: []PolicyRule{{
			Tools:  []string{"reports.*"},
			DryRun: true,
			Redact: []string{"password"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(PolicyInput{Action: action, Args: map[string]any{}, Context: initial})
	if decision.Decision != "allow" {
		t.Fatalf("decision = %#v", decision)
	}
	if !initial.DryRun {
		t.Fatal("policy did not set DryRun on the context")
	}
	if decision.Metadata["dryRun"] != true {
		t.Fatalf("metadata = %#v", decision.Metadata)
	}
	if !containsString(decision.RedactPaths, "secret") || !containsString(decision.RedactPaths, "password") {
		t.Fatalf("redact paths = %#v", decision.RedactPaths)
	}
}

func TestDefinePolicyValidationTable(t *testing.T) {
	tests := []struct {
		name     string
		document PolicyDocument
		wantErr  bool
	}{
		{name: "valid", document: PolicyDocument{Version: 1, Rules: []PolicyRule{}}},
		{name: "missing version", document: PolicyDocument{Rules: []PolicyRule{}}, wantErr: true},
		{name: "bad version", document: PolicyDocument{Version: 2, Rules: []PolicyRule{}}, wantErr: true},
		{name: "bad default", document: PolicyDocument{Version: 1, Default: "maybe", Rules: []PolicyRule{}}, wantErr: true},
		{name: "missing rules", document: PolicyDocument{Version: 1}, wantErr: true},
		{name: "negative max amount", document: PolicyDocument{Version: 1, Rules: []PolicyRule{{MaxAmount: Ptr(-1.0)}}}, wantErr: true},
		{name: "negative array length", document: PolicyDocument{Version: 1, Rules: []PolicyRule{{MaxArrayLength: Ptr(-1)}}}, wantErr: true},
		{name: "blank scope", document: PolicyDocument{Version: 1, Rules: []PolicyRule{{Scopes: []string{" "}}}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DefinePolicy(test.document)
			if test.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParsePolicyJSON(t *testing.T) {
	document, err := ParsePolicyString(`{
		"version": 1,
		"default": "deny",
		"rules": [{"tools": ["invoices.*"], "confirm": true, "reason": "review"}]
	}`)
	if err != nil {
		t.Fatalf("ParsePolicyString: %v", err)
	}
	if document.Default != "deny" || len(document.Rules) != 1 || !document.Rules[0].Confirm {
		t.Fatalf("document = %#v", document)
	}

	if _, err := ParsePolicyString(`{"version":1,"rules":[],"unknown":true}`); err == nil {
		t.Fatal("expected unknown fields to be rejected")
	}
}

func TestPolicyDocumentCloneIsDeep(t *testing.T) {
	document := PolicyDocument{
		Version: 1,
		Rules:   []PolicyRule{{Tools: []string{"a.*"}, Redact: []string{"secret"}}},
	}
	clone := document.Clone()
	clone.Rules[0].Tools[0] = "b.*"
	clone.Rules[0].Redact[0] = "other"
	if document.Rules[0].Tools[0] != "a.*" || document.Rules[0].Redact[0] != "secret" {
		t.Fatalf("clone mutated source: %#v", document)
	}
}

func TestPolicyToolGlobMatching(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "invoices.create", true},
		{"invoices.*", "invoices.create", true},
		{"invoices.*", "invoices", false},
		{"invoices.*", "reports.read", false},
		{"exact.tool", "exact.tool", true},
		{"exact.tool", "exact.tool.extra", false},
	}
	for _, test := range tests {
		if got := matchesTool(test.pattern, test.name); got != test.want {
			t.Fatalf("matchesTool(%q, %q) = %v, want %v", test.pattern, test.name, got, test.want)
		}
	}
}
