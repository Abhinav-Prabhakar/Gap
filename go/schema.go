package gap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// schemaCache memoizes compiled schemas by the canonical hash of their JSON
// representation. Schemas are immutable by convention after registration.
var schemaCache sync.Map // map[string]*jsonschema.Schema

// compileSchema compiles a JSON Schema map, reusing a previous compilation when
// the document is byte-for-byte equivalent after key normalization. The error is
// safe to return to a developer, not to an agent.
func compileSchema(schema map[string]any) (*jsonschema.Schema, error) {
	if schema == nil {
		return nil, nil
	}
	canonical, err := CanonicalJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("encode schema: %w", err)
	}
	sum := sha256.Sum256(canonical)
	key := hex.EncodeToString(sum[:])
	if cached, ok := schemaCache.Load(key); ok {
		return cached.(*jsonschema.Schema), nil
	}

	compiler := jsonschema.NewCompiler()
	resourceURL := "https://gap.invalid/schemas/" + key
	decoded, err := decodeJSONValue(canonical)
	if err != nil {
		return nil, fmt.Errorf("decode schema: %w", err)
	}
	if err := compiler.AddResource(resourceURL, decoded); err != nil {
		return nil, fmt.Errorf("add schema resource: %w", err)
	}
	compiled, err := compiler.Compile(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	actual, _ := schemaCache.LoadOrStore(key, compiled)
	return actual.(*jsonschema.Schema), nil
}

func decodeJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return normalizeJSON(value)
}

// ValidateValue validates a JSON-shaped value against a schema. A nil schema
// accepts every value. On success it returns the value unchanged. On failure it
// returns one issue per leaf validation error; callers add transport context.
//
// Validation is cached by schema content, so repeated tool calls do not
// recompile.
func ValidateValue(schema map[string]any, value any) (any, []ValidationIssue) {
	if schema == nil {
		return value, nil
	}
	compiled, err := compileSchema(schema)
	if err != nil {
		return value, []ValidationIssue{{
			Path:    "(schema)",
			Message: "The action's JSON Schema is invalid.",
			Code:    "schema",
		}}
	}
	if compiled == nil {
		return value, nil
	}
	if err := compiled.Validate(value); err != nil {
		var validationErr *jsonschema.ValidationError
		if ok := asValidationError(err, &validationErr); ok {
			issues := make([]ValidationIssue, 0, len(validationErr.Causes))
			flattenValidationError(validationErr, &issues)
			if len(issues) == 0 {
				issues = append(issues, ValidationIssue{
					Path:    "(root)",
					Message: "Value does not match the schema.",
					Code:    "validation",
				})
			}
			return value, issues
		}
		return value, []ValidationIssue{{
			Path:    "(root)",
			Message: err.Error(),
			Code:    "validation",
		}}
	}
	return value, nil
}

func asValidationError(err error, target **jsonschema.ValidationError) bool {
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		*target = ve
		return true
	}
	return false
}

var englishPrinter = message.NewPrinter(language.English)

func flattenValidationError(err *jsonschema.ValidationError, issues *[]ValidationIssue) {
	if err == nil {
		return
	}
	if len(err.Causes) > 0 {
		for _, cause := range err.Causes {
			flattenValidationError(cause, issues)
		}
		return
	}
	path := strings.Join(err.InstanceLocation, ".")
	if required, ok := err.ErrorKind.(*kind.Required); ok && len(required.Missing) > 0 {
		for _, missing := range required.Missing {
			missingPath := missing
			if path != "" {
				missingPath = path + "." + missing
			}
			*issues = append(*issues, ValidationIssue{Path: missingPath, Message: "Required property is missing.", Code: "required"})
		}
		return
	}
	if path == "" {
		path = "(root)"
	}
	msg := "Invalid value."
	if err.ErrorKind != nil {
		msg = err.ErrorKind.LocalizedString(englishPrinter)
	}
	code := ""
	if err.ErrorKind != nil {
		parts := err.ErrorKind.KeywordPath()
		if len(parts) > 0 {
			code = parts[len(parts)-1]
		}
	}
	*issues = append(*issues, ValidationIssue{Path: path, Message: msg, Code: code})
}

// IsObjectSchema reports whether a schema describes an object-shaped MCP input.
func IsObjectSchema(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if kind, _ := schema["type"].(string); kind == "object" {
		return true
	}
	if _, ok := schema["type"]; !ok {
		_, hasProperties := schema["properties"].(map[string]any)
		return hasProperties
	}
	return false
}

// SchemaPathsWithoutDescriptions collects property paths whose schema has no
// description. It is used by Registry.Validate to catch under-described tools.
func SchemaPathsWithoutDescriptions(schema map[string]any) []string {
	var missing []string
	collectUndescribed(schema, "", &missing)
	return missing
}

func collectUndescribed(schema map[string]any, prefix string, missing *[]string) {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		property, ok := properties[key].(map[string]any)
		if !ok {
			continue
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		description, _ := property["description"].(string)
		if strings.TrimSpace(description) == "" {
			*missing = append(*missing, path)
		}
		kind, _ := property["type"].(string)
		switch kind {
		case "object":
			collectUndescribed(property, path, missing)
		case "array":
			if items, ok := property["items"].(map[string]any); ok {
				collectUndescribed(items, path+"[]", missing)
			}
		}
	}
}

// ValidateSchema compiles a schema without validating a value. It is useful for
// contract tests and for reporting a schema error at registration time.
func ValidateSchema(schema map[string]any) error {
	_, err := compileSchema(schema)
	return err
}
