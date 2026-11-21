package gap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// REDACTED is the replacement written by Redact.
const REDACTED = "[REDACTED]"

// CanonicalJSON returns deterministic JSON with sorted object keys. It is used
// for argument hashing, approval binding, idempotency keys and audit records.
// Numbers are normalized so 1 and 1.0 hash identically.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	normalized, err := normalizeJSON(decoded)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func normalizeJSON(value any) (any, error) {
	switch v := value.(type) {
	case nil, bool, string:
		return v, nil
	case json.Number:
		return canonicalNumber(string(v))
	case float64:
		return canonicalNumber(strconv.FormatFloat(v, 'g', -1, 64))
	case float32:
		return canonicalNumber(strconv.FormatFloat(float64(v), 'g', -1, 32))
	case int, int8, int16, int32, int64:
		return v, nil
	case uint, uint8, uint16, uint32, uint64:
		return v, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			normalized, err := normalizeJSON(item)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			normalized, err := normalizeJSON(v[key])
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	default:
		return v, nil
	}
}

func canonicalNumber(raw string) (json.Number, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("canonical JSON: empty number")
	}
	f, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("canonical JSON: invalid number %q", raw)
	}
	if f == 0 {
		return json.Number("0"), nil
	}
	abs := math.Abs(f)
	var out string
	if abs < 1e-6 || abs >= 1e21 {
		out = strconv.FormatFloat(f, 'g', -1, 64)
	} else {
		out = strconv.FormatFloat(f, 'f', -1, 64)
	}
	return json.Number(out), nil
}

// Hash returns the hex SHA-256 of the canonical JSON encoding of value.
func Hash(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// HashBytes returns the hex SHA-256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashString returns the hex SHA-256 of s.
func HashString(s string) string { return HashBytes([]byte(s)) }

// HasScopes reports whether every required scope is covered by a granted
// scope. Grants support "*" and suffix wildcards such as "invoices:*".
func HasScopes(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, scope := range required {
		covered := false
		for _, grant := range granted {
			if scopeMatches(grant, scope) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// MissingScopes returns the required scopes not covered by granted.
func MissingScopes(granted, required []string) []string {
	var missing []string
	for _, scope := range required {
		covered := false
		for _, grant := range granted {
			if scopeMatches(grant, scope) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, scope)
		}
	}
	return missing
}

func scopeMatches(granted, required string) bool {
	if granted == "*" || granted == required {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		return strings.HasPrefix(required, strings.TrimSuffix(granted, "*"))
	}
	if strings.HasSuffix(granted, "*") {
		return strings.HasPrefix(required, strings.TrimSuffix(granted, "*"))
	}
	return false
}

// UniqueStrings de-duplicates values while preserving their original order.
func UniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// MergeScopes merges scope groups without duplicates.
func MergeScopes(groups ...[]string) []string {
	var all []string
	for _, group := range groups {
		all = append(all, group...)
	}
	return UniqueStrings(all)
}

// ParsePath splits a dot/bracket path into segments. `items[]` and `items[*]`
// both become "items" followed by "*".
func ParsePath(path string) []string {
	var b strings.Builder
	inBracket := false
	for _, r := range path {
		switch {
		case r == '[':
			b.WriteByte('.')
			inBracket = true
		case r == ']':
			inBracket = false
		case r == '.' && !inBracket:
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	parts := strings.Split(b.String(), ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			part = "*"
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// DeepGet reads a dot/bracket path from a JSON-shaped value. It returns
// (nil, false) when the path is absent.
func DeepGet(value any, path string) (any, bool) {
	current := value
	for _, segment := range ParsePath(path) {
		switch node := current.(type) {
		case nil:
			return nil, false
		case []any:
			if segment == "*" {
				return node, true
			}
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		case map[string]any:
			if segment == "*" {
				return node, true
			}
			next, ok := node[segment]
			if !ok {
				return nil, false
			}
			current = next
		default:
			return nil, false
		}
	}
	return current, true
}

// Redact deep-copies JSON-shaped values, replacing values at dot/bracket paths
// with REDACTED. It supports `items[].ssn`, `items[*].ssn` and `items.0.ssn`.
// The source value is never mutated.
func Redact(value any, paths []string) any {
	if len(paths) == 0 {
		return value
	}
	result := value
	for _, path := range paths {
		result = redactAt(result, ParsePath(path), 0)
	}
	return result
}

func redactAt(value any, segments []string, index int) any {
	if index >= len(segments) {
		return REDACTED
	}
	segment := segments[index]
	switch node := value.(type) {
	case []any:
		copySlice := make([]any, len(node))
		copy(copySlice, node)
		if segment == "*" {
			for i, item := range copySlice {
				copySlice[i] = redactAt(item, segments, index+1)
			}
			return copySlice
		}
		position, err := strconv.Atoi(segment)
		if err != nil || position < 0 || position >= len(copySlice) {
			return value
		}
		copySlice[position] = redactAt(copySlice[position], segments, index+1)
		return copySlice
	case map[string]any:
		if segment == "*" {
			copyMap := make(map[string]any, len(node))
			for key, item := range node {
				copyMap[key] = redactAt(item, segments, index+1)
			}
			return copyMap
		}
		item, ok := node[segment]
		if !ok {
			return value
		}
		copyMap := make(map[string]any, len(node))
		for key, existing := range node {
			copyMap[key] = existing
		}
		copyMap[segment] = redactAt(item, segments, index+1)
		return copyMap
	default:
		return value
	}
}

// ToJSONValue normalizes arbitrary Go values (including structs) into plain
// JSON values: nil, bool, string, float64, []any and map[string]any.
func ToJSONValue(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode JSON value: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode JSON value: %w", err)
	}
	return decoded, nil
}

// CreateID returns a prefixed random identifier, for example
// "apr_9f2c...". It uses crypto/rand and never panics.
func CreateID(prefix string) string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failure is unrecoverable for identifiers; fall back to
		// the current time so callers still get a unique-ish value.
		return fmt.Sprintf("%s_%x", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buf[:])
}

// RandomBase64 returns n random bytes encoded as unpadded base64url.
func RandomBase64(n int) string {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// FormatDuration renders a human-readable duration.
func FormatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	default:
		return strconv.FormatInt(int64(d.Minutes()), 10) + "m"
	}
}

// QuoteHeaderValue removes control characters and escapes a value for an HTTP
// quoted-string.
func QuoteHeaderValue(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Ptr returns a pointer to v. It is a convenience for optional Boolean and
// numeric configuration fields.
func Ptr[T any](v T) *T { return &v }
