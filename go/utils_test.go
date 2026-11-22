package gap

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSONStableAndNumberNormalized(t *testing.T) {
	left, err := CanonicalJSON(map[string]any{"b": 2, "a": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalJSON(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("canonical JSON differs: %s vs %s", left, right)
	}
	hashLeft, _ := Hash(map[string]any{"a": 1})
	hashRight, _ := Hash(map[string]any{"a": 1.0})
	if hashLeft != hashRight {
		t.Fatalf("hashes differ: %s vs %s", hashLeft, hashRight)
	}
	if _, err := CanonicalJSON(func() {}); err == nil {
		t.Fatal("expected a non-JSON value to fail")
	}
}

func TestHasScopesTable(t *testing.T) {
	tests := []struct {
		name     string
		granted  []string
		required []string
		want     bool
	}{
		{name: "nothing required", granted: nil, required: nil, want: true},
		{name: "exact", granted: []string{"invoices:read"}, required: []string{"invoices:read"}, want: true},
		{name: "wildcard", granted: []string{"*"}, required: []string{"anything:write"}, want: true},
		{name: "prefix wildcard", granted: []string{"invoices:*"}, required: []string{"invoices:write"}, want: true},
		{name: "prefix wildcard miss", granted: []string{"invoices:*"}, required: []string{"reports:read"}, want: false},
		{name: "all required", granted: []string{"a", "b"}, required: []string{"a", "b"}, want: true},
		{name: "one missing", granted: []string{"a"}, required: []string{"a", "b"}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := HasScopes(test.granted, test.required); got != test.want {
				t.Fatalf("HasScopes = %v, want %v", got, test.want)
			}
		})
	}

	missing := MissingScopes([]string{"invoices:*"}, []string{"invoices:read", "reports:read"})
	if len(missing) != 1 || missing[0] != "reports:read" {
		t.Fatalf("missing = %#v", missing)
	}
}

func TestRedactDoesNotMutate(t *testing.T) {
	input := map[string]any{
		"user": map[string]any{"ssn": "123-45-6789", "name": "Ada"},
		"items": []any{
			map[string]any{"ssn": "111-11-1111", "id": 1},
			map[string]any{"ssn": "222-22-2222", "id": 2},
		},
	}
	redacted := Redact(input, []string{"user.ssn", "items[].ssn"})
	if input["user"].(map[string]any)["ssn"] != "123-45-6789" {
		t.Fatal("source value was mutated")
	}
	user := redacted.(map[string]any)["user"].(map[string]any)
	if user["ssn"] != REDACTED || user["name"] != "Ada" {
		t.Fatalf("user = %#v", user)
	}
	items := redacted.(map[string]any)["items"].([]any)
	for _, item := range items {
		values := item.(map[string]any)
		if values["ssn"] != REDACTED {
			t.Fatalf("item = %#v", values)
		}
		if values["id"] == nil {
			t.Fatalf("item lost id: %#v", values)
		}
	}
}

func TestErrorPayloadAndNormalize(t *testing.T) {
	err := InvalidInput("Bad input.", map[string]any{"field": "name"})
	payload := err.Payload()
	if payload["code"] != CodeInvalidInput || payload["message"] != "Bad input." {
		t.Fatalf("payload = %#v", payload)
	}
	if _, ok := payload["details"]; !ok {
		t.Fatalf("details missing: %#v", payload)
	}
	if StatusFor(err) != 400 {
		t.Fatalf("status = %d", StatusFor(err))
	}

	internal := Internal("Database exploded.", os.ErrClosed)
	if internal.PublicMessage() != "Internal error." {
		t.Fatalf("public message = %q", internal.PublicMessage())
	}
	if _, ok := internal.Payload()["details"]; ok {
		t.Fatal("internal details leaked")
	}
	normalized := Normalize(os.ErrPermission)
	if normalized.Code != CodeInternal || normalized.PublicMessage() != "Internal error." {
		t.Fatalf("normalized = %#v", normalized)
	}
	if Normalize(context.DeadlineExceeded).Code != CodeTimeout {
		t.Fatalf("deadline error = %#v", Normalize(context.DeadlineExceeded))
	}
	if !IsCode(err, CodeInvalidInput) {
		t.Fatal("IsCode failed")
	}
	limited := RateLimited("slow down", 500)
	if limited.Retryable != true {
		t.Fatal("rate limited should be retryable")
	}
}

func TestHandoffLinkRoundTrip(t *testing.T) {
	link, err := CreateHandoffLink(HandoffLinkOptions{
		Secret:      "handoff-secret",
		Action:      "invoices.create",
		Args:        map[string]any{"customer": "cus_1"},
		PrincipalID: "usr_1",
		TenantID:    "ten_1",
		BaseURL:     "https://app.example.com",
		Route:       "/invoices/new",
	})
	if err != nil {
		t.Fatalf("CreateHandoffLink: %v", err)
	}
	if !strings.HasPrefix(link.URL, "https://app.example.com/invoices/new?gap_state=") {
		t.Fatalf("url = %q", link.URL)
	}
	state, err := HandoffStateFromURL(link.URL, "handoff-secret", HandoffVerifyOptions{
		Action: "invoices.create",
		Args:   map[string]any{"customer": "cus_1"},
	})
	if err != nil || state == nil {
		t.Fatalf("state = %#v, err = %v", state, err)
	}
	if state.PrincipalID != "usr_1" || state.TenantID != "ten_1" {
		t.Fatalf("state = %#v", state)
	}
	if _, err := VerifyHandoffToken(link.Token, "handoff-secret", HandoffVerifyOptions{Action: "invoices.delete"}); err != nil {
		t.Fatal(err)
	}
	if state, _ := VerifyHandoffToken(link.Token, "handoff-secret", HandoffVerifyOptions{Action: "invoices.delete"}); state != nil {
		t.Fatal("token verified for the wrong action")
	}
	if state, _ := VerifyHandoffToken(link.Token, "wrong-secret", HandoffVerifyOptions{}); state != nil {
		t.Fatal("token verified with the wrong secret")
	}
	tampered := tamperToken(link.Token)
	if state, _ := VerifyHandoffToken(tampered, "handoff-secret", HandoffVerifyOptions{}); state != nil {
		t.Fatal("tampered token verified")
	}
}

func TestHandoffExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	link, err := CreateHandoffLink(HandoffLinkOptions{
		Secret:      "secret",
		Action:      "a.b",
		Args:        map[string]any{},
		PrincipalID: "usr_1",
		TTL:         time.Minute,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if state, _ := VerifyHandoffToken(link.Token, "secret", HandoffVerifyOptions{Now: func() time.Time { return now }}); state != nil {
		t.Fatal("expired handoff token verified")
	}
}

func TestMemoryAuditLog(t *testing.T) {
	log := NewMemoryAuditLog(MemoryAuditLogOptions{Max: 2})
	for index := 0; index < 3; index++ {
		if err := log.Record(context.Background(), AuditEvent{ID: CreateID("audit"), Action: "a.b", PrincipalID: "usr_1"}); err != nil {
			t.Fatal(err)
		}
	}
	events := log.List()
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	for _, event := range events {
		if event.Timestamp.IsZero() {
			t.Fatal("timestamp was not filled")
		}
	}
	log.Clear()
	if len(log.List()) != 0 {
		t.Fatal("clear failed")
	}
}

func TestJSONLAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	log, err := NewJSONLAuditLog(path)
	if err != nil {
		t.Fatalf("NewJSONLAuditLog: %v", err)
	}
	if err := log.Record(context.Background(), AuditEvent{Action: "a.b", PrincipalID: "usr_1", Decision: AuditAllowed}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("audit log is empty")
	}
	var event AuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if event.Action != "a.b" || event.Decision != AuditAllowed {
		t.Fatalf("event = %#v", event)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := log.Record(context.Background(), AuditEvent{}); err == nil {
		t.Fatal("record after close should fail")
	}
}

func TestTokenBucketRateLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewTokenBucketRateLimiter(RateLimitOptions{
		Limit:  2,
		Window: time.Second,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if first := limiter.Consume("principal:tool", 1); !first.Allowed || first.Remaining != 1 {
		t.Fatalf("first = %#v", first)
	}
	if second := limiter.Consume("principal:tool", 1); !second.Allowed || second.Remaining != 0 {
		t.Fatalf("second = %#v", second)
	}
	if third := limiter.Consume("principal:tool", 1); third.Allowed || third.RetryAfter <= 0 {
		t.Fatalf("third = %#v", third)
	}
	now = now.Add(500 * time.Millisecond)
	if fourth := limiter.Consume("principal:tool", 1); !fourth.Allowed {
		t.Fatalf("fourth = %#v", fourth)
	}
	if fifth := limiter.Consume("principal:tool", 1); fifth.Allowed {
		t.Fatalf("fifth = %#v", fifth)
	}
	if other := limiter.Consume("other:tool", 1); !other.Allowed {
		t.Fatalf("other key = %#v", other)
	}
	limiter.Reset("principal:tool")
	if refreshed := limiter.Consume("principal:tool", 2); !refreshed.Allowed {
		t.Fatalf("reset = %#v", refreshed)
	}
	if _, err := NewTokenBucketRateLimiter(RateLimitOptions{}); err == nil {
		t.Fatal("expected an error for a zero limit")
	}
	if !(UnlimitedRateLimiter{}).Consume("x", 100).Allowed {
		t.Fatal("unlimited limiter rejected a call")
	}
}

func TestMemoryIdempotencyStore(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryIdempotencyStore(MemoryIdempotencyStoreOptions{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	store.Set(IdempotencyRecord{Key: "k1", Value: map[string]any{"ok": true}})
	record, ok := store.Get("k1")
	if !ok || record.Key != "k1" {
		t.Fatalf("record = %#v, ok = %v", record, ok)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.Get("k1"); ok {
		t.Fatal("expired record was returned")
	}
	store.Set(IdempotencyRecord{Key: "k2", Value: 1})
	if store.Size() != 1 {
		t.Fatalf("size = %d", store.Size())
	}
	store.Delete("k2")
	if _, ok := store.Get("k2"); ok {
		t.Fatal("delete failed")
	}
}

func TestCallStore(t *testing.T) {
	store := NewCallStore(2)
	store.Put(CallRecord{ID: "1", Action: "a.b", PrincipalID: "usr_1", Status: CallStatusSuccess})
	store.Put(CallRecord{ID: "2", Action: "a.b", PrincipalID: "usr_2", Status: CallStatusError})
	store.Put(CallRecord{ID: "3", Action: "c.d", PrincipalID: "usr_1", Status: CallStatusSuccess})
	if store.Size() != 2 {
		t.Fatalf("size = %d", store.Size())
	}
	if _, ok := store.Get("1"); ok {
		t.Fatal("oldest record was not evicted")
	}
	records := store.List(nil)
	if len(records) != 2 || records[0].ID != "3" {
		t.Fatalf("records = %#v", records)
	}
	filtered := store.List(&CallFilter{PrincipalID: "usr_1", Status: []CallStatus{CallStatusSuccess}})
	if len(filtered) != 1 || filtered[0].ID != "3" {
		t.Fatalf("filtered = %#v", filtered)
	}
	store.Put(CallRecord{ID: "2", Action: "a.b", PrincipalID: "usr_2", Status: CallStatusSuccess})
	updated, ok := store.Get("2")
	if !ok || updated.Status != CallStatusSuccess {
		t.Fatalf("upsert = %#v", updated)
	}
	if !store.MarkUndone("2", "undo-1", time.Now()) {
		t.Fatal("MarkUndone failed")
	}
	updated, _ = store.Get("2")
	if updated.UndoneAt == nil || updated.UndoReceiptID != "undo-1" {
		t.Fatalf("updated = %#v", updated)
	}
}

func TestCreateIDAndRandomBase64(t *testing.T) {
	first := CreateID("apr")
	second := CreateID("apr")
	if first == second || !strings.HasPrefix(first, "apr_") {
		t.Fatalf("ids = %q, %q", first, second)
	}
	if RandomBase64(8) == RandomBase64(8) {
		t.Fatal("random values repeated")
	}
	if FormatDuration(1500*time.Millisecond) != "1.5s" {
		t.Fatalf("duration = %q", FormatDuration(1500*time.Millisecond))
	}
}
