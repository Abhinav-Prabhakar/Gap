package gap

import (
	"strings"
	"testing"
	"time"
)

func TestHMACApprovalGateTable(t *testing.T) {
	gate, err := NewHMACApprovalGate(HmacApprovalGateOptions{Secret: "approval-secret"})
	if err != nil {
		t.Fatal(err)
	}
	request := ApprovalRequest{
		Action:      "invoices.create",
		Args:        map[string]any{"customer": "cus_1", "total": 1200},
		PrincipalID: "usr_1",
	}
	issued, err := gate.Issue(request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(issued.Token, "v1.") {
		t.Fatalf("token = %q", issued.Token)
	}

	verifyRequest := request
	if grant, err := gate.Verify(issued.Token, verifyRequest); err != nil || grant == nil {
		t.Fatalf("Verify = %#v, %v", grant, err)
	}
	if grant, _ := gate.Verify(issued.Token, ApprovalRequest{Action: "invoices.delete", Args: request.Args, PrincipalID: "usr_1"}); grant != nil {
		t.Fatal("token verified for a different action")
	}
	if grant, _ := gate.Verify(issued.Token, ApprovalRequest{Action: request.Action, Args: map[string]any{"total": 9999}, PrincipalID: "usr_1"}); grant != nil {
		t.Fatal("token verified for different arguments")
	}
	if grant, _ := gate.Verify(issued.Token, ApprovalRequest{Action: request.Action, Args: request.Args, PrincipalID: "usr_2"}); grant != nil {
		t.Fatal("token verified for a different principal")
	}
	tampered := tamperToken(issued.Token)
	if grant, _ := gate.Verify(tampered, verifyRequest); grant != nil {
		t.Fatal("tampered token verified")
	}
	for _, malformed := range []string{"", "v1", "v2.abc.def", "v1..", "v1.abc.", "not-a-token"} {
		if grant, _ := gate.Verify(malformed, verifyRequest); grant != nil {
			t.Fatalf("malformed token %q verified", malformed)
		}
	}
}

func TestHMACApprovalExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gate, err := NewHMACApprovalGate(HmacApprovalGateOptions{
		Secret: "secret",
		TTL:    time.Minute,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ApprovalRequest{Action: "a.b", Args: map[string]any{"x": 1}, PrincipalID: "usr_1"}
	issued, err := gate.Issue(request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if grant, _ := gate.Verify(issued.Token, request); grant != nil {
		t.Fatal("expired token verified")
	}
}

func TestHMACApprovalRequiresSecret(t *testing.T) {
	if _, err := NewHMACApprovalGate(HmacApprovalGateOptions{Secret: " "}); err == nil {
		t.Fatal("expected an error for an empty secret")
	}
}

func TestMemoryApprovalStoreLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryApprovalStore(MemoryApprovalStoreOptions{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	first, err := store.Create(CreateApprovalInput{
		PrincipalID: "usr_1",
		Action:      "invoices.create",
		ArgsHash:    "hash-1",
		Args:        map[string]any{"total": 10},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if first.Status != ApprovalPending {
		t.Fatalf("status = %s", first.Status)
	}
	if !strings.HasPrefix(first.ID, "apr_") {
		t.Fatalf("id = %q", first.ID)
	}
	second, err := store.Create(CreateApprovalInput{
		PrincipalID: "usr_1",
		Action:      "invoices.create",
		ArgsHash:    "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate approval was created: %s != %s", second.ID, first.ID)
	}

	approved, err := store.Approve(first.ID, ResolveApprovalOptions{Actor: "admin"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.Status != ApprovalApproved || approved.ApprovedBy != "admin" || approved.ApprovedAt == nil {
		t.Fatalf("approved = %#v", approved)
	}
	consumed, err := store.Consume(first.ID)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.Status != ApprovalConsumed || consumed.ConsumedAt == nil {
		t.Fatalf("consumed = %#v", consumed)
	}
	if _, err := store.Consume(first.ID); !IsCode(err, CodeConflict) {
		t.Fatalf("second consume err = %v", err)
	}
	if _, err := store.Approve("apr_missing", ResolveApprovalOptions{}); !IsCode(err, CodeNotFound) {
		t.Fatalf("missing approve err = %v", err)
	}
}

func TestMemoryApprovalStoreDenyAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryApprovalStore(MemoryApprovalStoreOptions{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	record, err := store.Create(CreateApprovalInput{
		PrincipalID: "usr_1",
		Action:      "invoices.delete",
		ArgsHash:    "hash-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := store.Deny(record.ID, ResolveApprovalOptions{Actor: "admin", Reason: "no"})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != ApprovalDenied || denied.Reason != "no" {
		t.Fatalf("denied = %#v", denied)
	}
	if _, err := store.Approve(record.ID, ResolveApprovalOptions{}); !IsCode(err, CodeConflict) {
		t.Fatalf("approve denied err = %v", err)
	}

	pending, err := store.Create(CreateApprovalInput{
		PrincipalID: "usr_2",
		Action:      "invoices.create",
		ArgsHash:    "hash-3",
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	expired, ok := store.Get(pending.ID)
	if !ok {
		t.Fatal("record disappeared")
	}
	if expired.Status != ApprovalExpired {
		t.Fatalf("status = %s", expired.Status)
	}
	if _, err := store.Approve(pending.ID, ResolveApprovalOptions{}); !IsCode(err, CodeConflict) {
		t.Fatalf("expired approve err = %v", err)
	}
}

func TestMemoryApprovalStoreListFilters(t *testing.T) {
	store := NewMemoryApprovalStore(MemoryApprovalStoreOptions{})
	_, _ = store.Create(CreateApprovalInput{PrincipalID: "usr_1", Action: "a.b", ArgsHash: "1"})
	_, _ = store.Create(CreateApprovalInput{PrincipalID: "usr_2", Action: "a.b", ArgsHash: "1"})
	_, _ = store.Create(CreateApprovalInput{PrincipalID: "usr_1", Action: "c.d", ArgsHash: "2"})

	all := store.List(nil)
	if len(all) != 3 {
		t.Fatalf("all = %d", len(all))
	}
	filtered := store.List(&ApprovalFilter{PrincipalID: "usr_1"})
	if len(filtered) != 2 {
		t.Fatalf("filtered = %d", len(filtered))
	}
	byAction := store.List(&ApprovalFilter{Action: "c.d"})
	if len(byAction) != 1 || byAction[0].Action != "c.d" {
		t.Fatalf("byAction = %#v", byAction)
	}
}

func tamperToken(token string) string {
	dot := strings.LastIndex(token, ".")
	if dot < 0 || dot+1 >= len(token) {
		return token + "A"
	}
	index := dot + 1
	replacement := byte('A')
	if token[index] == 'A' {
		replacement = 'B'
	}
	return token[:index] + string(replacement) + token[index+1:]
}
