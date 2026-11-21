package gap

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ApprovalStatus is the lifecycle of a human approval request.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalConsumed ApprovalStatus = "consumed"
	ApprovalExpired  ApprovalStatus = "expired"
)

// ApprovalRecord is one stored approval request. Records are deduplicated by
// (principalId, action, argsHash) while pending or approved.
type ApprovalRecord struct {
	ID          string         `json:"id"`
	PrincipalID string         `json:"principalId"`
	Action      string         `json:"action"`
	ArgsHash    string         `json:"argsHash"`
	Status      ApprovalStatus `json:"status"`
	CreatedAt   time.Time      `json:"createdAt"`
	ExpiresAt   time.Time      `json:"expiresAt"`
	Args        any            `json:"args,omitempty"`
	ApprovedAt  *time.Time     `json:"approvedAt,omitempty"`
	ApprovedBy  string         `json:"approvedBy,omitempty"`
	DeniedAt    *time.Time     `json:"deniedAt,omitempty"`
	DeniedBy    string         `json:"deniedBy,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	ConsumedAt  *time.Time     `json:"consumedAt,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// CreateApprovalInput is accepted by ApprovalStore.Create.
type CreateApprovalInput struct {
	PrincipalID string
	Action      string
	ArgsHash    string
	Args        any
	TTL         time.Duration
	Metadata    map[string]any
}

// ApprovalFilter narrows ApprovalStore.List.
type ApprovalFilter struct {
	PrincipalID string
	Action      string
	ArgsHash    string
	Status      []ApprovalStatus
}

// ResolveApprovalOptions identifies the human approving or denying a request.
type ResolveApprovalOptions struct {
	Actor  string
	Reason string
}

// ApprovalStore stores pending and resolved approvals.
type ApprovalStore interface {
	Create(CreateApprovalInput) (*ApprovalRecord, error)
	Get(string) (*ApprovalRecord, bool)
	List(*ApprovalFilter) []*ApprovalRecord
	Approve(string, ResolveApprovalOptions) (*ApprovalRecord, error)
	Deny(string, ResolveApprovalOptions) (*ApprovalRecord, error)
	Consume(string) (*ApprovalRecord, error)
}

// MemoryApprovalStoreOptions configures MemoryApprovalStore.
type MemoryApprovalStoreOptions struct {
	// TTL is the default lifetime for pending approvals (5 minutes).
	TTL time.Duration
	// Now is an injectable clock. Defaults to time.Now.
	Now func() time.Time
	// MaxEntries bounds retained records (2000). Terminal records are evicted
	// first.
	MaxEntries int
	// ClearOnExpire retains expired records for inspection when false. Records
	// still cannot be approved or consumed after expiry.
}

// MemoryApprovalStore is an in-memory ApprovalStore safe for concurrent use.
type MemoryApprovalStore struct {
	mu         sync.Mutex
	records    map[string]*ApprovalRecord
	ttl        time.Duration
	now        func() time.Time
	maxEntries int
}

// NewMemoryApprovalStore builds an in-memory approval store.
func NewMemoryApprovalStore(options MemoryApprovalStoreOptions) *MemoryApprovalStore {
	ttl := options.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	maxEntries := options.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 2000
	}
	return &MemoryApprovalStore{records: make(map[string]*ApprovalRecord), ttl: ttl, now: now, maxEntries: maxEntries}
}

// Size returns the number of retained records including terminal records.
func (s *MemoryApprovalStore) Size() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Clear removes every record.
func (s *MemoryApprovalStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make(map[string]*ApprovalRecord)
}

// Create implements ApprovalStore.
func (s *MemoryApprovalStore) Create(input CreateApprovalInput) (*ApprovalRecord, error) {
	if s == nil {
		return nil, Internal("Approval store is nil.", nil)
	}
	if strings.TrimSpace(input.PrincipalID) == "" || strings.TrimSpace(input.Action) == "" || strings.TrimSpace(input.ArgsHash) == "" {
		return nil, InvalidInput("Approval requires a principal, action and args hash.", nil)
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	for _, record := range s.records {
		if record.PrincipalID == input.PrincipalID && record.Action == input.Action && record.ArgsHash == input.ArgsHash &&
			(record.Status == ApprovalPending || record.Status == ApprovalApproved) && record.ExpiresAt.After(now) {
			return cloneApprovalRecord(record), nil
		}
	}
	ttl := input.TTL
	if ttl <= 0 {
		ttl = s.ttl
	}
	if ttl <= 0 {
		return nil, InvalidInput("Approval ttl must be positive.", nil)
	}
	record := &ApprovalRecord{
		ID:          CreateID("apr"),
		PrincipalID: input.PrincipalID,
		Action:      input.Action,
		ArgsHash:    input.ArgsHash,
		Status:      ApprovalPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		Args:        cloneJSONValue(input.Args),
		Metadata:    cloneMap(input.Metadata),
	}
	s.records[record.ID] = record
	s.pruneLocked()
	return cloneApprovalRecord(record), nil
}

// Get implements ApprovalStore.
func (s *MemoryApprovalStore) Get(id string) (*ApprovalRecord, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	record, ok := s.records[id]
	if !ok {
		return nil, false
	}
	return cloneApprovalRecord(record), true
}

// List implements ApprovalStore. Records are sorted oldest first.
func (s *MemoryApprovalStore) List(filter *ApprovalFilter) []*ApprovalRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	statuses := make(map[ApprovalStatus]struct{})
	if filter != nil {
		for _, status := range filter.Status {
			statuses[status] = struct{}{}
		}
	}
	out := make([]*ApprovalRecord, 0, len(s.records))
	for _, record := range s.records {
		if filter != nil {
			if filter.PrincipalID != "" && record.PrincipalID != filter.PrincipalID {
				continue
			}
			if filter.Action != "" && record.Action != filter.Action {
				continue
			}
			if filter.ArgsHash != "" && record.ArgsHash != filter.ArgsHash {
				continue
			}
			if len(statuses) > 0 {
				if _, ok := statuses[record.Status]; !ok {
					continue
				}
			}
		}
		out = append(out, cloneApprovalRecord(record))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Approve implements ApprovalStore.
func (s *MemoryApprovalStore) Approve(id string, options ResolveApprovalOptions) (*ApprovalRecord, error) {
	return s.resolve(id, true, options)
}

// Deny implements ApprovalStore.
func (s *MemoryApprovalStore) Deny(id string, options ResolveApprovalOptions) (*ApprovalRecord, error) {
	return s.resolve(id, false, options)
}

func (s *MemoryApprovalStore) resolve(id string, approve bool, options ResolveApprovalOptions) (*ApprovalRecord, error) {
	if s == nil {
		return nil, Internal("Approval store is nil.", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	record, ok := s.records[id]
	if !ok {
		return nil, NotFound("Approval not found.").WithDetails(map[string]any{"approvalId": id})
	}
	switch record.Status {
	case ApprovalExpired:
		return nil, Conflict("This approval request has expired.", map[string]any{"approvalId": id})
	case ApprovalConsumed:
		return nil, Conflict("This approval has already been consumed.", map[string]any{"approvalId": id})
	case ApprovalDenied:
		if approve {
			return nil, Conflict("This approval was denied.", map[string]any{"approvalId": id})
		}
	case ApprovalApproved:
		if !approve {
			return nil, Conflict("This approval was already approved.", map[string]any{"approvalId": id})
		}
	case ApprovalPending:
		actor := options.Actor
		if actor == "" {
			actor = "unknown"
		}
		if approve {
			record.Status = ApprovalApproved
			record.ApprovedAt = &now
			record.ApprovedBy = actor
		} else {
			record.Status = ApprovalDenied
			record.DeniedAt = &now
			record.DeniedBy = actor
			record.Reason = options.Reason
		}
	}
	return cloneApprovalRecord(record), nil
}

// Consume atomically transition an approved request to consumed. Only one
// caller can consume a given approval.
func (s *MemoryApprovalStore) Consume(id string) (*ApprovalRecord, error) {
	if s == nil {
		return nil, Internal("Approval store is nil.", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	record, ok := s.records[id]
	if !ok {
		return nil, NotFound("Approval not found.").WithDetails(map[string]any{"approvalId": id})
	}
	if record.Status != ApprovalApproved {
		message := fmt.Sprintf("This approval cannot be consumed while it is %s.", record.Status)
		if record.Status == ApprovalPending {
			message = "This approval has not been granted yet."
		}
		return nil, Conflict(message, map[string]any{"approvalId": id, "status": record.Status})
	}
	if !record.ExpiresAt.After(now) {
		record.Status = ApprovalExpired
		return nil, Conflict("This approval request has expired.", map[string]any{"approvalId": id})
	}
	record.Status = ApprovalConsumed
	record.ConsumedAt = &now
	return cloneApprovalRecord(record), nil
}

func (s *MemoryApprovalStore) expireLocked(now time.Time) {
	for _, record := range s.records {
		if (record.Status == ApprovalPending || record.Status == ApprovalApproved) && !record.ExpiresAt.After(now) {
			record.Status = ApprovalExpired
		}
	}
}

func (s *MemoryApprovalStore) pruneLocked() {
	if len(s.records) <= s.maxEntries {
		return
	}
	terminal := make([]*ApprovalRecord, 0)
	for _, record := range s.records {
		if record.Status == ApprovalConsumed || record.Status == ApprovalDenied || record.Status == ApprovalExpired {
			terminal = append(terminal, record)
		}
	}
	sort.Slice(terminal, func(i, j int) bool { return terminal[i].CreatedAt.Before(terminal[j].CreatedAt) })
	for _, record := range terminal {
		if len(s.records) <= s.maxEntries {
			break
		}
		delete(s.records, record.ID)
	}
}

func cloneApprovalRecord(record *ApprovalRecord) *ApprovalRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.Args = cloneJSONValue(record.Args)
	copy.Metadata = cloneMap(record.Metadata)
	if record.ApprovedAt != nil {
		value := *record.ApprovedAt
		copy.ApprovedAt = &value
	}
	if record.DeniedAt != nil {
		value := *record.DeniedAt
		copy.DeniedAt = &value
	}
	if record.ConsumedAt != nil {
		value := *record.ConsumedAt
		copy.ConsumedAt = &value
	}
	return &copy
}

func cloneMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = cloneJSONValue(value)
	}
	return out
}

func cloneJSONValue(value any) any {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return value
	}
	return out
}

// HmacApprovalGateOptions configures HmacApprovalGate.
type HmacApprovalGateOptions struct {
	// Secret signs tokens. It must not be empty.
	Secret string
	// TTL is the default grant lifetime (10 minutes).
	TTL time.Duration
	// Now is an injectable clock.
	Now func() time.Time
}

// HmacApprovalGate issues compact v1.<payload>.<hmac> approval grants bound to
// the action, principal and canonical argument hash.
type HmacApprovalGate struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

type approvalTokenPayload struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	ArgsHash    string `json:"argsHash"`
	PrincipalID string `json:"principalId"`
	ApprovedBy  string `json:"approvedBy"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Nonce       string `json:"nonce"`
}

// NewHMACApprovalGate builds an HMAC approval gate.
func NewHMACApprovalGate(options HmacApprovalGateOptions) (*HmacApprovalGate, error) {
	if strings.TrimSpace(options.Secret) == "" {
		return nil, InvalidInput("Approval gate secret must not be empty.", nil)
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &HmacApprovalGate{secret: []byte(options.Secret), ttl: ttl, now: now}, nil
}

// Issue implements ApprovalGate.
func (g *HmacApprovalGate) Issue(request ApprovalRequest) (IssuedApproval, error) {
	if g == nil {
		return IssuedApproval{}, Internal("Approval gate is nil.", nil)
	}
	action := strings.TrimSpace(request.Action)
	principalID := strings.TrimSpace(request.PrincipalID)
	if action == "" || principalID == "" {
		return IssuedApproval{}, InvalidInput("Approval requires an action and principalId.", nil)
	}
	ttl := request.TTL
	if ttl <= 0 {
		ttl = g.ttl
	}
	if ttl <= 0 {
		return IssuedApproval{}, InvalidInput("Approval ttl must be positive.", nil)
	}
	argsHash, err := Hash(request.Args)
	if err != nil {
		return IssuedApproval{}, WrapError(err, "Approval arguments must be JSON-serializable.", CodeInvalidInput)
	}
	now := g.now()
	approvedBy := request.ApprovedBy
	if approvedBy == "" {
		approvedBy = principalID
	}
	payload := approvalTokenPayload{
		ID:          CreateID("apr"),
		Action:      action,
		ArgsHash:    argsHash,
		PrincipalID: principalID,
		ApprovedBy:  approvedBy,
		IssuedAt:    now.UnixMilli(),
		ExpiresAt:   now.Add(ttl).UnixMilli(),
		Nonce:       RandomBase64(16),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return IssuedApproval{}, WrapError(err, "Failed to encode approval.", CodeInternal)
	}
	segment := base64.RawURLEncoding.EncodeToString(raw)
	signature := g.sign(segment)
	return IssuedApproval{
		Token: "v1." + segment + "." + signature,
		Grant: ApprovalGrant{
			ID:         payload.ID,
			Action:     payload.Action,
			ArgsHash:   payload.ArgsHash,
			ApprovedBy: payload.ApprovedBy,
			IssuedAt:   payload.IssuedAt,
			ExpiresAt:  payload.ExpiresAt,
			Nonce:      payload.Nonce,
		},
	}, nil
}

// Verify implements ApprovalGate. It returns (nil, nil) for any malformed,
// tampered, expired or mismatched token.
func (g *HmacApprovalGate) Verify(token string, request ApprovalRequest) (*ApprovalGrant, error) {
	if g == nil {
		return nil, nil
	}
	if token == "" || len(token) > 8*1024 {
		return nil, nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return nil, nil
	}
	if len(parts[1]) > 4096 || len(parts[2]) > 128 {
		return nil, nil
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(provided) != sha256.Size {
		return nil, nil
	}
	expected := g.mac(parts[1])
	if subtle.ConstantTimeCompare(provided, expected) != 1 {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil
	}
	var payload approvalTokenPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil
	}
	if payload.ID == "" || payload.Action == "" || payload.ArgsHash == "" || payload.PrincipalID == "" || payload.Nonce == "" {
		return nil, nil
	}
	if payload.ExpiresAt <= payload.IssuedAt || g.now().UnixMilli() >= payload.ExpiresAt {
		return nil, nil
	}
	if payload.Action != request.Action || payload.PrincipalID != request.PrincipalID {
		return nil, nil
	}
	if request.ApprovedBy != "" && payload.ApprovedBy != request.ApprovedBy {
		return nil, nil
	}
	expectedHash, err := Hash(request.Args)
	if err != nil {
		return nil, nil
	}
	if subtle.ConstantTimeCompare([]byte(payload.ArgsHash), []byte(expectedHash)) != 1 {
		return nil, nil
	}
	return &ApprovalGrant{
		ID:         payload.ID,
		Action:     payload.Action,
		ArgsHash:   payload.ArgsHash,
		ApprovedBy: payload.ApprovedBy,
		IssuedAt:   payload.IssuedAt,
		ExpiresAt:  payload.ExpiresAt,
		Nonce:      payload.Nonce,
	}, nil
}

func (g *HmacApprovalGate) mac(segment string) []byte {
	h := hmac.New(sha256.New, g.secret)
	h.Write([]byte("v1."))
	h.Write([]byte(segment))
	return h.Sum(nil)
}

func (g *HmacApprovalGate) sign(segment string) string {
	return base64.RawURLEncoding.EncodeToString(g.mac(segment))
}

var _ ApprovalGate = (*HmacApprovalGate)(nil)
var _ ApprovalStore = (*MemoryApprovalStore)(nil)
