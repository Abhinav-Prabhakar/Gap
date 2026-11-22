package gap

import (
	"sync"
	"time"
)

// CallStatus is the terminal (or in-progress) state of one tool invocation.
type CallStatus string

const (
	CallStatusSuccess          CallStatus = "success"
	CallStatusError            CallStatus = "error"
	CallStatusApprovalRequired CallStatus = "approval_required"
	CallStatusTask             CallStatus = "task"
	CallStatusDryRun           CallStatus = "dry_run"
)

// CallError is the safe error representation stored on a call record.
type CallError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// CallReceipt is the audit/UI receipt for a completed invocation.
type CallReceipt struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	PrincipalID string    `json:"principalId"`
	TenantID    string    `json:"tenantId,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	DurationMS  int64     `json:"durationMs"`
	ArgsHash    string    `json:"argsHash"`
	ResultHash  string    `json:"resultHash"`
	Undoable    bool      `json:"undoable"`
	DryRun      bool      `json:"dryRun,omitempty"`
	ApprovalID  string    `json:"approvalId,omitempty"`
	TraceID     string    `json:"traceId"`
	UndoOf      string    `json:"undoOf,omitempty"`
}

// CallRecord is one invocation kept for inspectors and receipts.
type CallRecord struct {
	ID             string         `json:"id"`
	Timestamp      time.Time      `json:"timestamp"`
	Action         string         `json:"action"`
	PrincipalID    string         `json:"principalId"`
	TenantID       string         `json:"tenantId,omitempty"`
	Status         CallStatus     `json:"status"`
	Args           any            `json:"args,omitempty"`
	Result         any            `json:"result,omitempty"`
	RedactedResult any            `json:"redactedResult,omitempty"`
	Error          *CallError     `json:"error,omitempty"`
	DurationMS     int64          `json:"durationMs"`
	Receipt        *CallReceipt   `json:"receipt,omitempty"`
	Approval       *ApprovalGrant `json:"approval,omitempty"`
	ApprovalID     string         `json:"approvalId,omitempty"`
	TraceID        string         `json:"traceId"`
	TaskID         string         `json:"taskId,omitempty"`
	Replayed       bool           `json:"replayed,omitempty"`
	UndoneAt       *time.Time     `json:"undoneAt,omitempty"`
	UndoReceiptID  string         `json:"undoReceiptId,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// CallFilter narrows CallStore.List.
type CallFilter struct {
	Limit       int
	PrincipalID string
	Action      string
	Status      []CallStatus
}

// CallStore is a fixed-size, id-upserting ring buffer of tool calls.
type CallStore struct {
	mu    sync.Mutex
	limit int
	items []*CallRecord
	byID  map[string]*CallRecord
}

// NewCallStore builds a call store. A non-positive limit uses 500.
func NewCallStore(limit int) *CallStore {
	if limit <= 0 {
		limit = 500
	}
	return &CallStore{limit: limit, byID: make(map[string]*CallRecord)}
}

// Limit returns the retention limit.
func (s *CallStore) Limit() int {
	if s == nil {
		return 0
	}
	return s.limit
}

// Size returns the number of retained calls.
func (s *CallStore) Size() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Put inserts or replaces a call, keeping its original position on replace.
func (s *CallStore) Put(record CallRecord) *CallRecord {
	if s == nil {
		return nil
	}
	copy := cloneCallRecord(&record)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byID[copy.ID]; ok {
		for index, item := range s.items {
			if item == existing {
				s.items[index] = copy
				break
			}
		}
		s.byID[copy.ID] = copy
		return cloneCallRecord(copy)
	}
	s.items = append(s.items, copy)
	s.byID[copy.ID] = copy
	for len(s.items) > s.limit {
		removed := s.items[0]
		s.items = s.items[1:]
		if removed != nil {
			delete(s.byID, removed.ID)
		}
	}
	return cloneCallRecord(copy)
}

// Get returns a call copy.
func (s *CallStore) Get(id string) (*CallRecord, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return cloneCallRecord(record), true
}

// List returns calls newest first.
func (s *CallStore) List(filter *CallFilter) []*CallRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	records := make([]*CallRecord, 0, len(s.items))
	for index := len(s.items) - 1; index >= 0; index-- {
		records = append(records, cloneCallRecord(s.items[index]))
	}
	s.mu.Unlock()

	var statuses map[CallStatus]struct{}
	if filter != nil && len(filter.Status) > 0 {
		statuses = make(map[CallStatus]struct{}, len(filter.Status))
		for _, status := range filter.Status {
			statuses[status] = struct{}{}
		}
	}
	out := make([]*CallRecord, 0, len(records))
	for _, record := range records {
		if filter != nil {
			if filter.PrincipalID != "" && record.PrincipalID != filter.PrincipalID {
				continue
			}
			if filter.Action != "" && record.Action != filter.Action {
				continue
			}
			if statuses != nil {
				if _, ok := statuses[record.Status]; !ok {
					continue
				}
			}
		}
		out = append(out, record)
		if filter != nil && filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out
}

// MarkUndone records that a receipt was undone by another receipt.
func (s *CallStore) MarkUndone(id, undoReceiptID string, at time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return false
	}
	record.UndoneAt = &at
	record.UndoReceiptID = undoReceiptID
	return true
}

// Clear removes every call.
func (s *CallStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = nil
	s.byID = make(map[string]*CallRecord)
}

func cloneCallRecord(record *CallRecord) *CallRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.Args = cloneJSONValue(record.Args)
	copy.Result = cloneJSONValue(record.Result)
	copy.RedactedResult = cloneJSONValue(record.RedactedResult)
	copy.Metadata = cloneMap(record.Metadata)
	if record.Receipt != nil {
		receipt := *record.Receipt
		copy.Receipt = &receipt
	}
	if record.Approval != nil {
		approval := *record.Approval
		copy.Approval = &approval
	}
	if record.Error != nil {
		callError := *record.Error
		callError.Details = cloneJSONValue(record.Error.Details)
		copy.Error = &callError
	}
	if record.UndoneAt != nil {
		at := *record.UndoneAt
		copy.UndoneAt = &at
	}
	return &copy
}
