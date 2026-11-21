package gap

import (
	"context"
	"sort"
	"sync"
	"time"
)

// TaskStatus is the lifecycle of a background task.
type TaskStatus string

const (
	TaskWorking   TaskStatus = "working"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

// TaskError is the safe error stored on a failed task.
type TaskError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// TaskRecord is a background action invocation created by an action with
// Task: true.
type TaskRecord struct {
	ID          string       `json:"id"`
	Action      string       `json:"action"`
	PrincipalID string       `json:"principalId"`
	TenantID    string       `json:"tenantId,omitempty"`
	Status      TaskStatus   `json:"status"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
	Input       any          `json:"input,omitempty"`
	Result      any          `json:"result,omitempty"`
	Error       *TaskError   `json:"error,omitempty"`
	Receipt     *CallReceipt `json:"receipt,omitempty"`
	TraceID     string       `json:"traceId"`
	ApprovalID  string       `json:"approvalId,omitempty"`
	CallID      string       `json:"callId,omitempty"`
}

// TaskRun is the work a task performs.
type TaskRun func(ctx context.Context) (any, *CallReceipt, error)

// TaskFilter narrows TaskManager.List.
type TaskFilter struct {
	PrincipalID string
	Action      string
	Status      []TaskStatus
}

type taskEntry struct {
	record  *TaskRecord
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
}

// TaskManager owns background executions. It is safe for concurrent use.
type TaskManager struct {
	mu        sync.Mutex
	tasks     map[string]*taskEntry
	order     []string
	maxTasks  int
	closed    bool
	now       func() time.Time
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewTaskManager builds a task manager. maxTasks <= 0 uses 1000.
func NewTaskManager(maxTasks int) *TaskManager {
	if maxTasks <= 0 {
		maxTasks = 1000
	}
	return &TaskManager{tasks: make(map[string]*taskEntry), maxTasks: maxTasks, now: time.Now}
}

// Size returns the number of retained tasks.
func (m *TaskManager) Size() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tasks)
}

// Start registers and starts a task. The returned record is a snapshot.
func (m *TaskManager) Start(record TaskRecord, run TaskRun) (*TaskRecord, error) {
	if m == nil {
		return nil, Internal("Task manager is nil.", nil)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, UnavailableError("Task manager is closed.")
	}
	now := m.now()
	if record.ID == "" {
		record.ID = CreateID("task")
	}
	record.Status = TaskWorking
	record.CreatedAt = now
	record.UpdatedAt = now
	ctx, cancel := context.WithCancel(context.Background())
	entry := &taskEntry{record: &record, cancel: cancel, done: make(chan struct{})}
	m.tasks[record.ID] = entry
	m.order = append(m.order, record.ID)
	m.pruneLocked(now)
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		defer close(entry.done)
		result, receipt, err := run(ctx)
		m.mu.Lock()
		defer m.mu.Unlock()
		if entry.record.Status == TaskCancelled || ctx.Err() != nil {
			entry.record.Status = TaskCancelled
			entry.record.UpdatedAt = m.now()
			return
		}
		entry.record.UpdatedAt = m.now()
		if err != nil {
			entry.record.Status = TaskFailed
			normalized := Normalize(err)
			entry.record.Error = &TaskError{Code: normalized.Code, Message: normalized.PublicMessage()}
			return
		}
		entry.record.Status = TaskCompleted
		entry.record.Result = cloneJSONValue(result)
		entry.record.Receipt = receipt
	}()

	m.mu.Lock()
	snapshot := cloneTaskRecord(entry.record)
	m.mu.Unlock()
	return snapshot, nil
}

// Get returns a task copy.
func (m *TaskManager) Get(id string) (*TaskRecord, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.tasks[id]
	if !ok {
		return nil, false
	}
	return cloneTaskRecord(entry.record), true
}

// List returns retained tasks newest first.
func (m *TaskManager) List(filter *TaskFilter) []*TaskRecord {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]*TaskRecord, 0, len(m.tasks))
	var statuses map[TaskStatus]struct{}
	if filter != nil && len(filter.Status) > 0 {
		statuses = make(map[TaskStatus]struct{}, len(filter.Status))
		for _, status := range filter.Status {
			statuses[status] = struct{}{}
		}
	}
	for _, entry := range m.tasks {
		record := entry.record
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
		out = append(out, cloneTaskRecord(record))
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Cancel aborts a running task. Cancelling a terminal task is a no-op.
func (m *TaskManager) Cancel(id string) (*TaskRecord, error) {
	if m == nil {
		return nil, Internal("Task manager is nil.", nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.tasks[id]
	if !ok {
		return nil, NotFound("Task not found.")
	}
	if entry.record.Status == TaskWorking {
		entry.cancel()
		entry.record.Status = TaskCancelled
		entry.record.UpdatedAt = m.now()
	}
	return cloneTaskRecord(entry.record), nil
}

// Wait waits for one task to settle or ctx to end.
func (m *TaskManager) Wait(ctx context.Context, id string) error {
	if m == nil {
		return Internal("Task manager is nil.", nil)
	}
	m.mu.Lock()
	entry, ok := m.tasks[id]
	m.mu.Unlock()
	if !ok {
		return NotFound("Task not found.")
	}
	select {
	case <-entry.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close aborts every running task and waits up to ctx for them to settle.
func (m *TaskManager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		for _, entry := range m.tasks {
			if entry.record.Status == TaskWorking {
				entry.cancel()
				entry.record.Status = TaskCancelled
				entry.record.UpdatedAt = m.now()
			}
		}
		m.mu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *TaskManager) pruneLocked(now time.Time) {
	if len(m.tasks) <= m.maxTasks {
		return
	}
	terminal := make([]*TaskRecord, 0)
	for _, entry := range m.tasks {
		if entry.record.Status == TaskCompleted || entry.record.Status == TaskFailed || entry.record.Status == TaskCancelled {
			terminal = append(terminal, entry.record)
		}
	}
	sort.Slice(terminal, func(i, j int) bool { return terminal[i].CreatedAt.Before(terminal[j].CreatedAt) })
	for _, record := range terminal {
		if len(m.tasks) <= m.maxTasks {
			break
		}
		entry := m.tasks[record.ID]
		if entry != nil {
			entry.cancel()
		}
		delete(m.tasks, record.ID)
	}
}

func cloneTaskRecord(record *TaskRecord) *TaskRecord {
	if record == nil {
		return nil
	}
	copy := *record
	copy.Input = cloneJSONValue(record.Input)
	copy.Result = cloneJSONValue(record.Result)
	if record.Receipt != nil {
		receipt := *record.Receipt
		copy.Receipt = &receipt
	}
	if record.Error != nil {
		taskError := *record.Error
		copy.Error = &taskError
	}
	return &copy
}
