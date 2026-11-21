package gap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NewAuditEvent fills the generated fields of an audit event.
func NewAuditEvent(event AuditEvent) AuditEvent {
	if event.ID == "" {
		event.ID = CreateID("audit")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event
}

// MemoryAuditLogOptions bounds the in-memory audit log.
type MemoryAuditLogOptions struct {
	// Max keeps only the newest Max events. Zero is unbounded.
	Max int
	// Now is an injectable clock used for events without a timestamp.
	Now func() time.Time
}

// MemoryAuditLog is a concurrency-safe in-memory AuditSink.
type MemoryAuditLog struct {
	mu     sync.Mutex
	events []AuditEvent
	max    int
}

// NewMemoryAuditLog builds an in-memory audit sink.
func NewMemoryAuditLog(options ...MemoryAuditLogOptions) *MemoryAuditLog {
	opts := MemoryAuditLogOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	return &MemoryAuditLog{max: opts.Max}
}

// Record implements AuditSink. Events are cloned so callers cannot mutate the
// stored history.
func (l *MemoryAuditLog) Record(_ context.Context, event AuditEvent) error {
	if l == nil {
		return nil
	}
	event = cloneAuditEvent(NewAuditEvent(event))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max == 0 {
		return nil
	}
	l.events = append(l.events, event)
	if l.max > 0 && len(l.events) > l.max {
		l.events = append([]AuditEvent(nil), l.events[len(l.events)-l.max:]...)
	}
	return nil
}

// List returns a snapshot oldest first.
func (l *MemoryAuditLog) List() []AuditEvent {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditEvent, len(l.events))
	copy(out, l.events)
	return out
}

// Clear removes every event.
func (l *MemoryAuditLog) Clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
}

func cloneAuditEvent(event AuditEvent) AuditEvent {
	event.Scopes = append([]string(nil), event.Scopes...)
	event.Metadata = cloneMap(event.Metadata)
	if event.Error != nil {
		copy := *event.Error
		event.Error = &copy
	}
	return event
}

// JSONLAuditLog appends one JSON object per line to a file with owner-only
// permissions. Writes are serialized.
type JSONLAuditLog struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	closed bool
}

// NewJSONLAuditLog opens (or creates) a JSON Lines audit log. Parent
// directories are created with 0755 and the file is mode 0600.
func NewJSONLAuditLog(path string) (*JSONLAuditLog, error) {
	if path == "" {
		return nil, InvalidInput("Audit log path must not be empty.", nil)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, WrapError(err, "Failed to create the audit log directory.", CodeInternal)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, WrapError(err, "Failed to open the audit log.", CodeInternal)
	}
	return &JSONLAuditLog{file: file, path: path}, nil
}

// Record implements AuditSink.
func (l *JSONLAuditLog) Record(_ context.Context, event AuditEvent) error {
	if l == nil {
		return nil
	}
	event = cloneAuditEvent(NewAuditEvent(event))
	line, err := json.Marshal(event)
	if err != nil {
		return WrapError(err, "Audit event is not JSON-serializable.", CodeInvalidInput)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Internal("Audit log is closed.", nil)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return WrapError(err, "Failed to write the audit log.", CodeInternal)
	}
	return nil
}

// Path returns the configured file path.
func (l *JSONLAuditLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close flushes and closes the file. It is safe to call more than once.
func (l *JSONLAuditLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if err := l.file.Sync(); err != nil {
		_ = l.file.Close()
		return WrapError(err, "Failed to flush the audit log.", CodeInternal)
	}
	if err := l.file.Close(); err != nil {
		return WrapError(err, "Failed to close the audit log.", CodeInternal)
	}
	return nil
}

// Compile-time assertions.
var _ AuditSink = (*MemoryAuditLog)(nil)
var _ AuditSink = (*JSONLAuditLog)(nil)
