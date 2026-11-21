package gap

import (
	"sort"
	"sync"
	"time"
)

// IdempotencyRecord is a cached tool result.
type IdempotencyRecord struct {
	Key       string    `json:"key"`
	Value     any       `json:"value"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// IdempotencyStore caches completed results so retries return the original
// response instead of executing twice.
type IdempotencyStore interface {
	Get(string) (*IdempotencyRecord, bool)
	Set(IdempotencyRecord)
	Delete(string)
}

// MemoryIdempotencyStoreOptions configures MemoryIdempotencyStore.
type MemoryIdempotencyStoreOptions struct {
	TTL        time.Duration
	Now        func() time.Time
	MaxEntries int
}

// MemoryIdempotencyStore is an in-memory, concurrency-safe IdempotencyStore.
type MemoryIdempotencyStore struct {
	mu         sync.Mutex
	records    map[string]IdempotencyRecord
	ttl        time.Duration
	now        func() time.Time
	maxEntries int
}

// NewMemoryIdempotencyStore builds a store. The default TTL is ten minutes.
func NewMemoryIdempotencyStore(options ...MemoryIdempotencyStoreOptions) *MemoryIdempotencyStore {
	opts := MemoryIdempotencyStoreOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	return &MemoryIdempotencyStore{records: make(map[string]IdempotencyRecord), ttl: ttl, now: now, maxEntries: maxEntries}
}

// Get implements IdempotencyStore.
func (s *MemoryIdempotencyStore) Get(key string) (*IdempotencyRecord, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	if !ok {
		return nil, false
	}
	if !record.ExpiresAt.After(s.now()) {
		delete(s.records, key)
		return nil, false
	}
	copy := record
	return &copy, true
}

// Set implements IdempotencyStore.
func (s *MemoryIdempotencyStore) Set(record IdempotencyRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.CreatedAt.Add(s.ttl)
	}
	if !record.ExpiresAt.After(now) {
		return
	}
	s.records[record.Key] = record
	s.pruneLocked(now)
}

// Delete implements IdempotencyStore.
func (s *MemoryIdempotencyStore) Delete(key string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key)
}

// Clear removes every record.
func (s *MemoryIdempotencyStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make(map[string]IdempotencyRecord)
}

// Size returns the number of retained, unexpired records.
func (s *MemoryIdempotencyStore) Size() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	return len(s.records)
}

func (s *MemoryIdempotencyStore) pruneLocked(now time.Time) {
	for key, record := range s.records {
		if !record.ExpiresAt.After(now) {
			delete(s.records, key)
		}
	}
	if len(s.records) <= s.maxEntries {
		return
	}
	records := make([]IdempotencyRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.Before(records[j].CreatedAt) })
	for _, record := range records {
		if len(s.records) <= s.maxEntries {
			break
		}
		delete(s.records, record.Key)
	}
}

var _ IdempotencyStore = (*MemoryIdempotencyStore)(nil)
