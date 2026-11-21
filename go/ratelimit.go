package gap

import (
	"math"
	"sync"
	"time"
)

// RateLimitResult is the outcome of one token-bucket accounting operation.
type RateLimitResult struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

// RateLimiter is a per-key limiter. The server keys calls by principal and tool
// so a noisy agent cannot starve other principals or tools.
type RateLimiter interface {
	Consume(key string, cost int) RateLimitResult
	Reset(key string)
}

// RateLimitOptions configures the built-in token bucket.
type RateLimitOptions struct {
	// Limit is the burst size and the number of calls allowed per window.
	Limit int
	// Window is the refill period.
	Window time.Duration
	// Now is an injectable clock.
	Now func() time.Time
}

type tokenBucket struct {
	tokens    float64
	updatedAt time.Time
}

// TokenBucketRateLimiter is a continuous-refill token bucket.
type TokenBucketRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	now      func() time.Time
	buckets  map[string]*tokenBucket
	maxKeys  int
}

// NewTokenBucketRateLimiter builds a limiter. Limit and Window must be
// positive.
func NewTokenBucketRateLimiter(options RateLimitOptions) (*TokenBucketRateLimiter, error) {
	if options.Limit <= 0 {
		return nil, Internal("Rate limit must be a positive number.", nil)
	}
	if options.Window <= 0 {
		return nil, Internal("Rate limit window must be a positive duration.", nil)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &TokenBucketRateLimiter{
		limit:   options.Limit,
		window:  options.Window,
		now:     now,
		buckets: make(map[string]*tokenBucket),
		maxKeys: 10_000,
	}, nil
}

// Limit returns the burst size.
func (l *TokenBucketRateLimiter) Limit() int {
	if l == nil {
		return 0
	}
	return l.limit
}

// Consume charges cost tokens to key. cost <= 0 is treated as 1.
func (l *TokenBucketRateLimiter) Consume(key string, cost int) RateLimitResult {
	if l == nil {
		return RateLimitResult{Allowed: true, Limit: math.MaxInt, Remaining: math.MaxInt, ResetAt: time.Now()}
	}
	if cost <= 0 {
		cost = 1
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, ok := l.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: float64(l.limit), updatedAt: now}
		l.buckets[key] = bucket
		l.pruneLocked(now)
	} else {
		elapsed := now.Sub(bucket.updatedAt)
		if elapsed > 0 {
			bucket.tokens = math.Min(float64(l.limit), bucket.tokens+float64(elapsed)*float64(l.limit)/float64(l.window))
		}
		bucket.updatedAt = now
	}
	if bucket.tokens >= float64(cost) {
		bucket.tokens -= float64(cost)
		return RateLimitResult{
			Allowed:   true,
			Limit:     l.limit,
			Remaining: int(math.Floor(bucket.tokens)),
			ResetAt:   now,
		}
	}
	missing := float64(cost) - bucket.tokens
	retryAfter := time.Duration(math.Ceil(missing * float64(l.window) / float64(l.limit)))
	if retryAfter < time.Millisecond {
		retryAfter = time.Millisecond
	}
	return RateLimitResult{
		Allowed:    false,
		Limit:      l.limit,
		Remaining:  int(math.Floor(bucket.tokens)),
		RetryAfter: retryAfter,
		ResetAt:    now.Add(retryAfter),
	}
}

// Reset drops one key, or every key when key is empty.
func (l *TokenBucketRateLimiter) Reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if key == "" {
		l.buckets = make(map[string]*tokenBucket)
		return
	}
	delete(l.buckets, key)
}

func (l *TokenBucketRateLimiter) pruneLocked(now time.Time) {
	if len(l.buckets) <= l.maxKeys {
		return
	}
	for key, bucket := range l.buckets {
		if bucket.tokens >= float64(l.limit) && now.Sub(bucket.updatedAt) > l.window {
			delete(l.buckets, key)
		}
		if len(l.buckets) <= l.maxKeys/2 {
			return
		}
	}
}

// UnlimitedRateLimiter never rejects a call.
type UnlimitedRateLimiter struct{}

// Consume implements RateLimiter.
func (UnlimitedRateLimiter) Consume(string, int) RateLimitResult {
	return RateLimitResult{Allowed: true, Limit: math.MaxInt, Remaining: math.MaxInt, ResetAt: time.Now()}
}

// Reset implements RateLimiter.
func (UnlimitedRateLimiter) Reset(string) {}

var _ RateLimiter = (*TokenBucketRateLimiter)(nil)
var _ RateLimiter = UnlimitedRateLimiter{}
