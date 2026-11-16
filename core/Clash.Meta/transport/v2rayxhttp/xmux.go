package v2rayxhttp

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// errMuxSaturated is returned when a pool reached `max_connections` and every
// live connection already carries `max_concurrency` streams. The dialer sees a
// clear "no slot" error instead of the stream being pushed onto a connection
// beyond its configured quota.
var errMuxSaturated = errors.New("v2rayxhttp: xmux pool saturated (max_connections reached, every connection at max_concurrency)")

// muxManager mirrors the vendor `xmux` pool: every HTTP/2 connection is a pool
// entry, and a new one is dialed when all entries reached `max_concurrency`
// concurrent streams (or when `max_connections`/reuse limits say so).
//
// The pool is bounded by two independent limits: `max_concurrency` caps the
// streams riding one connection and `max_connections` caps the connections.
// Their product is the hard ceiling on concurrent streams; once both are spent
// acquire() fails instead of over-subscribing a connection.
type muxManager struct {
	mu sync.Mutex

	entries []*muxEntry

	maxConcurrency int
	maxConnections int
	maxRequests    int
	maxReuseTimes  int
	maxReusable    time.Duration

	factory func() (*http.Client, error)
	closed  bool
}

type muxEntry struct {
	manager  *muxManager
	client   *http.Client
	open     int
	requests int
	// reuses counts how often this entry was handed out again after its first
	// stream, the counter behind `c_max_reuse_times`.
	reuses  int
	created time.Time
}

func newMuxManager(options *XmuxOptions, factory func() (*http.Client, error)) *muxManager {
	m := &muxManager{factory: factory}
	if options != nil {
		m.maxConcurrency = options.MaxConcurrency.Rand()
		m.maxConnections = options.MaxConnections.Rand()
		m.maxRequests = options.HMaxRequestTimes.Rand()
		m.maxReuseTimes = options.CMaxReuseTimes.Rand()
		if secs := options.HMaxReusableSecs.Rand(); secs > 0 {
			m.maxReusable = time.Duration(secs) * time.Second
		}
	}
	return m
}

func (m *muxManager) acquire() (*http.Client, *muxEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, nil, http.ErrServerClosed
	}
	// Reclaim entries that hit a reuse limit.
	live := m.entries[:0]
	for _, entry := range m.entries {
		if m.expired(entry) {
			entry.closeTransport()
			continue
		}
		live = append(live, entry)
	}
	m.entries = live
	now := time.Now()
	// Reusable entries first; a connection that spent its `c_max_reuse_times`
	// budget is skipped here and closed once its last stream finishes.
	active := 0
	for _, entry := range m.entries {
		if !m.canReuse(entry) {
			continue
		}
		active++
		if m.maxConcurrency <= 0 || entry.open < m.maxConcurrency {
			entry.open++
			entry.requests++
			if entry.open > 1 {
				entry.reuses++
			}
			return entry.client, entry, nil
		}
	}
	// Every connection is at its stream quota. Honour max_connections: a full
	// pool is an error, never a stream pushed past max_concurrency.
	if m.maxConnections > 0 && active >= m.maxConnections {
		return nil, nil, fmt.Errorf("%w (max_connections=%d, max_concurrency=%d)", errMuxSaturated, m.maxConnections, m.maxConcurrency)
	}
	client, err := m.factory()
	if err != nil {
		return nil, nil, err
	}
	entry := &muxEntry{manager: m, client: client, created: now}
	entry.open = 1
	entry.requests = 1
	m.entries = append(m.entries, entry)
	return client, entry, nil
}

// canReuse reports whether an entry may still take a new stream under
// `c_max_reuse_times`. Entries that cannot are drained and then dropped by
// expired().
func (m *muxManager) canReuse(entry *muxEntry) bool {
	return m.maxReuseTimes <= 0 || entry.reuses < m.maxReuseTimes
}

// expired reports whether an entry reached a reuse limit. An entry with open
// streams is only reclaimed once idle, so an in-flight stream is never cut.
func (m *muxManager) expired(entry *muxEntry) bool {
	if entry.open > 0 {
		return false
	}
	if !m.canReuse(entry) {
		return true
	}
	if m.maxRequests > 0 && entry.requests >= m.maxRequests {
		return true
	}
	if m.maxReusable > 0 && time.Since(entry.created) > m.maxReusable {
		return true
	}
	return false
}

func (m *muxManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, entry := range m.entries {
		entry.closeTransport()
	}
	m.entries = nil
}

func (e *muxEntry) release() {
	m := e.manager
	m.mu.Lock()
	if e.open > 0 {
		e.open--
	}
	m.mu.Unlock()
}

func (e *muxEntry) closeTransport() {
	e.client.CloseIdleConnections()
}
