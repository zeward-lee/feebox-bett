package v2rayxhttp

import (
	"net/http"
	"sync"
	"time"
)

// muxManager mirrors the vendor `xmux` pool: every HTTP/2 connection is a pool
// entry, and a new one is dialed when all entries reached `max_concurrency`
// concurrent streams (or when `max_connections`/reuse limits say so).
type muxManager struct {
	mu sync.Mutex

	entries []*muxEntry

	maxConcurrency int
	maxConnections int
	maxRequests    int
	maxReusable    time.Duration

	factory func() (*http.Client, error)
	closed  bool
}

type muxEntry struct {
	manager  *muxManager
	client   *http.Client
	open     int
	requests int
	created  time.Time
}

func newMuxManager(options *XmuxOptions, factory func() (*http.Client, error)) *muxManager {
	m := &muxManager{factory: factory}
	if options != nil {
		m.maxConcurrency = options.MaxConcurrency.Rand()
		m.maxConnections = options.MaxConnections.Rand()
		m.maxRequests = options.HMaxRequestTimes.Rand()
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
	for _, entry := range m.entries {
		if m.maxConcurrency <= 0 || entry.open < m.maxConcurrency {
			entry.open++
			entry.requests++
			return entry.client, entry, nil
		}
	}
	// All entries are saturated. Honour max_connections, otherwise grow the pool.
	if m.maxConnections > 0 && len(m.entries) >= m.maxConnections {
		entry := m.entries[0]
		for _, candidate := range m.entries[1:] {
			if candidate.open < entry.open {
				entry = candidate
			}
		}
		entry.open++
		entry.requests++
		return entry.client, entry, nil
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

// expired reports whether an entry reached a reuse limit. An entry with open
// streams is only reclaimed once idle, so an in-flight stream is never cut.
func (m *muxManager) expired(entry *muxEntry) bool {
	if entry.open > 0 {
		return false
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
