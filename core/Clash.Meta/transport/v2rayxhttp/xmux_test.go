package v2rayxhttp

import (
	"errors"
	"net/http"
	"testing"
)

func newTestMux(options *XmuxOptions) (*muxManager, *int) {
	created := 0
	m := newMuxManager(options, func() (*http.Client, error) {
		created++
		return &http.Client{}, nil
	})
	return m, &created
}

// TestMuxPoolBoundsTotalConcurrency is the assertion the review asked for: with
// max_concurrency=2 and max_connections=2 the pool carries exactly four
// concurrent streams, spread over two connections, and refuses the fifth with an
// explicit error instead of pushing it past a connection's quota.
func TestMuxPoolBoundsTotalConcurrency(t *testing.T) {
	m, created := newTestMux(&XmuxOptions{
		MaxConcurrency: Range{From: 2, To: 2},
		MaxConnections: Range{From: 2, To: 2},
	})
	entries := make([]*muxEntry, 0, 4)
	for i := 1; i <= 4; i++ {
		_, entry, err := m.acquire()
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		entries = append(entries, entry)
	}
	if *created != 2 {
		t.Errorf("dialed %d connections, want 2", *created)
	}
	if entries[0] == entries[2] {
		t.Error("stream 3 should ride the second connection")
	}
	for _, entry := range m.entries {
		if entry.open != 2 {
			t.Errorf("connection open = %d, want 2 (quota = max_concurrency)", entry.open)
		}
	}

	_, _, err := m.acquire()
	if !errors.Is(err, errMuxSaturated) {
		t.Fatalf("fifth stream error = %v, want errMuxSaturated", err)
	}

	// Releasing one stream frees exactly one slot, no more.
	entries[0].release()
	if _, _, err := m.acquire(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if _, _, err := m.acquire(); !errors.Is(err, errMuxSaturated) {
		t.Fatalf("fifth slot after release error = %v, want errMuxSaturated", err)
	}
}

// TestMuxReuseLimitRecyclesConnections covers the former dead field
// c_max_reuse_times: an entry that spent its reuse budget is not handed out
// again and is closed once idle, while a busy entry is kept until its stream
// finishes so no in-flight stream is ever cut.
func TestMuxReuseLimitRecyclesConnections(t *testing.T) {
	m, created := newTestMux(&XmuxOptions{CMaxReuseTimes: Range{From: 1, To: 1}})

	_, first, err := m.acquire()
	if err != nil {
		t.Fatalf("first stream: %v", err)
	}
	if *created != 1 {
		t.Fatalf("dialed %d connections, want 1", *created)
	}
	// One reuse is allowed by the budget.
	_, second, err := m.acquire()
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if second != first {
		t.Fatal("second stream should reuse the first connection")
	}
	if first.open != 2 {
		t.Fatalf("first connection open = %d, want 2", first.open)
	}
	// Budget spent while the entry is still busy: it must not be handed out a
	// third time, and it must not be cut either.
	_, third, err := m.acquire()
	if err != nil {
		t.Fatalf("third stream: %v", err)
	}
	if third == first {
		t.Error("connection with an exhausted reuse budget was handed out again")
	}
	if first.open != 2 {
		t.Errorf("in-flight streams were cut: open = %d, want 2", first.open)
	}
	if *created != 2 {
		t.Errorf("dialed %d connections, want 2", *created)
	}

	// Once the exhausted entry drains it is dropped instead of reused.
	first.release()
	first.release()
	_, fourth, err := m.acquire()
	if err != nil {
		t.Fatalf("acquire after drain: %v", err)
	}
	if fourth == first {
		t.Error("idle connection with an exhausted reuse budget was recycled")
	}
}
