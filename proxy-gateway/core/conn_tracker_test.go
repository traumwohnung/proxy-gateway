package core

import "testing"

func TestChainTrackers(t *testing.T) {
	if ChainTrackers(nil, nil) != nil {
		t.Fatal("nil+nil should be nil")
	}

	called := 0
	h := &testTracker{onClose: func() { called++ }}
	if ChainTrackers(nil, h) != h {
		t.Fatal("nil+h should be h")
	}
	if ChainTrackers(h, nil) != h {
		t.Fatal("h+nil should be h")
	}

	a := &testTracker{onClose: func() { called++ }}
	b := &testTracker{onClose: func() { called += 10 }}
	c := ChainTrackers(a, b)
	c.Close(0, 0)
	if called != 11 {
		t.Fatalf("expected 11, got %d", called)
	}
}

type testTracker struct {
	onClose func()
}

func (h *testTracker) RecordTraffic(_ bool, _ int64, _ func()) {}
func (h *testTracker) Close(_, _ int64)                        { h.onClose() }
