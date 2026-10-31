package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottledCallsWaitAndRetryThenSucceed(t *testing.T) {
	old := retryScale
	retryScale = 1000 // a "1 second" wait becomes 1 millisecond
	defer func() { retryScale = old }()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"a"}]}`))
	}))
	defer srv.Close()
	items, err := NewForTest(srv.URL, true).List(context.Background(), "/x")
	if err != nil || len(items) != 1 || calls != 3 {
		t.Fatalf("%v %v calls=%d", err, items, calls)
	}
}

func TestThrottlingGivesUpAfterAFewTriesWithTheRealStatus(t *testing.T) {
	old := retryScale
	retryScale = 1000
	defer func() { retryScale = old }()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1); w.WriteHeader(503) }))
	defer srv.Close()
	_, err := NewForTest(srv.URL, true).List(context.Background(), "/x")
	if err == nil || calls != int32(maxRetries)+1 {
		t.Fatalf("%v calls=%d", err, calls)
	}
}

func TestRetryStopsWhenTheRequestIsCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "30"); w.WriteHeader(429) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := NewForTest(srv.URL, true).List(ctx, "/x"); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("cancel must end the wait: %v after %v", err, time.Since(start))
	}
}

func TestBackoffHonoursRetryAfterAndCapsIt(t *testing.T) {
	if backoff(0, "5") != 5*time.Second || backoff(3, "") != 8*time.Second || backoff(0, "900") != 60*time.Second {
		t.Fatal("backoff")
	}
}
