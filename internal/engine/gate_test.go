package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAChangeWinsOverChecksAndChecksNeverWait(t *testing.T) {
	var g TenantGate
	endRead, ok := g.TryRead("t")
	if !ok {
		t.Fatal("a check starts when nothing is running")
	}
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		end := g.BeginWrite("t") // queued behind the running check
		end()
		close(done)
	}()
	<-started
	time.Sleep(30 * time.Millisecond)
	if _, ok := g.TryRead("t"); ok {
		t.Fatal("once a change is queued, new checks must be refused")
	}
	select {
	case <-done:
		t.Fatal("the change must wait for the running check to finish")
	default:
	}
	endRead()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the change should start as soon as the check finishes")
	}
	if end, ok := g.TryRead("t"); !ok {
		t.Fatal("checks resume after the change")
	} else {
		end()
	}
}

func TestChangesOnOneClientNeverOverlapButDifferentClientsDo(t *testing.T) {
	var g TenantGate
	var inside, maxInside int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			end := g.BeginWrite("same")
			n := atomic.AddInt32(&inside, 1)
			for {
				m := atomic.LoadInt32(&maxInside)
				if n <= m || atomic.CompareAndSwapInt32(&maxInside, m, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&inside, -1)
			end()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("two changes ran at once on one client: %d", maxInside)
	}
	e1 := g.BeginWrite("a")
	done := make(chan struct{})
	go func() { e2 := g.BeginWrite("b"); e2(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a change on one client must not block another client")
	}
	e1()
}
