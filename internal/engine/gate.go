package engine

import "sync"

// TenantGate keeps scheduled checks and changes from running on one client at the
// same time. A change always wins: once one is waiting, new checks are refused,
// and the change starts as soon as the checks already running have finished.
// Checks never wait; they skip the client and try again next cycle.
//
// The zero value is ready to use.
type TenantGate struct {
	mu sync.Mutex
	m  map[string]*gateState
}

type gateState struct {
	cond    *sync.Cond
	writing bool // a change is running
	waiting int  // changes queued behind it or behind readers
	readers int
}

func (g *TenantGate) state(tenant string) *gateState {
	if g.m == nil {
		g.m = map[string]*gateState{}
	}
	s := g.m[tenant]
	if s == nil {
		s = &gateState{cond: sync.NewCond(&g.mu)}
		g.m[tenant] = s
	}
	return s
}

// BeginWrite blocks until no check or other change is running on the client, then
// holds it. Call the returned function when the change is finished.
func (g *TenantGate) BeginWrite(tenant string) (end func()) {
	g.mu.Lock()
	s := g.state(tenant)
	s.waiting++
	for s.writing || s.readers > 0 {
		s.cond.Wait()
	}
	s.waiting--
	s.writing = true
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		s.writing = false
		s.cond.Broadcast()
		g.mu.Unlock()
	}
}

// TryRead takes a shared hold for a scheduled check. It returns false, without
// waiting, when a change is running or queued for the client.
func (g *TenantGate) TryRead(tenant string) (end func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.state(tenant)
	if s.writing || s.waiting > 0 {
		return nil, false
	}
	s.readers++
	return func() {
		g.mu.Lock()
		s.readers--
		s.cond.Broadcast()
		g.mu.Unlock()
	}, true
}
