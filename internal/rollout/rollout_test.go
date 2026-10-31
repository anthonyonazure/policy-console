package rollout

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/store"
)

const (
	g1 = "11111111-1111-1111-1111-111111111111"
	g2 = "22222222-2222-2222-2222-222222222222"
	g3 = "33333333-3333-3333-3333-333333333333"
	g0 = "00000000-0000-0000-0000-000000000000" // already assigned before the rollout
)

type fakeAssigner struct {
	cur     Assignment
	sets    []Assignment
	failSet error
}

func (f *fakeAssigner) Current(context.Context, string, string, string) (Assignment, error) {
	return f.cur, nil
}
func (f *fakeAssigner) Set(_ context.Context, _, _, _ string, a Assignment) error {
	if f.failSet != nil {
		return f.failSet
	}
	f.sets = append(f.sets, a)
	f.cur = a
	return nil
}

type fakeCheck struct{ pct int }

func (c *fakeCheck) CompliantPercent(context.Context, string, *store.Rollout) (int, error) {
	return c.pct, nil
}

type rig struct {
	r   *Runner
	a   *fakeAssigner
	c   *fakeCheck
	now time.Time
}

func newRig(t *testing.T) *rig {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	x := &rig{a: &fakeAssigner{cur: Assignment{Groups: []string{g0}}}, c: &fakeCheck{pct: 100}, now: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)}
	x.r = &Runner{Store: db, Assign: x.a, Check: x.c, Now: func() time.Time { return x.now }}
	return x
}

func threeRing() Request {
	return Request{TenantID: "t1", PlanID: "three-ring", Kind: "compliance-policies", ObjectID: "p1", ObjectName: "Windows compliance", Actor: "anthony",
		Binding: Binding{RingGroups: [][]string{{g1}, {g2}}, Everyone: AllDevices}}
}

func (x *rig) start(t *testing.T, req Request) *store.Rollout {
	t.Helper()
	sch, err := x.r.Preview(req)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := x.r.Create(context.Background(), req, sch.Hash)
	if err != nil {
		t.Fatal(err)
	}
	return ro
}

func (x *rig) tick() []Event {
	var out []Event
	for _, e := range x.r.Tick(context.Background()) {
		if e.What != "" {
			out = append(out, e)
		}
	}
	return out
}

func whats(es []Event) string {
	var s []string
	for _, e := range es {
		s = append(s, e.Ring+":"+e.What)
	}
	return strings.Join(s, ",")
}

func TestPlansAreValidatedBeforeAnythingIsCreated(t *testing.T) {
	p, _ := PlanByID("three-ring")
	cases := map[string]Binding{
		"needs at least one group": {RingGroups: [][]string{{g1}, {}}, Everyone: AllDevices},
		"not a group id":           {RingGroups: [][]string{{"nope"}, {g2}}, Everyone: AllDevices},
		"all users or all devices": {RingGroups: [][]string{{g1}, {g2}}},
		"more group lists":         {RingGroups: [][]string{{g1}, {g2}, {g3}}, Everyone: AllUsers},
	}
	for want, b := range cases {
		if _, err := Resolve(p, b); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	bad := Plan{Rings: []RingShape{{Name: "Everyone", Everyone: true}, {Name: "Later", WaitHours: 24}}}
	if _, err := Resolve(bad, Binding{Everyone: AllUsers, RingGroups: [][]string{{g1}}}); err == nil || !strings.Contains(err.Error(), "must be the last ring") {
		t.Fatalf("the everyone ring can only be last: %v", err)
	}
	fast := Plan{Rings: []RingShape{{Name: "A"}, {Name: "B", WaitHours: 0}}}
	if _, err := Resolve(fast, Binding{RingGroups: [][]string{{g1}, {g2}}}); err == nil {
		t.Fatal("rings after the first must wait at least an hour")
	}
}

func TestOnlyTheShownPreviewCanBeConfirmed(t *testing.T) {
	x := newRig(t)
	req := threeRing()
	if _, err := x.r.Create(context.Background(), req, "made-up"); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("%v", err)
	}
	sch, _ := x.r.Preview(req)
	req.Binding.RingGroups[0] = []string{g3} // changed after the preview
	if _, err := x.r.Create(context.Background(), req, sch.Hash); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("a changed request must not ride on an old confirmation: %v", err)
	}
	if len(x.a.sets) != 0 {
		t.Fatal("nothing may be written")
	}
}

func TestAThreeRingRolloutWalksThroughItsGatesAndEndsAtEveryone(t *testing.T) {
	x := newRig(t)
	x.start(t, threeRing())

	if got := whats(x.tick()); got != "Pilot:waiting" {
		t.Fatalf("pilot needs approval first: %s", got)
	}
	if got := whats(x.tick()); got != "" {
		t.Fatalf("a second tick with nothing new says nothing: %s", got)
	}
	if err := x.r.Approve(1, 0, "anthony"); err != nil {
		t.Fatal(err)
	}
	if got := whats(x.tick()); got != "Pilot:activated" {
		t.Fatalf("%s", got)
	}
	if want := (Assignment{Groups: []string{g0, g1}}); !same(x.a.cur, want) {
		t.Fatalf("pilot adds to what was there, never replaces it: %+v", x.a.cur)
	}

	x.now = x.now.Add(47 * time.Hour)
	if got := whats(x.tick()); got != "" {
		t.Fatalf("the early ring must wait its 48 hours: %s", got)
	}
	x.now = x.now.Add(2 * time.Hour)
	x.c.pct = 90
	ev := x.tick()
	if whats(ev) != "Early adopters:waiting" || !strings.Contains(ev[0].Detail, "only 90%") {
		t.Fatalf("a failed compliance gate says why: %+v", ev)
	}
	x.c.pct = 97
	if got := whats(x.tick()); got != "Early adopters:activated" {
		t.Fatalf("%s", got)
	}
	if !same(x.a.cur, Assignment{Groups: []string{g0, g1, g2}}) {
		t.Fatalf("cumulative: %+v", x.a.cur)
	}

	x.now = x.now.Add(73 * time.Hour)
	if got := whats(x.tick()); got != "Everyone:waiting" {
		t.Fatalf("the last ring needs a person: %s", got)
	}
	_ = x.r.Approve(1, 2, "anthony")
	if got := whats(x.tick()); got != "Everyone:activated,Everyone:completed" {
		t.Fatalf("%s", got)
	}
	if x.a.cur.Virtual != AllDevices || len(x.a.cur.Groups) != 0 {
		t.Fatalf("the everyone ring replaces the groups: %+v", x.a.cur)
	}
	ro, _ := x.r.Store.Rollout(1)
	if ro.State != StateCompleted {
		t.Fatal(ro.State)
	}
}

func same(a, b Assignment) bool {
	return strings.Join(a.Groups, ",") == strings.Join(b.Groups, ",") && a.Virtual == b.Virtual
}

func TestAFutureStartDoesNothingEarlyAndABusyPolicyIsRefused(t *testing.T) {
	x := newRig(t)
	req := threeRing()
	req.StartAt = x.now.Add(24 * time.Hour)
	ro := x.start(t, req)
	if ro.State != StateScheduled {
		t.Fatal(ro.State)
	}
	_ = x.r.Approve(ro.ID, 0, "a")
	if got := whats(x.tick()); got != "" || len(x.a.sets) != 0 {
		t.Fatalf("nothing before the start time: %s", got)
	}
	sch, _ := x.r.Preview(req)
	if _, err := x.r.Create(context.Background(), req, sch.Hash); !errors.Is(err, store.ErrPayloadBusy) {
		t.Fatalf("two rollouts must not move one policy: %v", err)
	}
	x.now = x.now.Add(25 * time.Hour)
	if got := whats(x.tick()); got != "Pilot:activated" {
		t.Fatalf("%s", got)
	}
}

func TestAPolicyAlreadyOnEveryoneAndReadOnlyModeAreRefused(t *testing.T) {
	x := newRig(t)
	x.a.cur = Assignment{Virtual: AllUsers}
	sch, _ := x.r.Preview(threeRing())
	if _, err := x.r.Create(context.Background(), threeRing(), sch.Hash); err == nil || !strings.Contains(err.Error(), "already assigned to everyone") {
		t.Fatalf("%v", err)
	}
	x.a.cur = Assignment{}
	x.r.ReadOnly = true
	if _, err := x.r.Create(context.Background(), threeRing(), sch.Hash); err == nil || !strings.Contains(err.Error(), "read only") {
		t.Fatalf("%v", err)
	}
	if ev := x.r.Tick(context.Background()); ev != nil {
		t.Fatal("nothing activates in read only mode")
	}
}

func TestAFailedActivationStopsTheRolloutAndResumeRetriesIt(t *testing.T) {
	x := newRig(t)
	ro := x.start(t, threeRing())
	_ = x.r.Approve(ro.ID, 0, "anthony")
	x.a.failSet = errors.New("graph 500")
	ev := x.tick()
	if whats(ev) != "Pilot:error" {
		t.Fatalf("%s", whats(ev))
	}
	if got, _ := x.r.Store.Rollout(ro.ID); got.State != StateError || got.Rings[0].State != RingError {
		t.Fatalf("%+v", got)
	}
	if whats(x.tick()) != "" {
		t.Fatal("an errored rollout waits for a person")
	}
	x.a.failSet = nil
	if err := x.r.Resume(ro.ID, "anthony"); err != nil {
		t.Fatal(err)
	}
	if got := whats(x.tick()); got != "Pilot:activated" {
		t.Fatalf("%s", got)
	}
}

func TestPauseStopsEverythingAndCancelCanPutTheOldAssignmentBack(t *testing.T) {
	x := newRig(t)
	ro := x.start(t, threeRing())
	_ = x.r.Approve(ro.ID, 0, "a")
	if err := x.r.Pause(ro.ID, "anthony"); err != nil {
		t.Fatal(err)
	}
	if whats(x.tick()) != "" || len(x.a.sets) != 0 {
		t.Fatal("a paused rollout changes nothing")
	}
	_ = x.r.Resume(ro.ID, "anthony")
	_ = x.tick() // pilot activates
	if !same(x.a.cur, Assignment{Groups: []string{g0, g1}}) {
		t.Fatalf("%+v", x.a.cur)
	}
	// Putting the old assignment back fails: the rollout must NOT be marked canceled.
	x.a.failSet = errors.New("graph down")
	if err := x.r.Cancel(context.Background(), ro.ID, "anthony", true); err == nil {
		t.Fatal("a failed revert must be reported")
	}
	if got, _ := x.r.Store.Rollout(ro.ID); got.State == StateCanceled {
		t.Fatal("the rollout still owns the assignment until the revert works")
	}
	x.a.failSet = nil
	if err := x.r.Cancel(context.Background(), ro.ID, "anthony", true); err != nil {
		t.Fatal(err)
	}
	if !same(x.a.cur, Assignment{Groups: []string{g0}}) {
		t.Fatalf("back to what it was: %+v", x.a.cur)
	}
	if err := x.r.Cancel(context.Background(), ro.ID, "anthony", false); err == nil {
		t.Fatal("a canceled rollout cannot be canceled again")
	}
}

func TestACatchUpAfterDowntimeActivatesEveryRingThatIsDue(t *testing.T) {
	x := newRig(t)
	Plans = append(Plans, Plan{ID: "auto", Name: "Auto", Rings: []RingShape{{Name: "A"}, {Name: "B", WaitHours: 1}, {Name: "C", WaitHours: 1}}})
	defer func() { Plans = Plans[:len(Plans)-1] }()
	req := Request{TenantID: "t1", PlanID: "auto", Kind: "compliance-policies", ObjectID: "p2", ObjectName: "x", Actor: "a",
		Binding: Binding{RingGroups: [][]string{{g1}, {g2}, {g3}}}}
	x.start(t, req)
	x.now = x.now.Add(10 * time.Hour) // the console was off for ten hours
	if got := whats(x.tick()); got != "A:activated" {
		t.Fatalf("next rings become due from when the previous one actually started: %s", got)
	}
	x.now = x.now.Add(2 * time.Hour)
	if got := whats(x.tick()); got != "B:activated" {
		t.Fatalf("%s", got)
	}
}

func TestApprovalNeedsAName(t *testing.T) {
	x := newRig(t)
	ro := x.start(t, threeRing())
	if err := x.r.Approve(ro.ID, 0, ""); err == nil {
		t.Fatal("an approval must name the person")
	}
	if err := x.r.Approve(ro.ID, 9, "a"); err == nil {
		t.Fatal("no such ring")
	}
}
