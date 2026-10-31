// Package rollout offers a policy to a client in stages. Each stage (ring) adds
// a group of devices or users after a wait and, if the plan says so, after a
// named person approves or a minimum share of devices would comply. It is the
// console's own version of Intune deployment plans, and works for every kind of
// policy the console writes, not only Windows ones.
//
// Safety rules built in: a policy can be in one rollout at a time; the final
// "everyone" ring can only be last; a rollout never starts on a policy that is
// already assigned to everyone; pause, resume and cancel are always possible;
// and nothing activates in read only mode.
package rollout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/store"
)

const (
	AllUsers   = "all-users"
	AllDevices = "all-devices"

	StateScheduled = "scheduled"
	StateRunning   = "running"
	StatePaused    = "paused"
	StateCompleted = "completed"
	StateCanceled  = "canceled"
	StateError     = "error"

	RingPending   = "pending"
	RingWaiting   = "waiting"
	RingActivated = "activated"
	RingError     = "error"
)

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Gate is what must be true before a ring starts, besides the wait.
type Gate struct {
	ManualApproval      bool `json:"manualApproval"`
	MinCompliantPercent int  `json:"minCompliantPercent,omitempty"` // predicted share of devices that would comply
}

// RingShape is one stage of a reusable plan, before any groups are chosen.
type RingShape struct {
	Name      string `json:"name"`
	WaitHours int    `json:"waitHours"` // after the previous ring started; the first ring starts at the start time
	Gate      Gate   `json:"gate"`
	Everyone  bool   `json:"everyone,omitempty"` // the final ring that targets all users or all devices
}

// Plan is a reusable rollout pattern. It holds no groups and no policy.
type Plan struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rings       []RingShape `json:"rings"`
}

// Plans are the patterns that ship with the console.
var Plans = []Plan{
	{ID: "three-ring", Name: "Three ring", Description: "A pilot group first, then a wider early group, then everyone. The standard choice.",
		Rings: []RingShape{
			{Name: "Pilot", WaitHours: 0, Gate: Gate{ManualApproval: true}},
			{Name: "Early adopters", WaitHours: 48, Gate: Gate{MinCompliantPercent: 95}},
			{Name: "Everyone", WaitHours: 72, Everyone: true, Gate: Gate{ManualApproval: true}},
		}},
	{ID: "careful-client", Name: "Careful client", Description: "One week between rings, and a person approves each one. For clients who dislike surprises.",
		Rings: []RingShape{
			{Name: "Pilot", WaitHours: 0, Gate: Gate{ManualApproval: true}},
			{Name: "Wave 1", WaitHours: 168, Gate: Gate{ManualApproval: true}},
			{Name: "Wave 2", WaitHours: 168, Gate: Gate{ManualApproval: true}},
			{Name: "Everyone", WaitHours: 168, Everyone: true, Gate: Gate{ManualApproval: true}},
		}},
	{ID: "emergency", Name: "Emergency", Description: "Everyone at once, after a person approves. Use only when waiting is worse than the risk.",
		Rings: []RingShape{{Name: "Everyone", WaitHours: 0, Everyone: true, Gate: Gate{ManualApproval: true}}}},
}

// PlanByID finds a built in plan.
func PlanByID(id string) (Plan, bool) {
	for _, p := range Plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}

// Binding chooses the groups for a plan's rings.
type Binding struct {
	RingGroups [][]string `json:"ringGroups"` // one list per ring that is not the everyone ring
	Everyone   string     `json:"everyone"`   // all-users or all-devices, used by the everyone ring
}

// RingSpec is a ring as stored: shape plus the groups chosen for it.
type RingSpec struct {
	RingShape
	Groups  []string `json:"groups,omitempty"`
	Virtual string   `json:"virtual,omitempty"`
}

// Assignment is what a policy is offered to. Exclusions are never touched by a rollout.
type Assignment struct {
	Groups  []string `json:"groups"`
	Virtual string   `json:"virtual"`
}

// Assigner reads and writes a policy's assignment.
type Assigner interface {
	Current(ctx context.Context, tenant, kind, objectID string) (Assignment, error)
	Set(ctx context.Context, tenant, kind, objectID string, a Assignment) error
}

// Checker answers the share of devices that would comply, for the compliance gate.
type Checker interface {
	CompliantPercent(ctx context.Context, tenant string, r *store.Rollout) (int, error)
}

// Resolve checks a plan and binding and returns the rings with their groups.
func Resolve(p Plan, b Binding) ([]RingSpec, error) {
	if len(p.Rings) == 0 {
		return nil, errors.New("a plan needs at least one ring")
	}
	var out []RingSpec
	gi := 0
	for i, shape := range p.Rings {
		if strings.TrimSpace(shape.Name) == "" {
			return nil, fmt.Errorf("ring %d has no name", i+1)
		}
		if shape.WaitHours < 0 || (i > 0 && shape.WaitHours < 1) {
			return nil, fmt.Errorf("ring %q must wait at least one hour after the ring before it", shape.Name)
		}
		if shape.Gate.MinCompliantPercent < 0 || shape.Gate.MinCompliantPercent > 100 {
			return nil, fmt.Errorf("ring %q has a compliance threshold outside 0 to 100", shape.Name)
		}
		spec := RingSpec{RingShape: shape}
		if shape.Everyone {
			if i != len(p.Rings)-1 {
				return nil, fmt.Errorf("the everyone ring %q must be the last ring", shape.Name)
			}
			if b.Everyone != AllUsers && b.Everyone != AllDevices {
				return nil, errors.New("choose whether the everyone ring means all users or all devices")
			}
			spec.Virtual = b.Everyone
		} else {
			if gi >= len(b.RingGroups) || len(b.RingGroups[gi]) == 0 {
				return nil, fmt.Errorf("ring %q needs at least one group", shape.Name)
			}
			seen := map[string]bool{}
			for _, g := range b.RingGroups[gi] {
				if !guidRE.MatchString(g) {
					return nil, fmt.Errorf("ring %q: %q is not a group id", shape.Name, g)
				}
				if !seen[strings.ToLower(g)] {
					seen[strings.ToLower(g)] = true
					spec.Groups = append(spec.Groups, g)
				}
			}
			gi++
		}
		out = append(out, spec)
	}
	if gi != len(b.RingGroups) {
		return nil, errors.New("more group lists were given than the plan has rings")
	}
	return out, nil
}

// Step is one line of a preview: when a ring becomes eligible, counting from the start.
type Step struct {
	Index      int      `json:"index"`
	Name       string   `json:"name"`
	EarliestAt string   `json:"earliestAt"` // assumes every earlier ring starts as soon as it may
	WaitHours  int      `json:"waitHours"`
	Gate       Gate     `json:"gate"`
	Groups     []string `json:"groups,omitempty"`
	Everyone   string   `json:"everyone,omitempty"`
}

// Schedule is what Preview shows before anything is created.
type Schedule struct {
	Plan  string `json:"plan"`
	Steps []Step `json:"steps"`
	Hash  string `json:"hash"`
}

// Request is everything needed to create a rollout.
type Request struct {
	TenantID, PlanID, Kind, ObjectID, ObjectName, Actor string
	Binding                                             Binding
	StartAt                                             time.Time
	TemplateID                                          string
}

// Runner moves rollouts forward.
type Runner struct {
	Store    *store.Store
	Assign   Assigner
	Check    Checker // optional
	Now      func() time.Time
	Logf     func(format string, args ...any)
	ReadOnly bool // when true nothing is activated
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) logf(f string, a ...any) {
	if r.Logf != nil {
		r.Logf(f, a...)
	}
}

// Preview shows the schedule a request would create. It reads and writes nothing.
func (r *Runner) Preview(req Request) (*Schedule, error) {
	p, ok := PlanByID(req.PlanID)
	if !ok {
		return nil, fmt.Errorf("unknown plan %q", req.PlanID)
	}
	rings, err := Resolve(p, req.Binding)
	if err != nil {
		return nil, err
	}
	if req.StartAt.IsZero() {
		req.StartAt = r.now()
	}
	sch := &Schedule{Plan: p.ID}
	at := req.StartAt.UTC()
	for i, rg := range rings {
		if i > 0 {
			at = at.Add(time.Duration(rg.WaitHours) * time.Hour)
		}
		sch.Steps = append(sch.Steps, Step{Index: i, Name: rg.Name, EarliestAt: at.Format(time.RFC3339), WaitHours: rg.WaitHours,
			Gate: rg.Gate, Groups: rg.Groups, Everyone: rg.Virtual})
	}
	sch.Hash = hashOf(req, rings)
	return sch, nil
}

func hashOf(req Request, rings []RingSpec) string {
	b, _ := json.Marshal(struct {
		T, P, K, O string
		S          int64
		R          []RingSpec
	}{req.TenantID, req.PlanID, req.Kind, req.ObjectID, req.StartAt.Unix(), rings})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ErrNotConfirmed means the confirmation did not match the preview that was shown.
var ErrNotConfirmed = errors.New("the confirmation does not match the preview; preview again and confirm that one")

// Create starts a rollout. confirmHash must be the hash from a preview of the
// same request, so what is created is what the person saw.
func (r *Runner) Create(ctx context.Context, req Request, confirmHash string) (*store.Rollout, error) {
	if req.StartAt.IsZero() {
		req.StartAt = r.now()
	}
	sch, err := r.Preview(req)
	if err != nil {
		return nil, err
	}
	if confirmHash == "" || confirmHash != sch.Hash {
		return nil, ErrNotConfirmed
	}
	if r.ReadOnly {
		return nil, errors.New("the console is in read only mode, so it will not start a rollout")
	}
	p, _ := PlanByID(req.PlanID)
	rings, _ := Resolve(p, req.Binding)

	initial, err := r.Assign.Current(ctx, req.TenantID, req.Kind, req.ObjectID)
	if err != nil {
		return nil, fmt.Errorf("read the policy's current assignment: %w", err)
	}
	if initial.Virtual != "" {
		return nil, errors.New("this policy is already assigned to everyone, so there is nothing left to stage")
	}
	planJSON, _ := json.Marshal(p)
	initJSON, _ := json.Marshal(initial)
	state := StateRunning
	if req.StartAt.After(r.now()) {
		state = StateScheduled
	}
	var sr []store.RolloutRing
	for i, rg := range rings {
		spec, _ := json.Marshal(rg)
		ring := store.RolloutRing{Index: i, Name: rg.Name, Spec: spec, State: RingPending}
		if i == 0 {
			ring.EligibleAt = req.StartAt.UTC().Format(time.RFC3339)
		}
		sr = append(sr, ring)
	}
	id, err := r.Store.CreateRollout(store.Rollout{TenantID: req.TenantID, PlanName: p.Name, Plan: planJSON, Kind: req.Kind,
		ObjectID: req.ObjectID, ObjectName: req.ObjectName, TemplateID: req.TemplateID, Initial: initJSON, State: state, CreatedBy: req.Actor}, sr)
	if err != nil {
		return nil, err
	}
	return r.Store.Rollout(id)
}

// Event describes one thing a Tick did, so the caller can alert on it.
type Event struct {
	RolloutID int64
	Tenant    string
	Name      string
	Ring      string
	What      string // activated | waiting | error | completed
	Detail    string
}

// Tick moves every active rollout as far as its rules allow. It is safe to call
// often and after a restart: each ring's activation is recorded only after the
// assignment succeeds, and the assignment it writes is the same every time.
func (r *Runner) Tick(ctx context.Context) []Event {
	if r.ReadOnly {
		return nil
	}
	list, err := r.Store.Rollouts("", true)
	if err != nil {
		r.logf("rollout: list: %v", err)
		return nil
	}
	var events []Event
	for i := range list {
		ro := &list[i]
		if ro.State != StateScheduled && ro.State != StateRunning {
			continue
		}
		events = append(events, r.advance(ctx, ro)...)
	}
	return events
}

func (r *Runner) advance(ctx context.Context, ro *store.Rollout) []Event {
	now := r.now()
	var events []Event
	if ro.State == StateScheduled {
		first := ro.Rings[0]
		if t, err := time.Parse(time.RFC3339, first.EligibleAt); err == nil && now.Before(t) {
			return nil
		}
		_ = r.Store.SetRolloutState(ro.ID, StateRunning, "")
		ro.State = StateRunning
	}
	var initial Assignment
	_ = json.Unmarshal(ro.Initial, &initial)

	// One ring per tick at most would be slow to catch up after downtime, so loop
	// while the next ring is ready.
	for {
		idx := -1
		for i, ring := range ro.Rings {
			if ring.State != RingActivated {
				idx = i
				break
			}
		}
		if idx < 0 {
			return events
		}
		ring := ro.Rings[idx]
		if ring.EligibleAt == "" {
			return events
		}
		if t, err := time.Parse(time.RFC3339, ring.EligibleAt); err != nil || now.Before(t) {
			return events
		}
		var spec RingSpec
		_ = json.Unmarshal(ring.Spec, &spec)

		if spec.Gate.ManualApproval && ring.ApprovedBy == "" {
			events = append(events, r.wait(ro, idx, ring, "waiting for a person to approve this ring"))
			return events
		}
		if spec.Gate.MinCompliantPercent > 0 && r.Check != nil {
			pct, err := r.Check.CompliantPercent(ctx, ro.TenantID, ro)
			if err != nil {
				events = append(events, r.wait(ro, idx, ring, "could not check device compliance: "+err.Error()))
				return events
			}
			if pct < spec.Gate.MinCompliantPercent {
				events = append(events, r.wait(ro, idx, ring, fmt.Sprintf("only %d%% of devices would comply and this ring needs %d%%", pct, spec.Gate.MinCompliantPercent)))
				return events
			}
		}

		desired := desiredAt(initial, ro.Rings, idx)
		if err := r.Assign.Set(ctx, ro.TenantID, ro.Kind, ro.ObjectID, desired); err != nil {
			_ = r.Store.UpdateRing(ro.ID, idx, RingError, "", "", err.Error())
			_ = r.Store.SetRolloutState(ro.ID, StateError, fmt.Sprintf("ring %q could not be activated: %v", ring.Name, err))
			return append(events, Event{ro.ID, ro.TenantID, ro.ObjectName, ring.Name, "error", err.Error()})
		}
		_ = r.Store.UpdateRing(ro.ID, idx, RingActivated, "", now.Format(time.RFC3339), "")
		ro.Rings[idx].State = RingActivated
		events = append(events, Event{ro.ID, ro.TenantID, ro.ObjectName, ring.Name, "activated", ""})

		if idx == len(ro.Rings)-1 {
			_ = r.Store.SetRolloutState(ro.ID, StateCompleted, "")
			return append(events, Event{ro.ID, ro.TenantID, ro.ObjectName, ring.Name, "completed", ""})
		}
		next := ro.Rings[idx+1]
		var nspec RingSpec
		_ = json.Unmarshal(next.Spec, &nspec)
		eligible := now.Add(time.Duration(nspec.WaitHours) * time.Hour).Format(time.RFC3339)
		_ = r.Store.UpdateRing(ro.ID, idx+1, RingPending, eligible, "", "")
		ro.Rings[idx+1].EligibleAt = eligible
	}
}

func (r *Runner) wait(ro *store.Rollout, idx int, ring store.RolloutRing, why string) Event {
	if ring.State != RingWaiting || ring.Detail != why {
		_ = r.Store.UpdateRing(ro.ID, idx, RingWaiting, "", "", why)
		return Event{ro.ID, ro.TenantID, ro.ObjectName, ring.Name, "waiting", why}
	}
	return Event{}
}

// desiredAt is what the policy should be assigned to once ring idx is active:
// what it had before, plus every ring up to this one. The everyone ring replaces
// the groups, as Intune's own deployments do.
func desiredAt(initial Assignment, rings []store.RolloutRing, idx int) Assignment {
	var spec RingSpec
	_ = json.Unmarshal(rings[idx].Spec, &spec)
	if spec.Virtual != "" {
		return Assignment{Virtual: spec.Virtual}
	}
	seen := map[string]bool{}
	var groups []string
	add := func(g string) {
		if k := strings.ToLower(g); !seen[k] {
			seen[k] = true
			groups = append(groups, g)
		}
	}
	for _, g := range initial.Groups {
		add(g)
	}
	for i := 0; i <= idx; i++ {
		var s RingSpec
		_ = json.Unmarshal(rings[i].Spec, &s)
		for _, g := range s.Groups {
			add(g)
		}
	}
	sort.Strings(groups)
	return Assignment{Groups: groups}
}

// ---- controls ----

// Pause stops a rollout where it is. Nothing is undone.
func (r *Runner) Pause(id int64, actor string) error {
	return r.change(id, func(ro *store.Rollout) (string, string, error) {
		if ro.State != StateRunning && ro.State != StateScheduled {
			return "", "", fmt.Errorf("a %s rollout cannot be paused", ro.State)
		}
		return StatePaused, "paused by " + actor, nil
	})
}

// Resume restarts a paused rollout, or one that stopped on an error.
func (r *Runner) Resume(id int64, actor string) error {
	return r.change(id, func(ro *store.Rollout) (string, string, error) {
		if ro.State != StatePaused && ro.State != StateError {
			return "", "", fmt.Errorf("a %s rollout cannot be resumed", ro.State)
		}
		for _, ring := range ro.Rings {
			if ring.State == RingError {
				_ = r.Store.UpdateRing(id, ring.Index, RingPending, "", "", "")
			}
		}
		return StateRunning, "resumed by " + actor, nil
	})
}

// Cancel ends a rollout. With revert, the policy goes back to what it was
// assigned to before the rollout started.
func (r *Runner) Cancel(ctx context.Context, id int64, actor string, revert bool) error {
	ro, err := r.Store.Rollout(id)
	if err != nil || ro == nil {
		return errors.New("no such rollout")
	}
	if ro.State == StateCompleted || ro.State == StateCanceled {
		return fmt.Errorf("a %s rollout cannot be canceled", ro.State)
	}
	note := "canceled by " + actor
	if revert {
		if r.ReadOnly {
			return errors.New("the console is in read only mode, so it will not change assignments")
		}
		var initial Assignment
		_ = json.Unmarshal(ro.Initial, &initial)
		if err := r.Assign.Set(ctx, ro.TenantID, ro.Kind, ro.ObjectID, initial); err != nil {
			return fmt.Errorf("the rollout was not canceled because putting the old assignment back failed: %w", err)
		}
		note += "; the policy was put back to its earlier assignment"
	}
	return r.Store.SetRolloutState(id, StateCanceled, note)
}

// Approve records a named person's approval of a ring. The ring starts at the
// next tick once it is also due.
func (r *Runner) Approve(id int64, ring int, by string) error {
	ro, err := r.Store.Rollout(id)
	if err != nil || ro == nil {
		return errors.New("no such rollout")
	}
	if ring < 0 || ring >= len(ro.Rings) {
		return errors.New("no such ring")
	}
	if ro.Rings[ring].State == RingActivated {
		return errors.New("that ring has already started")
	}
	return r.Store.ApproveRing(id, ring, by, r.now())
}

func (r *Runner) change(id int64, f func(*store.Rollout) (state, note string, err error)) error {
	ro, err := r.Store.Rollout(id)
	if err != nil || ro == nil {
		return errors.New("no such rollout")
	}
	state, note, err := f(ro)
	if err != nil {
		return err
	}
	return r.Store.SetRolloutState(id, state, note)
}
