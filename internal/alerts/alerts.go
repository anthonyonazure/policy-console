// Package alerts runs the scheduled drift check for each client and tells the
// right person at the right volume: critical drift reaches Teams once per
// client as it appears, and everything else waits for one daily email digest.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/drift"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/notify"
	"github.com/anthonyonazure/policy-console/internal/store"
)

const kvLastDigest = "alerts.last_digest"

// ErrChangeInProgress means a deploy or rollout is running on the client, so the
// scheduled check stepped aside and will run next cycle. It is not a failure.
var ErrChangeInProgress = errors.New("a change is in progress on this client, so the drift check was skipped")

// Gate lets a scheduled check step aside when a change is running on the client.
type Gate interface {
	TryRead(tenant string) (end func(), ok bool)
}

// Comparer is the part of the engine this package needs, so tests can stand in.
type Comparer interface {
	Compare(ctx context.Context, tenantID string, tokens map[string]string, state string) (*engine.CompareResult, error)
}

type Service struct {
	Compare     Comparer
	Gate        Gate // optional; when set, a client with a change in progress is skipped
	Store       *store.Store
	Notifier    notify.Notifier
	Logf        func(format string, args ...any)
	Now         func() time.Time
	DigestEvery time.Duration // default 24h
}

// CheckResult is what one client's check found.
type CheckResult struct {
	Tenant     string
	Open       int
	Opened     int
	Resolved   int
	Excepted   int
	Unchecked  []string
	CriticalTo int // critical findings announced to Teams in this check
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

// Check compares one client with the standard, records the findings, and
// announces any critical ones that nobody has been told about yet.
//
// A failed comparison changes nothing: if Graph is unreachable we must not
// conclude that every finding has been fixed.
func (s *Service) Check(ctx context.Context, t store.Tenant) (*CheckResult, error) {
	if s.Gate != nil {
		end, ok := s.Gate.TryRead(t.ID)
		if !ok {
			return nil, ErrChangeInProgress
		}
		defer end()
	}
	tokens, err := s.Store.Tokens(t.ID)
	if err != nil {
		return nil, fmt.Errorf("client values: %w", err)
	}
	cmp, err := s.Compare.Compare(ctx, t.ID, tokens, "")
	if err != nil {
		return nil, fmt.Errorf("compare: %w", err)
	}
	exceptions, err := s.Store.Exceptions(t.ID)
	if err != nil {
		return nil, fmt.Errorf("exceptions: %w", err)
	}
	now := s.now()
	ev := drift.Evaluate(cmp, exceptions, now)
	// Findings for anything this check could not look at stay open.
	unchecked := map[string]bool{}
	for _, id := range ev.UncheckedIDs {
		unchecked[id] = true
	}
	var unreadableExtra []string
	for _, k := range cmp.Unreadable {
		unreadableExtra = append(unreadableExtra, drift.ExtraID(k, ""))
	}
	keep := func(f store.Finding) bool {
		if unchecked[f.TemplateID] {
			return true
		}
		for _, p := range unreadableExtra {
			if strings.HasPrefix(f.TemplateID, p) {
				return true
			}
		}
		return false
	}
	change, err := s.Store.ApplyFindings(t.ID, ev.Findings, keep, now)
	if err != nil {
		return nil, fmt.Errorf("record findings: %w", err)
	}
	open, err := s.Store.OpenFindings(t.ID)
	if err != nil {
		return nil, err
	}
	res := &CheckResult{Tenant: t.Name, Open: len(open), Opened: len(change.Opened), Resolved: len(change.Resolved),
		Excepted: ev.Excepted, Unchecked: ev.UncheckedN}

	// Retry-safe: look at everything critical and still untold, not only what is new,
	// so a Teams outage delays the message instead of losing it.
	var pending []store.Finding
	for _, f := range open {
		if f.Severity == drift.Critical && f.NotifiedAt == "" && f.State == store.StateNew {
			pending = append(pending, f)
		}
	}
	if teams, _ := s.Notifier.Enabled(); teams && len(pending) > 0 {
		lines := make([]string, 0, len(pending))
		ids := make([]int64, 0, len(pending))
		for _, f := range pending {
			lines = append(lines, fmt.Sprintf("%s: %s. %s", f.Class, f.Name, f.Detail))
			ids = append(ids, f.ID)
		}
		title := fmt.Sprintf("Policy drift needs attention: %s (%d critical)", t.Name, len(pending))
		if err := s.Notifier.Teams(ctx, title, lines); err != nil {
			s.logf("alerts: teams post for %s failed, will retry next check: %v", t.Name, err)
		} else if err := s.Store.MarkNotified(ids, now); err != nil {
			return res, fmt.Errorf("mark notified: %w", err)
		} else {
			res.CriticalTo = len(pending)
		}
	}
	return res, nil
}

// CheckAll runs Check for every connected client, one at a time so a large
// fleet never bursts Graph, then sends the daily digest if it is due.
func (s *Service) CheckAll(ctx context.Context) {
	tenants, err := s.Store.Tenants()
	if err != nil {
		s.logf("alerts: list tenants: %v", err)
		return
	}
	for _, t := range tenants {
		if t.Status != "connected" {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		r, err := s.Check(ctx, t)
		if errors.Is(err, ErrChangeInProgress) {
			s.logf("alerts: %s: %v", t.Name, err)
			continue
		}
		if err != nil {
			s.logf("alerts: drift check %s: %v", t.Name, err)
			continue
		}
		s.logf("alerts: %s: %d open, %d new, %d resolved, %d excepted, %d unchecked, %d critical announced",
			r.Tenant, r.Open, r.Opened, r.Resolved, r.Excepted, len(r.Unchecked), r.CriticalTo)
	}
	if err := s.DigestIfDue(ctx); err != nil {
		s.logf("alerts: digest: %v", err)
	}
}

// DigestIfDue sends one email covering every open finding across all clients,
// at most once per DigestEvery. Nothing is sent when nothing is open.
func (s *Service) DigestIfDue(ctx context.Context) error {
	if _, email := s.Notifier.Enabled(); !email {
		return nil
	}
	every := s.DigestEvery
	if every <= 0 {
		every = 24 * time.Hour
	}
	now := s.now()
	if last, _ := s.Store.KV(kvLastDigest); last != "" {
		if lt, err := time.Parse(time.RFC3339, last); err == nil && now.Sub(lt) < every {
			return nil
		}
	}
	open, err := s.Store.AllOpenFindings()
	if err != nil {
		return err
	}
	// Acknowledged and snoozed findings are someone's job already: leave them out of the email.
	shown := open[:0:0]
	for _, f := range open {
		if f.State == store.StateNew {
			shown = append(shown, f)
		}
	}
	suppressed := len(open) - len(shown)
	open = shown
	if len(open) == 0 {
		return nil
	}
	names := map[string]string{}
	if ts, err := s.Store.Tenants(); err == nil {
		for _, t := range ts {
			names[t.ID] = t.Name
		}
	}
	subject, body := Digest(open, names)
	if suppressed > 0 {
		body += fmt.Sprintf("\n%d more finding(s) are acknowledged or snoozed and not listed here.\n", suppressed)
	}
	if err := s.Notifier.Email(ctx, subject, body); err != nil {
		return err
	}
	return s.Store.SetKV(kvLastDigest, now.UTC().Format(time.RFC3339))
}

// Digest renders open findings as plain text, worst clients first. It is a
// pure function so the wording can be tested without a mail server.
func Digest(open []store.Finding, tenantNames map[string]string) (subject, body string) {
	type group struct {
		name     string
		findings []store.Finding
		critical int
	}
	by := map[string]*group{}
	crit := 0
	for _, f := range open {
		g := by[f.TenantID]
		if g == nil {
			n := tenantNames[f.TenantID]
			if n == "" {
				n = f.TenantID
			}
			g = &group{name: n}
			by[f.TenantID] = g
		}
		g.findings = append(g.findings, f)
		if f.Severity == drift.Critical {
			g.critical++
			crit++
		}
	}
	groups := make([]*group, 0, len(by))
	for _, g := range by {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].critical != groups[j].critical {
			return groups[i].critical > groups[j].critical
		}
		return groups[i].name < groups[j].name
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%d open finding(s) across %d client(s); %d critical.\n", len(open), len(groups), crit)
	for _, g := range groups {
		fmt.Fprintf(&b, "\n%s (%d)\n", g.name, len(g.findings))
		for _, f := range g.findings {
			fmt.Fprintf(&b, "  [%s] %s: %s. %s\n", f.Severity, f.Class, f.Name, f.Detail)
		}
	}
	return fmt.Sprintf("Policy drift digest: %d open, %d critical", len(open), crit), b.String()
}
