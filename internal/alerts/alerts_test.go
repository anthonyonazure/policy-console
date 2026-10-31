package alerts

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type fakeCompare struct {
	res *engine.CompareResult
	err error
}

func (f *fakeCompare) Compare(context.Context, string, map[string]string, string) (*engine.CompareResult, error) {
	return f.res, f.err
}

type fakeNotifier struct {
	teams, email      bool
	teamsErr          error
	teamsMsgs, emails []string
}

func (n *fakeNotifier) Enabled() (bool, bool) { return n.teams, n.email }
func (n *fakeNotifier) Teams(_ context.Context, title string, lines []string) error {
	if n.teamsErr != nil {
		return n.teamsErr
	}
	n.teamsMsgs = append(n.teamsMsgs, title+"\n"+strings.Join(lines, "\n"))
	return nil
}
func (n *fakeNotifier) Email(_ context.Context, subject, body string) error {
	n.emails = append(n.emails, subject+"\n"+body)
	return nil
}

func setup(t *testing.T) (*Service, *fakeCompare, *fakeNotifier, store.Tenant) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tn := store.Tenant{ID: "t1", Name: "Acme", Status: "connected"}
	_ = db.UpsertTenant(tn)
	fc := &fakeCompare{res: &engine.CompareResult{}}
	fn := &fakeNotifier{teams: true, email: true}
	clock := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	svc := &Service{Compare: fc, Store: db, Notifier: fn, Logf: t.Logf, Now: func() time.Time { return clock }}
	return svc, fc, fn, tn
}

func caMissing(id string) engine.TemplateStatus {
	return engine.TemplateStatus{Template: catalog.Template{ID: id, Name: id, Kind: catalog.KindConditionalAccess}, State: "missing"}
}

func TestCriticalIsAnnouncedOnceNotEveryCheck(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1"), caMissing("c2")}
	for i := 0; i < 3; i++ {
		if _, err := svc.Check(context.Background(), tn); err != nil {
			t.Fatal(err)
		}
	}
	if len(fn.teamsMsgs) != 1 {
		t.Fatalf("want exactly one Teams message for the client, got %d", len(fn.teamsMsgs))
	}
	if !strings.Contains(fn.teamsMsgs[0], "c1") || !strings.Contains(fn.teamsMsgs[0], "c2") {
		t.Fatalf("both findings belong in the one message: %s", fn.teamsMsgs[0])
	}
}

func TestTeamsOutageDelaysTheMessageInsteadOfLosingIt(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1")}
	fn.teamsErr = errors.New("503")
	if _, err := svc.Check(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	fn.teamsErr = nil
	if _, err := svc.Check(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	if len(fn.teamsMsgs) != 1 {
		t.Fatalf("message must go out once the outage ends, got %d", len(fn.teamsMsgs))
	}
}

func TestWarningsDoNotInterruptTeams(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{{Template: catalog.Template{ID: "d1", Name: "d1", Kind: catalog.KindConfigPolicy}, State: "missing"}}
	_, _ = svc.Check(context.Background(), tn)
	if len(fn.teamsMsgs) != 0 {
		t.Fatal("a non-critical finding must wait for the digest")
	}
}

func TestFailedCompareDoesNotResolveAnything(t *testing.T) {
	svc, fc, _, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1")}
	_, _ = svc.Check(context.Background(), tn)
	fc.err = errors.New("graph unreachable")
	if _, err := svc.Check(context.Background(), tn); err == nil {
		t.Fatal("error must surface")
	}
	if open, _ := svc.Store.OpenFindings("t1"); len(open) != 1 {
		t.Fatalf("an outage must not look like a fix: %+v", open)
	}
}

func TestExceptionSilencesAndResolvesTheFinding(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1")}
	_, _ = svc.Check(context.Background(), tn)
	_, _ = svc.Store.AddException(store.Exception{TenantID: "t1", TemplateID: "c1", Reason: "client approved", Owner: "anthony"})
	r, _ := svc.Check(context.Background(), tn)
	if r.Open != 0 || r.Resolved != 1 || r.Excepted != 1 {
		t.Fatalf("%+v", r)
	}
	if len(fn.teamsMsgs) != 1 {
		t.Fatal("exception must not trigger a second message")
	}
}

func TestDigestOncePerDayAndOnlyWhenSomethingIsOpen(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	if err := svc.DigestIfDue(context.Background()); err != nil || len(fn.emails) != 0 {
		t.Fatal("nothing open means no email")
	}
	fc.res.Items = []engine.TemplateStatus{caMissing("c1")}
	_, _ = svc.Check(context.Background(), tn)
	_ = svc.DigestIfDue(context.Background())
	_ = svc.DigestIfDue(context.Background())
	if len(fn.emails) != 1 {
		t.Fatalf("one digest per day, got %d", len(fn.emails))
	}
	later := svc.Now().Add(25 * time.Hour)
	svc.Now = func() time.Time { return later }
	_ = svc.DigestIfDue(context.Background())
	if len(fn.emails) != 2 {
		t.Fatalf("next day sends again, got %d", len(fn.emails))
	}
}

func TestDigestWordingPutsWorstClientFirst(t *testing.T) {
	open := []store.Finding{
		{TenantID: "a", Severity: "warning", Class: "changed", Name: "W", Detail: "d"},
		{TenantID: "b", Severity: "critical", Class: "missing", Name: "C", Detail: "d"},
	}
	subj, body := Digest(open, map[string]string{"a": "Alpha", "b": "Bravo"})
	if !strings.Contains(subj, "1 critical") || strings.Index(body, "Bravo") > strings.Index(body, "Alpha") {
		t.Fatalf("%s\n%s", subj, body)
	}
}

func compMissing(id string) engine.TemplateStatus {
	return engine.TemplateStatus{Template: catalog.Template{ID: id, Name: id, Kind: catalog.KindCompliance}, State: "missing"}
}

// A client admin revoking one permission must not make that kind's findings
// disappear. Not looking is not the same as fixed.
func TestRevokedPermissionDoesNotResolveThatKindsFindings(t *testing.T) {
	svc, fc, _, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{compMissing("comp1"), caMissing("ca1")}
	fc.res.Unmanaged = []store.Version{{Kind: string(catalog.KindCompliance), ObjectID: "o9", Name: "extra compliance"}}
	if _, err := svc.Check(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	// The compliance kind turns unreadable; CA is still fine and still missing.
	fc.res = &engine.CompareResult{
		Items: []engine.TemplateStatus{
			{Template: catalog.Template{ID: "comp1", Name: "comp1", Kind: catalog.KindCompliance}, State: "error"},
			caMissing("ca1"),
		},
		Unreadable: []string{string(catalog.KindCompliance)},
	}
	r, err := svc.Check(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved != 0 {
		t.Fatalf("nothing may be resolved by not looking: resolved %d", r.Resolved)
	}
	open, _ := svc.Store.OpenFindings("t1")
	if len(open) != 3 { // the compliance template, the compliance extra, the CA template
		t.Fatalf("open findings = %d: %+v", len(open), open)
	}
	// Once readable again and genuinely fixed, it does resolve.
	fc.res = &engine.CompareResult{Items: []engine.TemplateStatus{
		{Template: catalog.Template{ID: "comp1", Name: "comp1", Kind: catalog.KindCompliance}, State: "matches"}, caMissing("ca1")}}
	r, _ = svc.Check(context.Background(), tn)
	if r.Resolved != 2 {
		t.Fatalf("readable and fixed should resolve the compliance finding and its extra: %d", r.Resolved)
	}
}

type busyGate struct{ busy bool }

func (g busyGate) TryRead(string) (func(), bool) { return func() {}, !g.busy }

func TestACheckStepsAsideWhileAChangeRunsOnTheClient(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1")}
	svc.Gate = busyGate{busy: true}
	if _, err := svc.Check(context.Background(), tn); !errors.Is(err, ErrChangeInProgress) {
		t.Fatalf("want ErrChangeInProgress: %v", err)
	}
	if len(fn.teamsMsgs) != 0 {
		t.Fatal("a skipped check must say nothing")
	}
	svc.Gate = busyGate{busy: false}
	if _, err := svc.Check(context.Background(), tn); err != nil || len(fn.teamsMsgs) != 1 {
		t.Fatalf("it runs once the change is done: %v", err)
	}
}

func TestAcknowledgedFindingsLeaveTheDigestAndTheTeamsMessage(t *testing.T) {
	svc, fc, fn, tn := setup(t)
	fc.res.Items = []engine.TemplateStatus{caMissing("c1"), compMissing("k1")}
	svc.Gate = nil
	// Take one finding before the first check announces it: add it, ack it, then check.
	if _, err := svc.Store.ApplyFindings("t1", nil, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	open, _ := svc.Store.OpenFindings("t1")
	for _, f := range open {
		if f.TemplateID == "c1" {
			_ = svc.Store.Acknowledge(f.ID, "anthony", "known", time.Now())
		}
	}
	if err := svc.DigestIfDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fn.emails) != 1 {
		t.Fatalf("emails: %d", len(fn.emails))
	}
	body := fn.emails[0]
	if strings.Contains(body, "c1") || !strings.Contains(body, "k1") || !strings.Contains(body, "1 more finding(s) are acknowledged or snoozed") {
		t.Fatalf("the digest must leave out what someone has taken and say how many:\n%s", body)
	}
}
