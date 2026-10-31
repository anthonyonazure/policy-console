package drift

import (
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/diff"
	"github.com/anthonyonazure/policy-console/internal/engine"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func ca(id string) catalog.Template {
	return catalog.Template{ID: id, Name: id, Kind: catalog.KindConditionalAccess}
}
func cfg(id string) catalog.Template {
	return catalog.Template{ID: id, Name: id, Kind: catalog.KindConfigPolicy}
}

func find(fs []store.Finding, id string) *store.Finding {
	for i := range fs {
		if fs[i].TemplateID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestSeverityFollowsWhatHurts(t *testing.T) {
	cmp := &engine.CompareResult{Items: []engine.TemplateStatus{
		{Template: ca("ca-missing"), State: "missing"},
		{Template: ca("ca-off"), State: "matches", LiveState: "disabled"},
		{Template: ca("ca-off-and-edited"), State: "drifted", LiveState: "disabled", Changes: []diff.Change{{Path: "a"}}},
		{Template: ca("ca-edited"), State: "drifted", LiveState: "enabled", Changes: []diff.Change{{Path: "grantControls"}}},
		{Template: cfg("cfg-missing"), State: "missing"},
		{Template: ca("ca-fine"), State: "matches", LiveState: "enabled"},
		{Template: ca("ca-report-only"), State: "matches", LiveState: "enabledForReportingButNotEnforced"},
	}}
	r := Evaluate(cmp, nil, time.Now())
	want := map[string][2]string{
		"ca-missing":        {ClassMissing, Critical},
		"ca-off":            {ClassDisabled, Critical},
		"ca-off-and-edited": {ClassDisabled, Critical},
		"ca-edited":         {ClassChanged, Warning},
		"cfg-missing":       {ClassMissing, Warning},
	}
	for id, w := range want {
		f := find(r.Findings, id)
		if f == nil || f.Class != w[0] || f.Severity != w[1] {
			t.Errorf("%s: got %+v, want class %s severity %s", id, f, w[0], w[1])
		}
	}
	for _, id := range []string{"ca-fine", "ca-report-only"} {
		if find(r.Findings, id) != nil {
			t.Errorf("%s should not be a finding", id)
		}
	}
}

func TestUncheckedTemplatesAreNotDriftAndNotHidden(t *testing.T) {
	cmp := &engine.CompareResult{Items: []engine.TemplateStatus{{Template: ca("needs-values"), State: "error", Note: "unfilled"}}}
	r := Evaluate(cmp, nil, time.Now())
	if len(r.Findings) != 0 || r.Unchecked != 1 || r.UncheckedN[0] != "needs-values" {
		t.Fatalf("unfilled template must be reported as unchecked only: %+v", r)
	}
}

func TestExceptionsSilenceUntilTheyExpire(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	cmp := &engine.CompareResult{
		Items:     []engine.TemplateStatus{{Template: ca("c1"), State: "missing"}, {Template: ca("c2"), State: "missing"}},
		Unmanaged: []store.Version{{Kind: "policies", ObjectID: "o1", Name: "Client made this"}},
	}
	ex := []store.Exception{
		{TemplateID: "c1"}, // no expiry
		{TemplateID: "c2", ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}, // lapsed
		{TemplateID: ExtraID("policies", "o1"), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
	}
	r := Evaluate(cmp, ex, now)
	if r.Excepted != 2 {
		t.Fatalf("excepted = %d, want 2", r.Excepted)
	}
	if len(r.Findings) != 1 || r.Findings[0].TemplateID != "c2" {
		t.Fatalf("a lapsed exception must let the finding back in: %+v", r.Findings)
	}
}

func TestUnmanagedObjectsAreInfoOnly(t *testing.T) {
	cmp := &engine.CompareResult{Unmanaged: []store.Version{{Kind: "policies", ObjectID: "o1", Name: "x"}}}
	r := Evaluate(cmp, nil, time.Now())
	if len(r.Findings) != 1 || r.Findings[0].Severity != Info || r.Findings[0].Class != ClassExtra {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestMissingCompliancePolicyIsCritical(t *testing.T) {
	cmp := &engine.CompareResult{Items: []engine.TemplateStatus{
		{Template: catalog.Template{ID: "comp", Name: "comp", Kind: catalog.KindCompliance}, State: "missing"},
		{Template: catalog.Template{ID: "app", Name: "app", Kind: catalog.KindIOSAppProtection}, State: "missing"},
		{Template: catalog.Template{ID: "err", Name: "err", Kind: catalog.KindCompliance}, State: "error"},
	}}
	r := Evaluate(cmp, nil, time.Now())
	if f := find(r.Findings, "comp"); f == nil || f.Severity != Critical {
		t.Fatalf("compliance missing: %+v", f)
	}
	if f := find(r.Findings, "app"); f == nil || f.Severity != Warning {
		t.Fatalf("app protection missing: %+v", f)
	}
	if len(r.UncheckedIDs) != 1 || r.UncheckedIDs[0] != "err" {
		t.Fatalf("unchecked ids: %v", r.UncheckedIDs)
	}
}
