package engine

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/store"
)

func TestPilotNarrowsOnlyAllUsersPolicies(t *testing.T) {
	all := []byte(`{"conditions":{"users":{"includeUsers":["All"],"excludeGroups":["bg"]}}}`)
	out, note, err := applyPilot(all, "pilot")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]map[string][]string
	_ = json.Unmarshal(out, &doc)
	u := doc["conditions"]["users"]
	if len(u["includeUsers"]) != 0 || len(u["includeGroups"]) != 1 || u["includeGroups"][0] != "pilot" || u["excludeGroups"][0] != "bg" {
		t.Fatalf("pilot not applied correctly (%s): %s", note, out)
	}
	// Admin-role policies must not be shrunk to a pilot group: that would
	// leave every other administrator unprotected.
	roles := []byte(`{"conditions":{"users":{"includeRoles":["r1","r2"]}}}`)
	out2, _, _ := applyPilot(roles, "pilot")
	if string(out2) != string(roles) {
		t.Fatalf("role-targeted policy was narrowed: %s", out2)
	}
}

func TestReportOnlyAgeFromHistory(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: db}
	save := func(state string) {
		_, _, err := db.SaveVersion(store.Version{TenantID: "t", Kind: string(catalog.KindConditionalAccess), ObjectID: "p",
			Name: "P", Source: "scheduled", Body: []byte(`{"state":"` + state + `","n":"` + time.Now().String() + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	save("enabledForReportingButNotEnforced")
	if _, ro, _ := e.ReportOnlySince("t", "p"); !ro {
		t.Fatal("report-only policy not recognized")
	}
	save("enabled")
	if _, ro, _ := e.ReportOnlySince("t", "p"); ro {
		t.Fatal("an enforced policy was reported as report-only")
	}
}
