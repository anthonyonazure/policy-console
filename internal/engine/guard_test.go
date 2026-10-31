package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/store"
)

// Whatever the source of a template, the console must refuse to create a
// policy that blocks every user from every app.
func TestDeployRefusesTenantLockout(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := catalog.Load("")
	cat.Replace("microsoft", []catalog.Template{catalog.FromBody("microsoft", catalog.KindConditionalAccess, "microsoft/lockout.json",
		[]byte(`{"displayName":"Microsoft | lockout","state":"enabledForReportingButNotEnforced","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"operator":"OR","builtInControls":["block"]}}`))})
	var id string
	for _, tpl := range cat.All() {
		if tpl.Category == "microsoft" {
			id = tpl.ID
		}
	}
	e := &Engine{Store: db, Catalog: cat}
	res, err := e.Deploy(context.Background(), DeployRequest{TenantID: "t", TemplateIDs: []string{id}, Preview: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].Result != "failed" {
		t.Fatalf("lockout policy was not refused: %+v", res.Items)
	}
}

// Continuous access evaluation exists only in beta; creating it through v1.0
// would silently drop the one control the policy exists for.
func TestBetaOnlyDetection(t *testing.T) {
	if !usesBetaOnly([]byte(`{"sessionControls":{"continuousAccessEvaluation":{"mode":"strictLocation"}}}`)) {
		t.Fatal("CAE session control not recognized as beta-only")
	}
	if usesBetaOnly([]byte(`{"sessionControls":{"signInFrequency":{"value":4}}}`)) {
		t.Fatal("a v1.0 session control was sent to beta")
	}
}
