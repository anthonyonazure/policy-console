package score

import (
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/equiv"
)

// Controls that demand phishing-resistant MFA. Claiming full coverage of these
// from a template that grants ordinary MFA is how C003b overclaimed.
var phishingResistantControls = map[string]bool{"MS.AAD.3.1v1": true, "MS.AAD.3.6v1": true}

func TestPhishingResistantClaimsMatchBehavior(t *testing.T) {
	cat, err := catalog.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range cat.All() {
		for _, c := range loaded.Templates[tpl.ID] {
			promises := phishingResistantControls[c.ID] || strings.Contains(strings.ToLower(c.Title), "phishing-resistant")
			if !promises || c.Coverage == "partial" {
				continue
			}
			s, err := equiv.Parse(tpl.Body)
			if err != nil {
				t.Fatal(err)
			}
			if s.Action.MFALevel < 3 {
				t.Errorf("%s claims full coverage of %s but grants %s", tpl.Name, c.ID, s.Action)
			}
		}
	}
}

// Every template id in the mapping must exist, or its claims silently vanish.
func TestMappingNamesRealTemplates(t *testing.T) {
	cat, _ := catalog.Load("")
	for id := range loaded.Templates {
		if cat.Get(id) == nil {
			t.Errorf("mapping refers to template %q, which is not in the baseline", id)
		}
	}
}
