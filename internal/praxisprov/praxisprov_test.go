package praxisprov

import (
	"encoding/json"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/equiv"
)

// A Praxis template is only worth its name if every setting says where it came
// from. These rules are what separate it from a hand-typed baseline.
func TestEverySettingHasASource(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, tpl := range p.Templates {
		if len(tpl.Settings) == 0 {
			t.Errorf("%s: no settings recorded", name)
		}
		for _, s := range tpl.Settings {
			switch s.Source {
			case "library":
				if len(s.Citations) == 0 {
					t.Errorf("%s / %s: claims the library but cites nothing", name, s.Setting)
				}
				for _, c := range s.Citations {
					if c.Passage == 0 || c.Course == "" {
						t.Errorf("%s / %s: incomplete citation %+v", name, s.Setting, c)
					}
				}
			case "microsoft", "judgement":
				if s.Note == "" {
					t.Errorf("%s / %s: %s value with no explanation", name, s.Setting, s.Source)
				}
			default:
				t.Errorf("%s / %s: unknown source %q", name, s.Setting, s.Source)
			}
		}
	}
}

func TestEveryPraxisTemplateHasProvenance(t *testing.T) {
	p, _ := Load()
	cat, err := catalog.Load("")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, tpl := range cat.All() {
		if tpl.Category != "praxis" {
			continue
		}
		n++
		if _, ok := p.Templates[tpl.Name]; !ok {
			t.Errorf("%s has no provenance", tpl.Name)
		}
	}
	if n == 0 {
		t.Fatal("no Praxis templates loaded")
	}
}

// The Praxis set exists partly because two House templates do not do what
// their names say. It must not repeat that.
func TestPraxisNamesMatchBehavior(t *testing.T) {
	cat, _ := catalog.Load("")
	for _, tpl := range cat.All() {
		if tpl.Category != "praxis" || tpl.Kind != catalog.KindConditionalAccess {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(tpl.Body, &doc); err != nil {
			t.Fatalf("%s: %v", tpl.Name, err)
		}
		sh, err := equiv.Parse(tpl.Body)
		if err != nil {
			t.Fatal(err)
		}
		if w := equiv.AuditName(sh); len(w) > 0 {
			t.Errorf("%s: %v", tpl.Name, w)
		}
		if equiv.BlocksEveryone(sh) {
			t.Errorf("%s would block every user from every app", tpl.Name)
		}
	}
}
