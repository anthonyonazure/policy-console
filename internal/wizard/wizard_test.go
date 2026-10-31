package wizard

import (
	"strings"
	"testing"

	"github.com/anthonyonazure/policy-console/internal/catalog"
)

func tpl(id, category, body string, kind catalog.Kind, code string) catalog.Template {
	return catalog.Template{ID: id, Name: id, Category: category, Kind: kind, Code: code, Body: []byte(body)}
}

func fixture() []catalog.Template {
	win := `{"name":"w","platforms":"windows10","settings":[{}]}`
	mac := `{"name":"m","platforms":"macOS","settings":[{}]}`
	ios := `{"name":"i","platforms":"iOS","settings":[{}]}`
	return []catalog.Template{
		tpl("intune-win", "intune", win, catalog.KindConfigPolicy, ""),
		tpl("intune-mac", "intune", mac, catalog.KindConfigPolicy, ""),
		tpl("intune-ios", "intune", ios, catalog.KindConfigPolicy, ""),
		tpl("defender-win", "defender", win, catalog.KindConfigPolicy, ""),
		tpl("pack-compliance-win", "pack-compliance", `{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"x"}`, catalog.KindCompliance, ""),
		tpl("pack-compliance-mac", "pack-compliance", `{"@odata.type":"#microsoft.graph.macOSCompliancePolicy","displayName":"x"}`, catalog.KindCompliance, ""),
		tpl("ca-c001", "conditional-access", `{"displayName":"c1"}`, catalog.KindConditionalAccess, "C001"),
		tpl("ca-c015", "conditional-access", `{"displayName":"c15"}`, catalog.KindConditionalAccess, "C015"),
		tpl("byod-ios", "oib-byod", `{"@odata.type":"#microsoft.graph.iosManagedAppProtection","displayName":"b"}`, catalog.KindIOSAppProtection, ""),
	}
}

func byID(p Plan) map[string]Step {
	m := map[string]Step{}
	for _, s := range p.Steps {
		m[s.ID] = s
	}
	return m
}

func TestEveryStepComesAfterWhatItDependsOn(t *testing.T) {
	for _, a := range []Answers{
		{Platforms: []string{"Windows"}},
		{Platforms: []string{"Windows", "macOS", "iOS", "Android"}, Ownership: "both", Regulated: true},
		{Platforms: []string{"Windows"}, Brownfield: true, ThirdPartyEDR: true},
	} {
		p := Build(a, fixture())
		pos := map[string]int{}
		for i, s := range p.Steps {
			pos[s.ID] = i
		}
		for i, s := range p.Steps {
			for _, d := range s.DependsOn {
				if j, ok := pos[d]; !ok || j >= i {
					t.Fatalf("step %q depends on %q which is missing or later: %+v", s.ID, d, a)
				}
			}
		}
		if p.Steps[0].ID != "discover" || p.Steps[len(p.Steps)-1].ID != "handover" {
			t.Fatalf("always look first and report last: %v", p.Steps)
		}
	}
}

func TestOnlyTheChosenPlatformsGetPolicies(t *testing.T) {
	p := byID(Build(Answers{Platforms: []string{"Windows"}}, fixture()))
	sec := strings.Join(p["security"].TemplateIDs, ",")
	if !strings.Contains(sec, "intune-win") || strings.Contains(sec, "intune-mac") || strings.Contains(sec, "intune-ios") {
		t.Fatalf("a Windows client gets Windows policies: %s", sec)
	}
	if strings.Join(p["compliance"].TemplateIDs, ",") != "pack-compliance-win" {
		t.Fatalf("%v", p["compliance"].TemplateIDs)
	}
	if _, ok := p["apple-prereqs"]; ok {
		t.Fatal("no Apple setup for a Windows only client")
	}
	if _, ok := p["mobile"]; ok {
		t.Fatal("no phone app protection for a corporate Windows client")
	}
	// Conditional Access has no platform, so it always applies.
	if !strings.Contains(strings.Join(p["identity"].TemplateIDs, ","), "ca-c001") {
		t.Fatal("identity")
	}
}

func TestAThirdPartyEDRLeavesDefenderOut(t *testing.T) {
	with := byID(Build(Answers{Platforms: []string{"Windows"}}, fixture()))
	without := byID(Build(Answers{Platforms: []string{"Windows"}, ThirdPartyEDR: true}, fixture()))
	if !strings.Contains(strings.Join(with["security"].TemplateIDs, ","), "defender-win") {
		t.Fatal("Defender is in the standard plan")
	}
	if strings.Contains(strings.Join(without["security"].TemplateIDs, ","), "defender-win") || len(without["security"].Notes) < 2 {
		t.Fatalf("left out, and the plan says why: %+v", without["security"])
	}
}

func TestBYODAndApplePlatformsAddTheirSteps(t *testing.T) {
	p := byID(Build(Answers{Platforms: []string{"iOS", "Android"}, Ownership: "byod"}, fixture()))
	for _, id := range []string{"apple-prereqs", "android-prereqs", "mobile"} {
		if _, ok := p[id]; !ok {
			t.Errorf("missing step %s", id)
		}
	}
	if p["apple-prereqs"].Type != TypeManual {
		t.Error("the console cannot create an Apple push certificate; it must be a manual step")
	}
}

func TestDeviceBasedAccessPoliciesWaitForTheCompliantPilot(t *testing.T) {
	p := byID(Build(Answers{Platforms: []string{"Windows"}}, fixture()))
	dev := p["identity-devices"]
	if strings.Join(dev.TemplateIDs, ",") != "ca-c015" {
		t.Fatalf("%v", dev.TemplateIDs)
	}
	if !strings.Contains(strings.Join(dev.DependsOn, ","), "pilot") {
		t.Fatalf("the policies that lock out unmanaged devices come only after the pilot proves devices comply: %v", dev.DependsOn)
	}
	if strings.Contains(strings.Join(p["identity"].TemplateIDs, ","), "ca-c015") {
		t.Fatal("C015 must not be in the early identity step")
	}
	if p["pilot"].Type != TypeGate {
		t.Fatal("the pilot is a gate: a person confirms it")
	}
}

func TestGreenfieldHasTheSecurityDefaultsStepAndBrownfieldHasTheConflictCheck(t *testing.T) {
	g := byID(Build(Answers{Platforms: []string{"Windows"}}, fixture()))
	b := byID(Build(Answers{Platforms: []string{"Windows"}, Brownfield: true}, fixture()))
	if _, ok := g["security-defaults"]; !ok {
		t.Fatal("a new tenant has Security Defaults on")
	}
	if _, ok := g["conflicts"]; ok {
		t.Fatal("nothing to collide with in a new tenant")
	}
	if _, ok := b["conflicts"]; !ok {
		t.Fatal("an existing tenant needs the overlap check")
	}
	if _, ok := b["security-defaults"]; ok {
		t.Fatal("an existing tenant is not assumed to be on Security Defaults")
	}
}

func TestAnswersAreCleanedAndRegulatedClientsGetAnAssessment(t *testing.T) {
	a := Answers{Platforms: []string{"windows", "Windows", "Amiga", "Windows"}, Ownership: "weird"}.Normalize()
	if len(a.Platforms) != 1 || a.Platforms[0] != "Windows" || a.Ownership != "corporate" {
		t.Fatalf("%+v", a)
	}
	if got := (Answers{}).Normalize(); got.Platforms[0] != "Windows" {
		t.Fatal("a Windows plan is the default")
	}
	if _, ok := byID(Build(Answers{Regulated: true}, fixture()))["assess"]; !ok {
		t.Fatal("regulated clients need evidence")
	}
}

func TestCountsAddUp(t *testing.T) {
	p := Build(Answers{Platforms: []string{"Windows", "macOS"}}, fixture())
	deploy, tpls := 0, 0
	for _, s := range p.Steps {
		if s.Type == TypeDeploy {
			deploy++
		}
		tpls += len(s.TemplateIDs)
	}
	if p.Counts.Steps != len(p.Steps) || p.Counts.Deploy != deploy || p.Counts.Templates != tpls {
		t.Fatalf("%+v", p.Counts)
	}
}
