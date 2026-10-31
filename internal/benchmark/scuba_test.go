package benchmark

import "testing"

// A fixture in the published shape. If CISA changes the format, this test fails
// and the console keeps its cached catalog rather than reporting zero controls,
// which would read as "no controls to meet" in a client report.
const fixture = `
# CISA M365 Secure Configuration Baseline for Microsoft Entra ID

## 1. Legacy Authentication

### Policies
#### MS.AAD.1.1v1
Legacy authentication SHALL be blocked.

<!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->
- _Rationale:_ something
- _Last modified:_ June 2026

### Implementation
#### MS.AAD.1.1v1 Instructions
1. Open the portal.

## 2. Risk Based Policies

### Policies
#### MS.AAD.2.2v1
A notification SHOULD be sent to the administrator.

<!--Policy: MS.AAD.2.2v1; Criticality: SHOULD -->
`

func TestParseScuba(t *testing.T) {
	got := parseScuba("aad", fixture)
	if len(got) != 2 {
		t.Fatalf("expected 2 controls, got %d: %+v", len(got), got)
	}
	if got[0].ID != "MS.AAD.1.1v1" || got[0].Criticality != "SHALL" {
		t.Fatalf("first control wrong: %+v", got[0])
	}
	if got[0].Text != "Legacy authentication SHALL be blocked." {
		t.Fatalf("requirement text wrong: %q", got[0].Text)
	}
	if got[0].Section != "1. Legacy Authentication" {
		t.Fatalf("section wrong: %q", got[0].Section)
	}
	if got[1].Criticality != "SHOULD" {
		t.Fatalf("second control criticality wrong: %+v", got[1])
	}
}

// The Instructions headings repeat each control id. Counting them twice would
// double the size of the framework and halve every percentage.
func TestParseScubaIgnoresRepeatedHeadings(t *testing.T) {
	for _, c := range parseScuba("aad", fixture) {
		if c.ID == "MS.AAD.1.1v1" && c.Text == "1. Open the portal." {
			t.Fatal("an Instructions heading was parsed as a control")
		}
	}
}

func TestCatalogValidatesIds(t *testing.T) {
	c := &Catalog{Controls: []Control{{ID: "MS.AAD.1.1v1"}}}
	if !c.Has("MS.AAD.1.1v1") || !c.Has("ms.aad.1.1v1") {
		t.Fatal("known control not found")
	}
	if c.Has("MS.AAD.9.9v9") {
		t.Fatal("invented control reported as published")
	}
}
