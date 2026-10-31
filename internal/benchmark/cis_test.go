package benchmark

import "testing"

// Both layouts that broke the first version of the parser: a form feed at the
// start of a page hiding the recommendation number (Microsoft 365 benchmark),
// and headings indented under the page margin (Azure Foundations).
const cisFixture = "Table of Contents\n" +
	"          5.2.2.1 Ensure multifactor authentication is enabled for all users in administrative roles\n" +
	"          (Automated) ........ 280\n" +
	"                        Page 279\n" +
	"\f5.2.2.1 Ensure multifactor authentication is enabled for all users in\n" +
	"administrative roles (Automated)\n" +
	"Profile Applicability:\n" +
	"\n" +
	"• E3 Level 1\n" +
	"• E5 Level 1\n" +
	"\n" +
	"Description:\n" +
	"Some text.\n" +
	"\f            5.3.3 Ensure That Use of the 'User Access Administrator' Role is\n" +
	"            Restricted (Automated)\n" +
	"            Profile Applicability:\n" +
	"\n" +
	"            • Level 1\n" +
	"\n" +
	"            Description:\n"

func TestParseCISHandlesBothLayouts(t *testing.T) {
	got := ParseCIS(cisFixture)
	if len(got) != 2 {
		t.Fatalf("expected 2 recommendations, got %d: %+v", len(got), got)
	}
	if got[0].ID != "5.2.2.1" || got[0].Text != "Ensure multifactor authentication is enabled for all users in administrative roles" {
		t.Fatalf("form-feed heading parsed wrong: %+v", got[0])
	}
	if got[0].Criticality != "E3 Level 1, E5 Level 1 (Automated)" {
		t.Fatalf("levels wrong: %q", got[0].Criticality)
	}
	if got[1].ID != "5.3.3" || got[1].Criticality != "Level 1 (Automated)" {
		t.Fatalf("indented heading parsed wrong: %+v", got[1])
	}
}

// 5.2.2.10 must sort after 5.2.2.9, not after 5.2.2.1.
func TestVersionOrder(t *testing.T) {
	if !versionLess("5.2.2.9", "5.2.2.10") || versionLess("5.2.2.10", "5.2.2.9") {
		t.Fatal("control ids sorted as text rather than as numbers")
	}
}

// A newer benchmark version must replace the older one, not score alongside it.
func TestCISKeyIgnoresVersion(t *testing.T) {
	a, _ := cisSourceName("CIS_Microsoft_Intune_for_Windows_11_Benchmark_v5.0.0.pdf")
	b, _ := cisSourceName("CIS_Microsoft_Intune_for_Windows_11_Benchmark_v6.0.0.pdf")
	if a != b {
		t.Fatalf("versions produced different keys: %q vs %q", a, b)
	}
	if k, _ := cisSourceName("CIS Azure kubernetes Service (AKS) benchmark V2.0.0 - Draft PDF.pdf"); k != "cis-azure-kubernetes-service-aks" {
		t.Fatalf("spaced file name keyed as %q", k)
	}
	if m, _ := cisSourceName("CIS_Microsoft_365_Foundations_Benchmark_v7.0.0.pdf"); m != "cis-m365" {
		t.Fatalf("Microsoft 365 benchmark key changed: %q", m)
	}
}
