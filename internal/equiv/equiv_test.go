package equiv

import "testing"

func shape(t *testing.T, doc string) *Shape {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const legacyBlockTemplate = `{"displayName":"MS Elite | C006 - Block Legacy Authentication","state":"enabledForReportingButNotEnforced",
 "conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["exchangeActiveSync","other"]},
 "grantControls":{"operator":"OR","builtInControls":["block"]}}`

// The failure that started this: a tenant blocking legacy auth under its own
// policy name was reported as unprotected.
func TestDifferentNameSameBehaviorCovers(t *testing.T) {
	live := shape(t, `{"displayName":"Block legacy authentication","state":"enabled",
	 "conditions":{"users":{"includeUsers":["All"],"excludeUsers":["breakglass"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["other","exchangeActiveSync"]},
	 "grantControls":{"operator":"OR","builtInControls":["block"]}}`)
	v := Covers(live, shape(t, legacyBlockTemplate))
	if !v.Covers || !v.Exact {
		t.Fatalf("identical behavior under another name not recognized: %+v", v)
	}
}

func TestMFAForAllCoversMFAForAdmins(t *testing.T) {
	live := shape(t, `{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"builtInControls":["mfa"]}}`)
	tmpl := shape(t, `{"displayName":"MFA admins","conditions":{"users":{"includeRoles":["62e90394-69f5-4237-9190-012177145e10"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"builtInControls":["mfa"]}}`)
	v := Covers(live, tmpl)
	if !v.Covers || v.Exact {
		t.Fatalf("MFA for everyone should cover MFA for admins as a broader policy: %+v", v)
	}
}

// Ordinary MFA must never be credited as phishing-resistant: it accepts SMS.
func TestOrdinaryMFADoesNotCoverPhishingResistant(t *testing.T) {
	live := shape(t, `{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`)
	tmpl := shape(t, `{"displayName":"PR admins","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"authenticationStrength":{"id":"`+StrengthPhishingResistant+`"}}}`)
	if v := Covers(live, tmpl); v.Covers {
		t.Fatalf("ordinary MFA credited as phishing-resistant: %+v", v)
	}
}

func TestPhishingResistantCoversOrdinaryMFA(t *testing.T) {
	live := shape(t, `{"displayName":"PR all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"authenticationStrength":{"id":"`+StrengthPhishingResistant+`"}}}`)
	tmpl := shape(t, `{"displayName":"MFA all","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`)
	if v := Covers(live, tmpl); !v.Covers {
		t.Fatalf("stronger MFA should cover weaker: %+v", v)
	}
}

// A policy that only fires on risky sign-ins is narrower than an always-on one
// and must not be credited for it.
func TestNarrowerConditionDoesNotCover(t *testing.T) {
	live := shape(t, `{"displayName":"risky only","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"signInRiskLevels":["high"]},"grantControls":{"builtInControls":["mfa"]}}`)
	tmpl := shape(t, `{"displayName":"MFA all","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`)
	if v := Covers(live, tmpl); v.Covers {
		t.Fatalf("risk-only policy credited as always-on MFA: %+v", v)
	}
}

func TestBlockIsNotMFA(t *testing.T) {
	live := shape(t, legacyBlockTemplate)
	tmpl := shape(t, `{"displayName":"MFA all","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`)
	if v := Covers(live, tmpl); v.Covers {
		t.Fatalf("a block was credited as MFA: %+v", v)
	}
}

// Blocking everyone would lock a tenant out, so an unfiltered block is never a
// match for "block unmanaged devices".
func TestDeviceFilterBlockNotCoveredByPlainBlock(t *testing.T) {
	live := shape(t, `{"displayName":"block outside US","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}`)
	tmpl := shape(t, `{"displayName":"block unmanaged","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"devices":{"deviceFilter":{"mode":"include","rule":"device.isCompliant -ne True"}}},"grantControls":{"builtInControls":["block"]}}`)
	if v := Covers(live, tmpl); v.Covers {
		t.Fatalf("plain block credited as unmanaged-device block: %+v", v)
	}
}

func TestAuditNameCatchesMislabelledStrength(t *testing.T) {
	s := shape(t, `{"displayName":"MS Elite | C003b - Require phishing-resistant MFA for Admin Roles","grantControls":{"authenticationStrength":{"id":"`+StrengthMFA+`"}}}`)
	if w := AuditName(s); len(w) == 0 {
		t.Fatal("a phishing-resistant name on ordinary MFA was not flagged")
	}
	ok := shape(t, `{"displayName":"Require phishing-resistant MFA","grantControls":{"authenticationStrength":{"id":"`+StrengthPhishingResistant+`"}}}`)
	if w := AuditName(ok); len(w) != 0 {
		t.Fatalf("correctly labelled policy flagged: %v", w)
	}
}

// The lockout the deploy guard exists for.
func TestBlocksEveryoneDetected(t *testing.T) {
	all := shape(t, `{"displayName":"x","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}`)
	if !BlocksEveryone(all) {
		t.Fatal("a block on everyone for everything was not detected")
	}
	for _, narrow := range []string{
		legacyBlockTemplate,
		`{"displayName":"x","conditions":{"users":{"includeUsers":["None"]},"clientApplications":{"includeAgentIdServicePrincipals":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}`,
		`{"displayName":"x","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"locations":{"includeLocations":["All"],"excludeLocations":["x"]}},"grantControls":{"builtInControls":["block"]}}`,
	} {
		if BlocksEveryone(shape(t, narrow)) {
			t.Fatalf("a narrowed block was flagged as blocking everyone: %s", narrow)
		}
	}
}

// Agent-identity templates must never be read as policies about people.
func TestAgentTemplateIsNotAUserPolicy(t *testing.T) {
	agent := shape(t, `{"displayName":"Block all agent identities","conditions":{"users":{"includeUsers":["None"]},"clientApplications":{"includeAgentIdServicePrincipals":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}`)
	geo := shape(t, `{"displayName":"Block outside US","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"locations":{"includeLocations":["All"],"excludeLocations":["us"]}},"grantControls":{"builtInControls":["block"]}}`)
	if v := Covers(geo, agent); v.Covers {
		t.Fatalf("a location block was credited as blocking agent identities: %+v", v)
	}
}

// The false positive this logic replaced: MFA was credited as satisfying
// "require a compliant device".
func TestMFADoesNotSatisfyCompliantDevice(t *testing.T) {
	mfa := shape(t, `{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`)
	compliant := shape(t, `{"displayName":"compliant","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["compliantDevice"]}}`)
	if v := Covers(mfa, compliant); v.Covers {
		t.Fatalf("MFA credited as a compliant device: %+v", v)
	}
}

// "MFA or compliant or hybrid-joined" is satisfied by requiring MFA outright.
func TestMFASatisfiesAnOrTemplateThatAllowsMFA(t *testing.T) {
	mfa := shape(t, `{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`)
	either := shape(t, `{"displayName":"either","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa","compliantDevice","domainJoinedDevice"]}}`)
	if v := Covers(mfa, either); !v.Covers {
		t.Fatalf("MFA should satisfy MFA-or-device: %+v", v)
	}
}

// The reverse must fail: a live "MFA or compliant device" lets a compliant
// device through with no MFA, so it does not meet "require MFA".
func TestOrLiveDoesNotCoverStricterTemplate(t *testing.T) {
	either := shape(t, `{"displayName":"either","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa","compliantDevice"]}}`)
	mfa := shape(t, `{"displayName":"MFA all","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`)
	if v := Covers(either, mfa); v.Covers {
		t.Fatalf("MFA-or-device credited as requiring MFA: %+v", v)
	}
}

// Session controls are compared by kind.
func TestSessionControlsComparedByKind(t *testing.T) {
	freq := shape(t, `{"displayName":"freq","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"sessionControls":{"signInFrequency":{"value":1,"type":"hours","isEnabled":true}}}`)
	aer := shape(t, `{"displayName":"aer","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"sessionControls":{"applicationEnforcedRestrictions":{"isEnabled":true}}}`)
	if v := Covers(freq, aer); v.Covers {
		t.Fatalf("sign-in frequency credited as app-enforced restrictions: %+v", v)
	}
}
