package impact

import (
	"context"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func b(v bool) *bool { return &v }

func win(name, ver string, enc *bool, seenDaysAgo int) Device {
	return Device{ID: name, Name: name, User: name + "@x", Platform: "Windows", OSVersion: ver, Encrypted: enc, LastSync: now.Add(-time.Duration(seenDaysAgo) * 24 * time.Hour)}
}

func TestVersionsCompareNumericallyNotAsText(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"10.0.22621", "10.0.22621.0", 0},
		{"10.0.22631.4460", "10.0.22621", 1},
		{"10.0.19045.5011", "10.0.22621", -1},
		{"10.0.9", "10.0.10", -1}, // as text "9" > "10"
		{"17.5.1", "17.5", 1},
		{"14", "14.0.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestEachDeviceGetsAVerdictAndTheReason(t *testing.T) {
	cfg := Config{"osMinimumVersion": "10.0.22621", "bitLockerEnabled": true}
	devices := []Device{
		win("good", "10.0.26100.1", b(true), 1),
		win("old-os", "10.0.19045.5011", b(true), 1),
		win("no-crypt", "10.0.26100.1", b(false), 1),
		win("both", "10.0.19044.1", b(false), 2),
		win("silent", "10.0.26100.1", nil, 1), // never reported encryption
		win("retired", "10.0.19044.1", b(false), 90),
		{ID: "mac", Name: "mac", Platform: "macOS", OSVersion: "12.0", LastSync: now},
	}
	r := Evaluate("Windows", cfg, nil, devices, now)
	got := map[string]DeviceVerdict{}
	for _, d := range r.Devices {
		got[d.Name] = d
	}
	if len(got) != 6 {
		t.Fatalf("only Windows devices are judged by a Windows policy: %d", len(got))
	}
	want := map[string]string{"good": OK, "old-os": Fail, "no-crypt": Fail, "both": Fail, "silent": Unknown, "retired": Stale}
	for n, w := range want {
		if got[n].Verdict != w {
			t.Errorf("%s: %s, want %s (%v)", n, got[n].Verdict, w, got[n].Reasons)
		}
	}
	if len(got["both"].Reasons) != 2 || !strings.Contains(got["old-os"].Reasons[0], "older than the required 10.0.22621") {
		t.Errorf("reasons must name the setting, the device's value and the required value: %v / %v", got["both"].Reasons, got["old-os"].Reasons)
	}
	c := r.Counts
	if c.OK != 1 || c.Fail != 3 || c.Unknown != 1 || c.Stale != 1 || c.Active != 5 || c.PercentOK != 20 {
		t.Fatalf("counts: %+v", c)
	}
	if r.Oldest == nil || r.Oldest.Name != "both" {
		t.Fatalf("the oldest active device is marked: %+v", r.Oldest)
	}
}

func TestAFailBeatsACannotTellAndStaleIsNeverJudged(t *testing.T) {
	cfg := Config{"bitLockerEnabled": true, "secureBootEnabled": true}
	d := win("x", "10.0.26100", b(false), 1) // encryption fails, secure boot unknown
	r := Evaluate("Windows", cfg, nil, []Device{d}, now)
	if r.Devices[0].Verdict != Fail {
		t.Fatalf("%+v", r.Devices[0])
	}
	d2 := win("y", "10.0.26100", b(true), 1) // passes encryption, secure boot unknown
	r = Evaluate("Windows", cfg, nil, []Device{d2}, now)
	if r.Devices[0].Verdict != Unknown || !strings.Contains(r.Devices[0].Reasons[0], "health attestation") {
		t.Fatalf("a setting that cannot be judged is said so, not passed: %+v", r.Devices[0])
	}
}

func TestWhatIfTurnsSettingsOnAndOffAndShowsTheFleet(t *testing.T) {
	devices := []Device{win("a", "10.0.19045", b(true), 1), win("b", "10.0.22631", b(true), 1), win("c", "10.0.26100", b(false), 1)}
	base := Config{"bitLockerEnabled": true}
	r := Evaluate("Windows", base, nil, devices, now)
	if r.Counts.Fail != 1 {
		t.Fatalf("baseline: %+v", r.Counts)
	}
	// Switch the minimum OS on: one more device fails, and the original config is untouched.
	what := base.Apply(map[string]any{"osMinimumVersion": "10.0.22621"})
	r2 := Evaluate("Windows", what, nil, devices, now)
	if r2.Counts.Fail != 2 || len(base) != 1 {
		t.Fatalf("what-if: %+v, base %v", r2.Counts, base)
	}
	// Switch encryption off: only the OS failure remains.
	r3 := Evaluate("Windows", what.Apply(map[string]any{"bitLockerEnabled": nil}), nil, devices, now)
	if r3.Counts.Fail != 1 {
		t.Fatalf("%+v", r3.Counts)
	}
	for _, s := range r.Settings {
		if s.Key == "osMinimumVersion" {
			if s.On || !s.Hypothetical || s.Fails != 1 {
				t.Fatalf("an off setting still says what would happen if it were on: %+v", s)
			}
			if s.Fleet.Oldest != "10.0.19045" || s.Fleet.Newest != "10.0.26100" || s.Fleet.Median != "10.0.22631" {
				t.Fatalf("the fleet picture: %+v", s.Fleet)
			}
		}
	}
}

func TestConfigFromAPolicyReadsWhatIsOnAndAdmitsWhatItCannotJudge(t *testing.T) {
	body := `{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","displayName":"x","secureBootEnabled":true,
	  "codeIntegrityEnabled":false,"osMinimumVersion":null,"tpmRequired":true,"passwordRequired":true,"passwordRequiredType":"deviceDefault",
	  "passwordMinimumLength":8,"deviceThreatProtectionRequiredSecurityLevel":"unavailable","createdDateTime@odata.type":"x"}`
	cfg, platform, np, err := ConfigFromPolicy([]byte(body))
	if err != nil || platform != "Windows" {
		t.Fatalf("%v %s", err, platform)
	}
	if len(cfg) != 1 || cfg["secureBootEnabled"] != true {
		t.Fatalf("on settings: %v", cfg)
	}
	want := "passwordMinimumLength passwordRequired tpmRequired"
	if strings.Join(np, " ") != want {
		t.Fatalf("not predictable: %v", np)
	}
	if _, _, _, err := ConfigFromPolicy([]byte(`{"@odata.type":"#microsoft.graph.somethingElse"}`)); err == nil {
		t.Fatal("not a compliance policy")
	}
}

func TestJailbreakAndMissingAnswers(t *testing.T) {
	ios := func(n string, jb *bool) Device {
		return Device{ID: n, Name: n, Platform: "iOS", OSVersion: "17.5", JailBroken: jb, LastSync: now}
	}
	r := Evaluate("iOS", Config{"securityBlockJailbrokenDevices": true}, nil, []Device{ios("ok", b(false)), ios("jb", b(true)), ios("silent", nil)}, now)
	m := map[string]string{}
	for _, d := range r.Devices {
		m[d.Name] = d.Verdict
	}
	if m["ok"] != OK || m["jb"] != Fail || m["silent"] != Unknown {
		t.Fatalf("%v", m)
	}
}

func TestGraphDeviceMapping(t *testing.T) {
	d := DeviceFromGraph(map[string]any{
		"id": "1", "deviceName": "LT-1", "userPrincipalName": "a@x", "operatingSystem": "Windows", "osVersion": "10.0.22631.4460",
		"isEncrypted": false, "jailBroken": "Unknown", "lastSyncDateTime": "2026-10-26T10:00:00Z",
		"deviceHealthAttestationState": map[string]any{"secureBoot": "enabled", "codeIntegrityCheck": "unknown"},
	})
	if d.Platform != "Windows" || d.Encrypted == nil || *d.Encrypted || d.JailBroken != nil {
		t.Fatalf("%+v", d)
	}
	if d.SecureBoot == nil || !*d.SecureBoot || d.CodeIntegrity != nil {
		t.Fatalf("an 'unknown' attestation is not an answer: %+v", d)
	}
	if DeviceFromGraph(map[string]any{"operatingSystem": "iPadOS"}).Platform != "iOS" {
		t.Fatal("iPadOS is judged with iOS")
	}
	if !DeviceFromGraph(map[string]any{"lastSyncDateTime": "0001-01-01T00:00:00Z"}).LastSync.IsZero() {
		t.Fatal("a never-synced device has no last sync time")
	}
}

type fakeLister struct {
	uri   string
	items []map[string]any
}

func (f *fakeLister) List(_ context.Context, uri string) ([]map[string]any, error) {
	f.uri = uri
	return f.items, nil
}

func TestGraphSourceAsksForOnlyTheFieldsItNeeds(t *testing.T) {
	fl := &fakeLister{items: []map[string]any{{"id": "1", "deviceName": "LT-1", "operatingSystem": "macOS", "osVersion": "14.5"}}}
	ds, err := GraphSource{New: func(string) Lister { return fl }}.Devices(context.Background(), "t")
	if err != nil || len(ds) != 1 || ds[0].Platform != "macOS" {
		t.Fatalf("%v %+v", err, ds)
	}
	if !strings.Contains(fl.uri, "$select=") || strings.Contains(fl.uri, "hardwareInformation") {
		t.Fatalf("a narrow read keeps the data we hold small: %s", fl.uri)
	}
}

func TestSampleDevicesAreInventedAndUsable(t *testing.T) {
	ds, _ := SampleSource{}.Devices(context.Background(), "x")
	if len(ds) != 46 {
		t.Fatalf("%d", len(ds))
	}
	r := Evaluate("Windows", Config{"osMinimumVersion": "10.0.22621", "bitLockerEnabled": true}, nil, ds, time.Now())
	if r.Counts.Fail == 0 || r.Counts.Stale != 2 || r.Counts.OK == 0 {
		t.Fatalf("a demo that shows nothing is useless: %+v", r.Counts)
	}
	for _, d := range ds {
		if !strings.Contains(d.Name, "SAMPLE") || strings.Contains(d.User, "@") && !strings.HasSuffix(d.User, ".invalid") {
			t.Fatalf("sample data must be unmistakably fake: %+v", d)
		}
	}
}

func TestObservedResultsAreCountedAndSilenceIsNotSuccess(t *testing.T) {
	o := ParseObserved([]map[string]any{
		{"deviceDisplayName": "A", "status": "compliant"}, {"deviceDisplayName": "B", "status": "nonCompliant"},
		{"deviceDisplayName": "C", "status": "error"}, {"deviceDisplayName": "D", "status": "notApplicable"}, {"deviceDisplayName": "E", "status": "pending"},
	})
	if o.Compliant != 1 || o.NonCompliant != 1 || o.Problems != 1 || o.NotApplicable != 1 || o.Unknown != 1 {
		t.Fatalf("%+v", o)
	}
	if pct, ok := o.PercentCompliant(); !ok || pct != 33 {
		t.Fatalf("an error counts against the share: %d %v", pct, ok)
	}
	if _, ok := (&Observed{}).PercentCompliant(); ok {
		t.Fatal("no device has reported, so there is no answer, which must not look like 100 percent")
	}
}

func TestPredictionIsSetBesideWhatReallyHappened(t *testing.T) {
	pred := []DeviceVerdict{
		{Name: "a", Verdict: OK}, {Name: "b", Verdict: Fail}, {Name: "c", Verdict: OK}, {Name: "d", Verdict: Unknown}, {Name: "only-predicted", Verdict: OK},
	}
	obs := ParseObserved([]map[string]any{
		{"deviceDisplayName": "A", "status": "compliant"},    // agreed
		{"deviceDisplayName": "B", "status": "nonCompliant"}, // agreed
		{"deviceDisplayName": "C", "status": "nonCompliant"}, // we said fine, Intune says not
		{"deviceDisplayName": "D", "status": "compliant"},    // we made no claim
		{"deviceDisplayName": "only-observed", "status": "compliant"},
	})
	c := Compare(pred, obs)
	if c.Agreed != 2 || c.Disagreed != 1 || c.NotInBoth != 2 || len(c.Rows) != 1 || c.Rows[0].Device != "c" {
		t.Fatalf("%+v", c)
	}
}

func TestAConditionalAccessPolicyIsJudgedOnRealSignIns(t *testing.T) {
	pol := func(id, res string) []any { return []any{map[string]any{"id": id, "result": res}} }
	dev := func(managed, compliant bool) map[string]any {
		return map[string]any{"isManaged": managed, "isCompliant": compliant}
	}
	items := []map[string]any{
		{"userPrincipalName": "a@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("P1", "reportOnlyFailure"), "deviceDetail": dev(true, false)},
		{"userPrincipalName": "a@x", "appDisplayName": "Teams", "appliedConditionalAccessPolicies": pol("P1", "reportOnlyFailure"), "deviceDetail": dev(true, false)},
		{"userPrincipalName": "b@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("p1", "reportOnlyFailure"), "deviceDetail": dev(false, false)},
		{"userPrincipalName": "c@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("P1", "reportOnlySuccess"), "deviceDetail": dev(true, true)},
		{"userPrincipalName": "d@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("P1", "reportOnlyInterrupted")},
		{"userPrincipalName": "e@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("P1", "notApplied")},
		{"userPrincipalName": "f@x", "appDisplayName": "Outlook", "appliedConditionalAccessPolicies": pol("OTHER", "reportOnlyFailure")},
	}
	r := SummariseAccess(items, "P1", 7)
	if r.SignIns != 7 || r.Applied != 5 || r.WouldBlock != 3 || r.WouldPrompt != 1 || r.Passed != 1 {
		t.Fatalf("%+v", r)
	}
	if len(r.Users) != 3 || r.Users[0].User != "a@x" || r.Users[0].Count != 2 || len(r.Users[0].Apps) != 2 {
		t.Fatalf("the person stopped most often comes first: %+v", r.Users)
	}
	if r.Reasons["the device is not compliant"] != 2 || r.Reasons["the device is not managed"] != 1 {
		t.Fatalf("a reason in words for every stop: %v", r.Reasons)
	}
	if r2 := SummariseAccess(items, "NOPE", 7); r2.Applied != 0 || len(r2.Users) != 0 {
		t.Fatalf("a policy that never applied says nothing: %+v", r2)
	}
}

func TestAccessWindowIsBounded(t *testing.T) {
	if _, err := AccessFromGraph(context.Background(), &fakeLister{}, "p", 0, time.Now()); err == nil {
		t.Fatal("0 days")
	}
	if _, err := AccessFromGraph(context.Background(), &fakeLister{}, "p", 90, time.Now()); err == nil {
		t.Fatal("90 days is too much history for one question")
	}
	fl := &fakeLister{}
	if _, err := AccessFromGraph(context.Background(), fl, "p", 7, time.Now()); err != nil || !strings.Contains(fl.uri, "signIns") || !strings.Contains(fl.uri, "%24top=500") {
		t.Fatalf("%v %s", err, fl.uri)
	}
}
