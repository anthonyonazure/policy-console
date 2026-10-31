package baseline

import (
	"strings"
	"testing"
)

// A policy in the shape Intune stores it: a plain choice, a simple value, and
// a group collection holding a child (how ASR rules are stored).
const policy = `{"settings":[
 {"settingInstance":{"settingDefinitionId":"defender_allowemailscanning",
   "choiceSettingValue":{"value":"defender_allowemailscanning_0","children":[]}}},
 {"settingInstance":{"settingDefinitionId":"defender_schedulequickscantime",
   "simpleSettingValue":{"value":720}}},
 {"settingInstance":{"settingDefinitionId":"defender_asr",
   "groupSettingCollectionValue":[{"children":[
     {"settingDefinitionId":"defender_asr_blockadobe","choiceSettingValue":{"value":"defender_asr_blockadobe_audit","children":[]}}
   ]}]}}
]}`

var bl = Baseline{
	Name: "Test baseline",
	Recs: []Rec{
		{DefinitionID: "defender_allowemailscanning", Name: "Allow Email Scanning", Expected: "defender_allowemailscanning_1"},
		{DefinitionID: "defender_schedulequickscantime", Name: "Quick scan time", Expected: "720"},
		{DefinitionID: "defender_asr_blockadobe", Name: "Block Adobe child processes", Expected: "defender_asr_blockadobe_block"},
		{DefinitionID: "defender_allowrealtime", Name: "Real-time", Expected: "defender_allowrealtime_1"},
	},
	Labels: map[string]string{"defender_asr_blockadobe_audit": "Audit"},
}

func TestCompareReadsNestedSettings(t *testing.T) {
	obs := map[string][]Observed{}
	if err := Flatten("P1", []byte(policy), obs); err != nil {
		t.Fatal(err)
	}
	r := Compare(bl, obs)
	state := map[string]ItemState{}
	for _, it := range r.Items {
		state[it.Name] = it.State
	}
	if state["Allow Email Scanning"] != Differs {
		t.Errorf("email scanning: got %s", state["Allow Email Scanning"])
	}
	if state["Quick scan time"] != Met {
		t.Errorf("simple value 720 should match, got %s", state["Quick scan time"])
	}
	// The ASR rule sits inside a group collection; missing it would silently
	// report every ASR rule as unset.
	if state["Block Adobe child processes"] != Differs {
		t.Errorf("nested ASR rule not read: %s", state["Block Adobe child processes"])
	}
	if state["Real-time"] != NotSet {
		t.Errorf("unset setting: got %s", state["Real-time"])
	}
	if r.Met != 1 || r.Differs != 2 || r.NotSet != 1 {
		t.Fatalf("counts wrong: %+v", r)
	}
	// Unset settings fall back to the Windows default and are not counted as failures.
	if r.Percent != 33 {
		t.Fatalf("agreement should be 1 of 3 set, got %d%%", r.Percent)
	}
}

func TestPoliciesThatDisagreeAreAConflict(t *testing.T) {
	obs := map[string][]Observed{}
	_ = Flatten("P1", []byte(policy), obs)
	_ = Flatten("P2", []byte(strings.ReplaceAll(policy, "defender_allowemailscanning_0", "defender_allowemailscanning_1")), obs)
	r := Compare(bl, obs)
	for _, it := range r.Items {
		if it.Name == "Allow Email Scanning" && it.State != Conflict {
			t.Fatalf("two policies setting different values must be a conflict, got %s", it.State)
		}
	}
}

func TestDifferencesListedFirst(t *testing.T) {
	obs := map[string][]Observed{}
	_ = Flatten("P1", []byte(policy), obs)
	r := Compare(bl, obs)
	if r.Items[0].State != Differs {
		t.Fatalf("findings should lead the list, first item is %s", r.Items[0].State)
	}
}

// Two policies setting the same value is a duplicate; different values is a
// conflict. One policy setting a value is neither.
func TestOverlaps(t *testing.T) {
	obs := map[string][]Observed{}
	_ = Flatten("P1", []byte(policy), obs)
	_ = Flatten("P2", []byte(strings.ReplaceAll(policy, "defender_allowemailscanning_0", "defender_allowemailscanning_1")), obs)
	got := Overlaps(obs, nil)
	conflicts, dupes := 0, 0
	for _, o := range got {
		if o.Conflict {
			conflicts++
		} else {
			dupes++
		}
	}
	if conflicts != 1 || dupes != 2 {
		t.Fatalf("expected 1 conflict and 2 duplicates, got %d and %d: %+v", conflicts, dupes, got)
	}
	single := map[string][]Observed{}
	_ = Flatten("P1", []byte(policy), single)
	if len(Overlaps(single, nil)) != 0 {
		t.Fatal("a setting from one policy reported as an overlap")
	}
}
