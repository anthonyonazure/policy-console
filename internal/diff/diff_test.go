package diff

import "testing"

func TestIgnoresTenantOwnedFields(t *testing.T) {
	base := []byte(`{"displayName":"P","state":"enabled"}`)
	live := []byte(`{"id":"abc","createdDateTime":"2026-01-01","displayName":"P","state":"enabled"}`)
	got, err := Compare(base, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no drift, got %+v", got)
	}
}

func TestDetectsChangedSetting(t *testing.T) {
	base := []byte(`{"state":"enabledForReportingButNotEnforced"}`)
	live := []byte(`{"state":"enabled"}`)
	got, _ := Compare(base, live)
	if len(got) != 1 || got[0].Path != "state" || got[0].Kind != Changed {
		t.Fatalf("unexpected result %+v", got)
	}
}

// Graph returns role and country lists in arbitrary order; reordering is not a change.
func TestScalarListsCompareAsSets(t *testing.T) {
	base := []byte(`{"roles":["a","b","c"]}`)
	live := []byte(`{"roles":["c","a","b"]}`)
	got, _ := Compare(base, live)
	if len(got) != 0 {
		t.Fatalf("reordering counted as drift: %+v", got)
	}
}

func TestScalarListMembershipChange(t *testing.T) {
	base := []byte(`{"roles":["a","b"]}`)
	live := []byte(`{"roles":["a","c"]}`)
	got, _ := Compare(base, live)
	if len(got) != 2 {
		t.Fatalf("expected one removal and one addition, got %+v", got)
	}
}
