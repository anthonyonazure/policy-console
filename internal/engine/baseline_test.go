package engine

import (
	"context"
	"testing"
)

func TestAssessAgainstAChosenBaselineJudgesOnlyThatSet(t *testing.T) {
	f := newFakeGraph(t)
	cat := library(t, map[string]string{"c.json": complianceTpl})
	e := engineFor(t, f, cat, true)
	f.lists[compPath] = []any{liveCompliance(map[string]any{"bitLockerEnabled": false})}

	std, err := e.Compare(context.Background(), "t", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(std.Items) != 1 || len(std.Unmanaged) != 0 {
		t.Fatalf("the House standard: %d items, %d unmanaged", len(std.Items), len(std.Unmanaged))
	}

	// The same template held in a library category is judged only when that library is chosen.
	lib := library2(t, "oib-test", map[string]string{"c.json": complianceTpl})
	e2 := engineFor(t, f, lib, true)
	res, err := e2.Compare(context.Background(), "t", nil, "")
	if err != nil || len(res.Items) != 0 {
		t.Fatalf("a library must not count against the standard: %v %+v", err, res.Items)
	}
	res, err = e2.CompareAgainst(context.Background(), "t", nil, "", "oib-test")
	if err != nil || len(res.Items) != 1 || res.Items[0].State != "drifted" {
		t.Fatalf("chosen baseline: %v %+v", err, res.Items)
	}
	if len(res.Unmanaged) != 0 {
		t.Fatal("against a chosen baseline, everything else in the tenant is not a finding")
	}
}
