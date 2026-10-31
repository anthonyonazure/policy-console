package engine

import "testing"

func TestOnlyTheHouseSetCountsAsTheStandard(t *testing.T) {
	for _, c := range []string{"conditional-access", "defender", "intune"} {
		if !inStandard(c) {
			t.Errorf("%s is part of the standard", c)
		}
	}
	for _, c := range []string{"microsoft", "praxis", "oib-windows", "oib-macos", "oib-windows365", "pack-compliance"} {
		if inStandard(c) {
			t.Errorf("%s must not be expected in every tenant", c)
		}
	}
}
