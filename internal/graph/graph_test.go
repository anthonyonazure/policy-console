package graph

import (
	"fmt"
	"testing"
)

func TestOnlyA403MeansNoPermission(t *testing.T) {
	if !IsForbidden(&APIError{Status: 403}) {
		t.Error("403 is a missing permission")
	}
	if IsForbidden(&APIError{Status: 401}) {
		t.Error("401 is a bad credential, an outage, and must not be treated as 'not permitted'")
	}
	if IsForbidden(&APIError{Status: 500}) || IsForbidden(fmt.Errorf("boom")) || IsForbidden(nil) {
		t.Error("nothing else counts")
	}
	wrapped := fmt.Errorf("list: %w", &APIError{Status: 403})
	if !IsForbidden(wrapped) {
		t.Error("a wrapped 403 is still a 403")
	}
}
