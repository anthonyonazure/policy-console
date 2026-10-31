package main

import (
	"testing"

	"github.com/anthonyonazure/policy-console/internal/config"
)

func TestWriteGate(t *testing.T) {
	cases := []struct {
		name             string
		cfg              config.Config
		anySignIn, local bool
		wantErr          bool
	}{
		{"writes, sign-in, no list", config.Config{}, true, false, true},
		{"writes, sign-in, allow-list", config.Config{AllowedUsers: []string{"a@b"}}, true, false, false},
		{"writes, sign-in, group", config.Config{AllowedGroup: "g"}, true, false, false},
		{"read-only needs nothing", config.Config{ReadOnly: true}, true, false, false},
		{"local dev, no sign-in", config.Config{}, false, true, false},
		{"public, no sign-in, no list", config.Config{}, false, false, true},
	}
	for _, c := range cases {
		err := writeGateError(c.cfg, c.anySignIn, c.local)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}
