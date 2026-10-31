package main

import (
	"fmt"

	"github.com/anthonyonazure/policy-console/internal/config"
)

// writeGateError refuses a configuration where anyone who can sign in could
// write to every connected tenant. Read-only mode is always fine. A console
// listening only on this machine with no sign-in at all is the development case.
func writeGateError(cfg config.Config, anySignIn, local bool) error {
	if cfg.ReadOnly {
		return nil
	}
	if !anySignIn && local {
		return nil
	}
	if len(cfg.AllowedUsers) == 0 && cfg.AllowedGroup == "" {
		return fmt.Errorf("writes are enabled but neither PC_ALLOWED_USERS nor PC_ALLOWED_GROUP is set, so every user in the tenant could deploy to every customer. Set one, or set PC_READ_ONLY=true")
	}
	return nil
}
