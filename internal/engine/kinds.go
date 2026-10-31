package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
)

// isExtended reports whether a kind is one of the later additions: compliance
// policies and app protection policies. They are polymorphic objects with
// nested parts (actions on non-compliance, the list of covered apps) that the
// older kinds do not have, so they need their own handling when written.
func isExtended(k catalog.Kind) bool {
	return k == catalog.KindCompliance || k == catalog.KindIOSAppProtection || k == catalog.KindAndroidAppProtection
}

func isAppProtection(k catalog.Kind) bool {
	return k == catalog.KindIOSAppProtection || k == catalog.KindAndroidAppProtection
}

// scrubDeep removes, at every depth, what an export or a live read carries that
// must not be sent back: OData bookkeeping, action metadata and assignments.
func scrubDeep(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			switch {
			case k == "assignments", strings.HasPrefix(k, "#microsoft.graph."):
				delete(x, k)
			case strings.Contains(k, "@odata.") && k != "@odata.type":
				delete(x, k)
			default:
				scrubDeep(c)
			}
		}
	case []any:
		for _, c := range x {
			scrubDeep(c)
		}
	}
}

// extendedReadOnly are top level fields the service computes for these kinds.
var extendedReadOnly = []string{"version", "deployedAppCount", "isAssigned", "createdDateTime", "lastModifiedDateTime", "id"}

// forCreate prepares the body to POST and, for app protection, the apps the
// policy covers. Those are attached in a second call because the service does
// not accept them on create.
func forCreate(kind catalog.Kind, body []byte) (clean []byte, apps []any, err error) {
	if !isExtended(kind) {
		clean, err = strip(body)
		return clean, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, err
	}
	scrubDeep(doc)
	for _, f := range extendedReadOnly {
		delete(doc, f)
	}
	if isAppProtection(kind) {
		if a, ok := doc["apps"].([]any); ok {
			apps = a
		}
		delete(doc, "apps")
	}
	if kind == catalog.KindCompliance {
		stripNestedIDs(doc["scheduledActionsForRule"])
		// Microsoft requires at least one action for non-compliance when a policy is
		// created. Exports often leave it out, so a template without one gets the
		// standard "mark non-compliant immediately" action instead of a refused create.
		if rules, _ := doc["scheduledActionsForRule"].([]any); len(rules) == 0 {
			doc["scheduledActionsForRule"] = []any{map[string]any{
				"ruleName": "PasswordRequired",
				"scheduledActionConfigurations": []any{map[string]any{
					"actionType": "block", "gracePeriodHours": 0, "notificationTemplateId": "", "notificationMessageCCList": []any{},
				}},
			}}
		}
	}
	clean, err = json.Marshal(doc)
	return clean, apps, err
}

// forUpdate prepares the body to PATCH. The nested parts cannot be changed by
// PATCH (actions on non-compliance and the app list each have their own call),
// so they are left out; the caller is told, so a revert does not claim more than it did.
func forUpdate(kind catalog.Kind, body []byte) (clean []byte, notRestored string, err error) {
	if !isExtended(kind) {
		clean, err = strip(body)
		return clean, "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", err
	}
	scrubDeep(doc)
	for _, f := range extendedReadOnly {
		delete(doc, f)
	}
	switch {
	case isAppProtection(kind):
		if _, ok := doc["apps"]; ok {
			notRestored = "the list of covered apps was not restored"
		}
		delete(doc, "apps")
	case kind == catalog.KindCompliance:
		if _, ok := doc["scheduledActionsForRule"]; ok {
			notRestored = "the actions on non-compliance were not restored"
		}
		delete(doc, "scheduledActionsForRule")
	}
	clean, err = json.Marshal(doc)
	return clean, notRestored, err
}

func stripNestedIDs(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "id")
		for _, c := range x {
			stripNestedIDs(c)
		}
	case []any:
		for _, c := range x {
			stripNestedIDs(c)
		}
	}
}

// targetAppsBody builds the call that attaches apps to a new app protection
// policy. Only each app's identifier is sent; the service looks up the rest.
func targetAppsBody(apps []any) ([]byte, int) {
	out := []map[string]any{}
	for _, a := range apps {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		id, ok := m["mobileAppIdentifier"].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, map[string]any{"mobileAppIdentifier": id})
	}
	b, _ := json.Marshal(map[string]any{"apps": out})
	return b, len(out)
}

// normalizeForCompare puts the order-insensitive parts of a policy into a fixed
// order so a different order from the service does not read as drift.
func normalizeForCompare(kind catalog.Kind, doc []byte) []byte {
	if !isExtended(kind) {
		return doc
	}
	var m map[string]any
	if json.Unmarshal(doc, &m) != nil {
		return doc
	}
	sortBy := func(key string, id func(map[string]any) string) {
		list, ok := m[key].([]any)
		if !ok {
			return
		}
		sort.SliceStable(list, func(i, j int) bool {
			a, _ := list[i].(map[string]any)
			b, _ := list[j].(map[string]any)
			return id(a) < id(b)
		})
	}
	sortBy("apps", func(a map[string]any) string { b, _ := json.Marshal(a["mobileAppIdentifier"]); return string(b) })
	sortBy("scheduledActionsForRule", func(a map[string]any) string { return fmt.Sprint(a["ruleName"]) })
	out, err := json.Marshal(m)
	if err != nil {
		return doc
	}
	return out
}
