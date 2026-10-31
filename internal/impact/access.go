package impact

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AccessReport says how a Conditional Access policy has behaved on real sign-ins:
// who it would have blocked or interrupted (a report-only policy records this
// without acting), who it let through, and why people would have been stopped.
type AccessReport struct {
	PolicyID    string         `json:"policyId"`
	Days        int            `json:"days"`
	SignIns     int            `json:"signInsChecked"`
	Applied     int            `json:"signInsPolicyApplied"` // the policy was evaluated for these
	WouldBlock  int            `json:"wouldBeBlocked"`
	WouldPrompt int            `json:"wouldBeInterrupted"` // asked for more, such as multi-factor
	Passed      int            `json:"wouldPass"`
	Users       []AccessUser   `json:"users"`
	Reasons     map[string]int `json:"reasons"`
	Truncated   bool           `json:"truncated"` // more sign-ins existed than were read
}

// AccessUser is one person who would have been stopped.
type AccessUser struct {
	User    string   `json:"user"`
	Count   int      `json:"signIns"`
	Apps    []string `json:"apps"`
	Reasons []string `json:"reasons"`
}

// maxSignIns bounds how much history one question reads, so a busy tenant cannot
// turn a question into a long, throttled crawl.
const maxSignIns = 2500

// AccessFromGraph reads recent sign-ins and summarises one policy's behaviour.
func AccessFromGraph(ctx context.Context, g Lister, policyID string, days int, now time.Time) (*AccessReport, error) {
	if days < 1 || days > 30 {
		return nil, fmt.Errorf("choose between 1 and 30 days")
	}
	since := now.UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	q := url.Values{}
	q.Set("$filter", "createdDateTime ge "+since)
	q.Set("$top", "500")
	q.Set("$select", "userPrincipalName,appDisplayName,createdDateTime,appliedConditionalAccessPolicies,deviceDetail")
	uri := "/v1.0/auditLogs/signIns?" + q.Encode()
	items, err := g.List(ctx, uri)
	if err != nil {
		return nil, err
	}
	return SummariseAccess(items, policyID, days), nil
}

// SummariseAccess folds sign-in records into a report for one policy.
func SummariseAccess(items []map[string]any, policyID string, days int) *AccessReport {
	r := &AccessReport{PolicyID: policyID, Days: days, Reasons: map[string]int{}}
	if len(items) > maxSignIns {
		items, r.Truncated = items[:maxSignIns], true
	}
	type agg struct {
		count   int
		apps    map[string]bool
		reasons map[string]bool
	}
	users := map[string]*agg{}
	for _, m := range items {
		r.SignIns++
		pol := policyResult(m, policyID)
		if pol == "" || pol == "notApplied" || pol == "notEnabled" {
			continue // the policy was not evaluated for this sign-in
		}
		r.Applied++
		switch pol {
		case "reportOnlyFailure", "failure":
			r.WouldBlock++
		case "reportOnlyInterrupted":
			r.WouldPrompt++
		case "reportOnlySuccess", "success":
			r.Passed++
			continue
		default:
			continue // not applied, or not evaluated
		}
		upn, _ := m["userPrincipalName"].(string)
		app, _ := m["appDisplayName"].(string)
		reason := accessReason(m, pol)
		r.Reasons[reason]++
		a := users[upn]
		if a == nil {
			a = &agg{apps: map[string]bool{}, reasons: map[string]bool{}}
			users[upn] = a
		}
		a.count++
		a.apps[app] = true
		a.reasons[reason] = true
	}
	for u, a := range users {
		r.Users = append(r.Users, AccessUser{User: u, Count: a.count, Apps: keys(a.apps), Reasons: keys(a.reasons)})
	}
	sort.Slice(r.Users, func(i, j int) bool {
		if r.Users[i].Count != r.Users[j].Count {
			return r.Users[i].Count > r.Users[j].Count
		}
		return r.Users[i].User < r.Users[j].User
	})
	if len(r.Users) > 50 {
		r.Users = r.Users[:50]
	}
	return r
}

func policyResult(m map[string]any, policyID string) string {
	list, _ := m["appliedConditionalAccessPolicies"].([]any)
	for _, p := range list {
		pm, _ := p.(map[string]any)
		if id, _ := pm["id"].(string); strings.EqualFold(id, policyID) {
			res, _ := pm["result"].(string)
			return res
		}
	}
	return ""
}

// accessReason says in words why a sign-in would have been stopped, from what the
// sign-in record shows about the device.
func accessReason(m map[string]any, result string) string {
	dd, _ := m["deviceDetail"].(map[string]any)
	managed, mok := dd["isManaged"].(bool)
	compliant, cok := dd["isCompliant"].(bool)
	switch {
	case mok && !managed:
		// An unmanaged device is also reported as not compliant; "not managed" is the cause.
		return "the device is not managed"
	case cok && !compliant:
		return "the device is not compliant"
	case result == "reportOnlyInterrupted":
		return "it would have asked for more proof, such as multi-factor"
	}
	return "the sign-in did not meet the policy's conditions"
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
