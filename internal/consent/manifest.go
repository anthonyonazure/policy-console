// Package consent grants the console's application permissions inside a client
// tenant, using the partner's own delegated access, and proves they landed.
//
// It talks only to Microsoft Graph. Nothing here calls the Partner Center API,
// which stays read only by standing rule.
package consent

import "sort"

const (
	ProfileRead  = "read"  // inventory, drift, assessments; changes nothing
	ProfileWrite = "write" // deploys and rollouts; consented only in onboarded clients

	// ProfilePlanner is for our own tenant only: it lets the write app post build
	// outs to Microsoft Planner. It touches no client.
	ProfilePlanner = "planner"

	// GraphAppID is Microsoft Graph's own application id, the same in every tenant.
	GraphAppID = "00000003-0000-0000-c000-000000000000"
)

// Grant is one Microsoft Graph application permission and why the console wants it.
// Permissions are named, never numbered: the id is looked up in the client's own
// Microsoft Graph service principal at grant time, so there is no second list of
// ids to keep in step with Microsoft.
type Grant struct {
	Kind       string `json:"kind"`       // the part of the console that needs it
	Permission string `json:"permission"` // Graph application permission value
	Why        string `json:"why"`        // plain English
}

var readGrants = []Grant{
	{"tenant", "Organization.Read.All", "Confirm the connection works and read the organization name."},
	{"conditional-access", "Policy.Read.All", "Read Conditional Access policies, named locations and authentication strengths."},
	{"configuration-policies", "DeviceManagementConfiguration.Read.All", "Read Intune settings catalog, compliance and device configuration policies."},
	{"score", "SecurityEvents.Read.All", "Read Microsoft Secure Score."},
	{"apps", "DeviceManagementApps.Read.All", "Read apps, app assignments and app protection policies."},
	{"enrollment", "DeviceManagementServiceConfig.Read.All", "Read Autopilot profiles and enrollment restrictions."},
	{"devices", "DeviceManagementManagedDevices.Read.All", "Read the device inventory to suggest pilot members and check rollout health."},
	{"groups", "Group.Read.All", "Read the groups a pack's policies are assigned to."},
	{"audit", "AuditLog.Read.All", "Say who changed a setting when drift is found."},
}

var writeGrants = []Grant{
	{"conditional-access", "Policy.ReadWrite.ConditionalAccess", "Create and change Conditional Access policies, named locations and authentication strengths."},
	{"configuration-policies", "DeviceManagementConfiguration.ReadWrite.All", "Create and change Intune policies and their assignments."},
	{"apps", "DeviceManagementApps.ReadWrite.All", "Assign apps and app protection policies."},
	{"enrollment", "DeviceManagementServiceConfig.ReadWrite.All", "Create Autopilot profiles and enrollment restrictions."},
	{"groups", "Group.ReadWrite.All", "Create the groups and filters a pack depends on."},
}

var plannerGrants = []Grant{
	{"planner", "Tasks.ReadWrite.All", "Create and update Planner plans, buckets and tasks for build outs."},
}

// Manifest returns every permission a registration needs. The write profile
// includes the read permissions because a deploy has to read first.
func Manifest(profile string) []Grant {
	switch profile {
	case ProfileRead:
		return append([]Grant(nil), readGrants...)
	case ProfilePlanner:
		return append([]Grant(nil), plannerGrants...)
	case ProfileWrite:
		out := append([]Grant(nil), readGrants...)
		return append(out, writeGrants...)
	}
	return nil
}

// KindState is how much of one kind's permissions a client has granted.
type KindState struct {
	Kind    string   `json:"kind"`
	State   string   `json:"state"` // granted | partial | none
	Missing []string `json:"missing,omitempty"`
}

// KindStates folds a set of granted permission names into one state per kind, so
// one refused permission blocks only that kind of work instead of everything.
func KindStates(profile string, granted map[string]bool) []KindState {
	byKind := map[string][]Grant{}
	for _, g := range Manifest(profile) {
		byKind[g.Kind] = append(byKind[g.Kind], g)
	}
	out := make([]KindState, 0, len(byKind))
	for kind, gs := range byKind {
		ks := KindState{Kind: kind}
		have := 0
		for _, g := range gs {
			if granted[g.Permission] {
				have++
			} else {
				ks.Missing = append(ks.Missing, g.Permission)
			}
		}
		switch {
		case have == len(gs):
			ks.State = "granted"
		case have == 0:
			ks.State = "none"
		default:
			ks.State = "partial"
		}
		sort.Strings(ks.Missing)
		out = append(out, ks)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}
