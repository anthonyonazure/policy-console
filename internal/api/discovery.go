package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/anthonyonazure/policy-console/internal/impact"
)

type platformPicture struct {
	Devices int    `json:"devices"`
	Active  int    `json:"active"` // seen in the last 30 days
	Stale   int    `json:"notSeen"`
	Oldest  string `json:"oldestOS,omitempty"`
	Newest  string `json:"newestOS,omitempty"`
}

// discovery is the before picture for a build out (PRD FR-71): what the client
// already has, read from the console's own history and the device list, with no
// new access needed and nothing changed.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("id")
	t, err := s.Store.Tenant(tenant)
	if err != nil || t == nil {
		fail(w, 404, errors.New("unknown tenant"))
		return
	}
	objs, err := s.Store.LatestObjects(tenant)
	if err != nil {
		fail(w, 500, err)
		return
	}
	kinds := map[string]int{}
	names := map[string][]string{}
	for _, o := range objs {
		if o.Deleted {
			continue
		}
		kinds[o.Kind]++
		if len(names[o.Kind]) < 25 {
			names[o.Kind] = append(names[o.Kind], o.Name)
		}
	}
	for k := range names {
		sort.Strings(names[k])
	}
	out := map[string]any{
		"client": t.Name, "lastSnapshot": t.LastSeenAt, "policiesByKind": kinds, "policyNames": names,
	}
	var notes []string
	if t.LastSeenAt == "" {
		notes = append(notes, "No snapshot has been taken yet, so the policy counts are empty. Take a snapshot first.")
	}
	if s.Impact != nil {
		devs, err := s.Impact.Devices(r.Context(), tenant)
		if err != nil {
			notes = append(notes, "The device list could not be read: "+err.Error())
		} else {
			now := time.Now()
			byPlatform := map[string]*platformPicture{}
			oldest, newest := map[string]impact.Device{}, map[string]impact.Device{}
			for _, d := range devs {
				p := byPlatform[d.Platform]
				if p == nil {
					p = &platformPicture{}
					byPlatform[d.Platform] = p
				}
				p.Devices++
				if !d.LastSync.IsZero() && now.Sub(d.LastSync) > impact.StaleAfter {
					p.Stale++
					continue
				}
				p.Active++
				if d.OSVersion == "" {
					continue
				}
				if o, ok := oldest[d.Platform]; !ok || impact.CompareVersions(d.OSVersion, o.OSVersion) < 0 {
					oldest[d.Platform] = d
				}
				if n, ok := newest[d.Platform]; !ok || impact.CompareVersions(d.OSVersion, n.OSVersion) > 0 {
					newest[d.Platform] = d
				}
			}
			for k, p := range byPlatform {
				p.Oldest, p.Newest = oldest[k].OSVersion, newest[k].OSVersion
			}
			out["devices"] = map[string]any{"total": len(devs), "byPlatform": byPlatform}
			if len(devs) == 0 {
				notes = append(notes, "No enrolled devices were found.")
			}
		}
	}
	if sample, ok := s.Impact.(interface{ IsSample() bool }); ok && sample.IsSample() {
		notes = append(notes, "The device figures are invented demo data.")
	}
	out["notes"] = notes
	_ = fmt.Sprint
	writeJSON(w, 200, out)
}
