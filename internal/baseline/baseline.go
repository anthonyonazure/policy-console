// Package baseline compares Intune settings against Microsoft's own security
// baselines, setting by setting.
//
// CIS describes its recommendations in prose, so matching one to a real
// setting takes judgment. Microsoft publishes its baselines as settings catalog
// templates that use exactly the setting and option identifiers Intune
// policies use, so this comparison needs no interpretation at all: a setting
// either holds Microsoft's recommended value, holds a different one, or is not
// set by any policy.
package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Wanted names the baselines worth measuring a managed tenant against. The
// HoloLens, Windows 365 and agent baselines are for other kinds of device.
var Wanted = []string{
	"Security Baseline for Windows 10 and later",
	"Microsoft Defender for Endpoint Security Baseline",
	"Security Baseline for Microsoft Edge",
	"Microsoft 365 Apps for Enterprise Security Baseline",
	"Microsoft Windows 11 Security Technical Implementation Guide",
}

type Grapher interface {
	List(ctx context.Context, uri string) ([]map[string]any, error)
}

// Rec is one value Microsoft recommends.
type Rec struct {
	DefinitionID  string `json:"definitionId"`
	Name          string `json:"name"`
	Expected      string `json:"expected"`      // option id or literal value
	ExpectedLabel string `json:"expectedLabel"` // what the portal shows
}

type Baseline struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Recs    []Rec             `json:"recs"`
	Labels  map[string]string `json:"labels"` // setting and option ids to display names
	// FetchError is set when Microsoft's service could not return this baseline.
	FetchError string `json:"fetchError,omitempty"`
}

// Fetch reads the active Microsoft baselines this console measures against.
// The templates are the same in every tenant, so any consented tenant will do.
func Fetch(ctx context.Context, g Grapher) ([]Baseline, error) {
	list, err := g.List(ctx, "/beta/deviceManagement/configurationPolicyTemplates?$filter="+url.QueryEscape("templateFamily eq 'baseline'")+"&$select=id,displayName,displayVersion,lifecycleState")
	if err != nil {
		return nil, err
	}
	var out []Baseline
	for _, t := range list {
		if str(t["lifecycleState"]) != "active" || !wanted(str(t["displayName"])) {
			continue
		}
		id := str(t["id"])
		b := Baseline{ID: id, Name: str(t["displayName"]), Version: str(t["displayVersion"]), Labels: map[string]string{}}
		// Large baselines (the Windows 11 STIG) time out on Microsoft's side when
		// asked for in one page, so pages shrink on failure. One baseline that
		// still fails is reported, not allowed to sink the others.
		var settings []map[string]any
		var lastErr error
		for _, page := range []int{200, 50, 20} {
			settings, lastErr = g.List(ctx, fmt.Sprintf("/beta/deviceManagement/configurationPolicyTemplates('%s')/settingTemplates?$expand=settingDefinitions&$top=%d", id, page))
			if lastErr == nil {
				break
			}
		}
		if lastErr != nil {
			b.FetchError = lastErr.Error()
			if len(b.FetchError) > 300 {
				b.FetchError = b.FetchError[:300]
			}
			out = append(out, b)
			continue
		}
		for _, s := range settings {
			for _, d := range list2(s["settingDefinitions"]) {
				b.Labels[strings.ToLower(str(d["id"]))] = str(d["displayName"])
				for _, o := range list2(d["options"]) {
					b.Labels[strings.ToLower(str(o["itemId"]))] = str(o["displayName"])
				}
			}
			walkTemplate(obj(s["settingInstanceTemplate"]), &b)
		}
		for i := range b.Recs {
			b.Recs[i].Name = b.Labels[strings.ToLower(b.Recs[i].DefinitionID)] + scopeHint(b.Recs[i].DefinitionID)
			if b.Recs[i].Name == "" {
				b.Recs[i].Name = b.Recs[i].DefinitionID
			}
			b.Recs[i].ExpectedLabel = b.Labels[strings.ToLower(b.Recs[i].Expected)]
			if b.Recs[i].ExpectedLabel == "" {
				b.Recs[i].ExpectedLabel = b.Recs[i].Expected
			}
		}
		sort.Slice(b.Recs, func(i, j int) bool { return b.Recs[i].Name < b.Recs[j].Name })
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// scopeHint tells apart settings Microsoft names identically, such as the same
// firewall option for the domain, private and public network profiles, which
// otherwise read as duplicate rows.
func scopeHint(def string) string {
	d := strings.ToLower(def)
	for _, p := range []struct{ key, label string }{
		{"domainprofile", "Domain"}, {"privateprofile", "Private"}, {"publicprofile", "Public"},
	} {
		if strings.Contains(d, p.key) {
			return " (" + p.label + " network)"
		}
	}
	return ""
}

func wanted(name string) bool {
	for _, w := range Wanted {
		if strings.HasPrefix(name, w) {
			return true
		}
	}
	return false
}

// walkTemplate collects every recommended leaf value, descending into the
// children of choices and into group collections such as the ASR rule set.
func walkTemplate(t map[string]any, b *Baseline) {
	def := str(t["settingDefinitionId"])
	if v := obj(t["choiceSettingValueTemplate"]); len(v) > 0 {
		dv := obj(v["defaultValue"])
		if opt := str(dv["settingDefinitionOptionId"]); opt != "" {
			b.Recs = append(b.Recs, Rec{DefinitionID: def, Expected: opt})
		}
		for _, c := range list2(dv["children"]) {
			walkTemplate(c, b)
		}
	}
	if v := obj(t["simpleSettingValueTemplate"]); len(v) > 0 {
		dv := obj(v["defaultValue"])
		if c, ok := dv["constantValue"]; ok && c != nil {
			b.Recs = append(b.Recs, Rec{DefinitionID: def, Expected: fmt.Sprint(c)})
		}
	}
	for _, g := range list2(t["groupSettingCollectionValueTemplate"]) {
		for _, c := range list2(g["children"]) {
			walkTemplate(c, b)
		}
	}
	if g := obj(t["groupSettingValueTemplate"]); len(g) > 0 {
		for _, c := range list2(g["children"]) {
			walkTemplate(c, b)
		}
	}
}

// Observed is one value a policy sets.
type Observed struct {
	Value  string `json:"value"`
	Label  string `json:"label"`
	Policy string `json:"policy"`
}

// Flatten reads every setting value out of a settings catalog policy, keyed by
// setting definition id.
func Flatten(policyName string, body []byte, into map[string][]Observed) error {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	for _, s := range list2(doc["settings"]) {
		walkInstance(obj(s["settingInstance"]), policyName, into)
	}
	return nil
}

func walkInstance(inst map[string]any, policy string, into map[string][]Observed) {
	def := strings.ToLower(str(inst["settingDefinitionId"]))
	add := func(v string) {
		if v != "" {
			into[def] = append(into[def], Observed{Value: v, Policy: policy})
		}
	}
	if v := obj(inst["choiceSettingValue"]); len(v) > 0 {
		add(str(v["value"]))
		for _, c := range list2(v["children"]) {
			walkInstance(c, policy, into)
		}
	}
	for _, v := range list2(inst["choiceSettingCollectionValue"]) {
		add(str(v["value"]))
		for _, c := range list2(v["children"]) {
			walkInstance(c, policy, into)
		}
	}
	if v := obj(inst["simpleSettingValue"]); len(v) > 0 && v["value"] != nil {
		add(fmt.Sprint(v["value"]))
	}
	for _, v := range list2(inst["simpleSettingCollectionValue"]) {
		if v["value"] != nil {
			add(fmt.Sprint(v["value"]))
		}
	}
	for _, g := range list2(inst["groupSettingCollectionValue"]) {
		for _, c := range list2(g["children"]) {
			walkInstance(c, policy, into)
		}
	}
	if g := obj(inst["groupSettingValue"]); len(g) > 0 {
		for _, c := range list2(g["children"]) {
			walkInstance(c, policy, into)
		}
	}
}

type ItemState string

const (
	Met      ItemState = "met"
	Differs  ItemState = "differs"
	Conflict ItemState = "conflict" // policies disagree; the device outcome depends on Intune's conflict handling
	NotSet   ItemState = "not-set"
)

type Item struct {
	Name          string     `json:"name"`
	DefinitionID  string     `json:"definitionId"`
	ExpectedLabel string     `json:"expected"`
	State         ItemState  `json:"state"`
	Observed      []Observed `json:"observed,omitempty"`
}

type Result struct {
	FetchError string `json:"fetchError,omitempty"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Total      int    `json:"total"`
	Met        int    `json:"met"`
	Differs    int    `json:"differs"`
	Conflict   int    `json:"conflict"`
	NotSet     int    `json:"notSet"`
	// Percent is met out of the settings that some policy actually sets. A
	// setting nobody configures falls back to the Windows default, which may or
	// may not match Microsoft's recommendation, so it is reported rather than
	// scored as a failure.
	Percent  int    `json:"percent"`
	Coverage int    `json:"coverage"` // how many recommendations any policy addresses at all
	Items    []Item `json:"items"`
}

// Compare measures a set of observed settings against one baseline.
func Compare(b Baseline, observed map[string][]Observed) Result {
	r := Result{ID: b.ID, Name: b.Name, Version: b.Version, FetchError: b.FetchError}
	for _, rec := range b.Recs {
		it := Item{Name: rec.Name, DefinitionID: rec.DefinitionID, ExpectedLabel: rec.ExpectedLabel}
		obs := observed[strings.ToLower(rec.DefinitionID)]
		for i := range obs {
			obs[i].Label = b.Labels[strings.ToLower(obs[i].Value)]
			if obs[i].Label == "" {
				obs[i].Label = obs[i].Value
			}
		}
		it.Observed = obs
		match, other := false, false
		for _, o := range obs {
			if strings.EqualFold(o.Value, rec.Expected) {
				match = true
			} else {
				other = true
			}
		}
		switch {
		case len(obs) == 0:
			it.State = NotSet
			r.NotSet++
		case match && other:
			it.State = Conflict
			r.Conflict++
		case match:
			it.State = Met
			r.Met++
		default:
			it.State = Differs
			r.Differs++
		}
		r.Items = append(r.Items, it)
	}
	r.Total = len(r.Items)
	addressed := r.Met + r.Differs + r.Conflict
	if addressed > 0 {
		r.Percent = r.Met * 100 / addressed
	}
	if r.Total > 0 {
		r.Coverage = addressed * 100 / r.Total
	}
	// Differences first: they are the findings. Then conflicts, then matches.
	rank := map[ItemState]int{Differs: 0, Conflict: 1, Met: 2, NotSet: 3}
	sort.SliceStable(r.Items, func(i, j int) bool { return rank[r.Items[i].State] < rank[r.Items[j].State] })
	return r
}

func str(v any) string { s, _ := v.(string); return s }

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list2(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, i := range items {
		if m, ok := i.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Overlap is one setting configured by more than one policy. Guidance in the
// library is blunt: do not let two profiles configure the same setting, because
// one quietly undoes the other and the device outcome depends on Intune's
// conflict handling, not on anyone's intent.
type Overlap struct {
	DefinitionID string     `json:"definitionId"`
	Name         string     `json:"name"`
	Conflict     bool       `json:"conflict"` // policies set different values
	Observed     []Observed `json:"observed"`
}

// Overlaps finds settings set by two or more different policies. Baselines are
// used only for display names; the check covers every setting, not just the
// ones a Microsoft baseline mentions.
func Overlaps(observed map[string][]Observed, labels []Baseline) []Overlap {
	names := map[string]string{}
	for _, b := range labels {
		for k, v := range b.Labels {
			names[k] = v
		}
	}
	var out []Overlap
	for def, obs := range observed {
		policies := map[string]bool{}
		values := map[string]bool{}
		for _, o := range obs {
			policies[o.Policy] = true
			values[strings.ToLower(o.Value)] = true
		}
		if len(policies) < 2 {
			continue
		}
		ov := Overlap{DefinitionID: def, Name: names[def] + scopeHint(def), Conflict: len(values) > 1}
		if names[def] == "" {
			ov.Name = def
		}
		for _, o := range obs {
			o.Label = names[strings.ToLower(o.Value)]
			if o.Label == "" {
				o.Label = o.Value
			}
			ov.Observed = append(ov.Observed, o)
		}
		out = append(out, ov)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conflict != out[j].Conflict {
			return out[i].Conflict
		}
		return out[i].Name < out[j].Name
	})
	return out
}
