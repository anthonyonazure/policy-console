// Package engine performs the tenant-facing operations: snapshot, compare,
// deploy, modify and revert. Every write is bracketed by a snapshot of the
// object before and after, so history is complete even when a change is made
// by someone else and only discovered later.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/diff"
	"github.com/anthonyonazure/policy-console/internal/equiv"
	"github.com/anthonyonazure/policy-console/internal/graph"
	"github.com/anthonyonazure/policy-console/internal/store"
)

type Engine struct {
	Store    *store.Store
	Catalog  *catalog.Catalog
	NewGraph func(tenantID string) *graph.Client
	// Gate serialises changes and scheduled checks per client.
	Gate TenantGate

	// NewReadGraph, when set, is used for everything that only reads: snapshots,
	// comparisons, drift checks and assessments. Writes always use NewGraph. This
	// keeps the scheduled work running under credentials that cannot change a tenant.
	NewReadGraph func(tenantID string) *graph.Client
}

// Reader returns the client for read-only work.
func (e *Engine) Reader(tenantID string) *graph.Client {
	if e.NewReadGraph != nil {
		return e.NewReadGraph(tenantID)
	}
	return e.NewGraph(tenantID)
}

// readOnlyFields are stripped before any write. Graph rejects some of them and
// silently ignores others; sending them back is how a revert turns into a 400.
var readOnlyFields = []string{
	"id", "createdDateTime", "modifiedDateTime", "lastModifiedDateTime",
	"@odata.context", "@odata.id", "isAssigned", "settingCount",
	"creationSource", "priorityMetaData", "templateReference",
}

func strip(body []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	for _, f := range readOnlyFields {
		delete(doc, f)
	}
	for k := range doc {
		if strings.HasPrefix(k, "@odata") && k != "@odata.type" {
			delete(doc, k)
		}
	}
	return json.Marshal(doc)
}

func nameOf(obj map[string]any, kind catalog.Kind) string {
	if v, ok := obj[catalog.Collections[kind].NameProperty].(string); ok {
		return v
	}
	if v, ok := obj["displayName"].(string); ok {
		return v
	}
	if v, ok := obj["name"].(string); ok {
		return v
	}
	return ""
}

func idOf(obj map[string]any) string {
	if v, ok := obj["id"].(string); ok {
		return v
	}
	return ""
}

// listURI adds the expansion a kind needs to come back whole. A settings
// catalog policy without $expand=settings looks empty, which would make every
// comparison report the whole policy as missing.
func listURI(kind catalog.Kind) string {
	return catalog.Collections[kind].URI + expansion(kind)
}

// expansion asks for the nested parts of a kind that a plain read leaves out.
// Without it a policy looks emptier than it is and every comparison reports drift.
func expansion(kind catalog.Kind) string {
	switch kind {
	case catalog.KindConfigPolicy:
		return "?$expand=settings"
	case catalog.KindCompliance:
		return "?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)"
	case catalog.KindIOSAppProtection, catalog.KindAndroidAppProtection:
		return "?$expand=apps"
	}
	return ""
}

func itemURI(kind catalog.Kind, id string) string {
	return catalog.Collections[kind].URI + "/" + id + expansion(kind)
}

// ---- snapshot ----

type SnapshotResult struct {
	TenantID string   `json:"tenantId"`
	Captured int      `json:"captured"` // objects read
	Changed  int      `json:"changed"`  // objects whose contents differed from last time
	RunID    int64    `json:"runId"`
	Errors   []string `json:"errors,omitempty"`
}

// Snapshot captures every managed object in a tenant. source records why.
func (e *Engine) Snapshot(ctx context.Context, tenantID, source, actor string) (*SnapshotResult, error) {
	g := e.Reader(tenantID)
	runID, err := e.Store.StartRun(store.Run{TenantID: tenantID, Action: "snapshot", Mode: "live", Actor: actor})
	if err != nil {
		return nil, err
	}
	res := &SnapshotResult{TenantID: tenantID, RunID: runID}

	seen := map[string]bool{}
	failedKinds := map[string]bool{}
	for _, kind := range catalog.ManagedKinds() {
		items, err := g.List(ctx, listURI(kind))
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", kind, err))
			failedKinds[string(kind)] = true
			continue
		}
		for _, obj := range items {
			body, _ := json.Marshal(obj)
			ver, changed, err := e.Store.SaveVersion(store.Version{
				TenantID: tenantID, Kind: string(kind), ObjectID: idOf(obj),
				Name: nameOf(obj, kind), Source: source, RunID: &runID, Body: body,
			})
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				continue
			}
			seen[string(kind)+"/"+idOf(obj)] = true
			res.Captured++
			if changed {
				res.Changed++
				_ = e.Store.AddRunItem(store.RunItem{RunID: runID, Kind: string(kind), ObjectID: idOf(obj),
					Name: nameOf(obj, kind), Result: "captured", Detail: fmt.Sprintf("version %d", ver), AfterVer: &ver})
			}
		}
	}

	// Anything previously known and now absent is recorded as deleted, so the
	// history shows when a policy disappeared instead of just going stale.
	known, err := e.Store.LatestObjects(tenantID)
	if err == nil {
		for _, v := range known {
			// Only a kind that was read in full can say an object is gone. One that failed to
			// read says nothing, and must not be taken as deletions.
			if v.Deleted || seen[v.Kind+"/"+v.ObjectID] || failedKinds[v.Kind] || len(res.Errors) > len(failedKinds) {
				continue
			}
			ver, changed, err := e.Store.SaveVersion(store.Version{
				TenantID: tenantID, Kind: v.Kind, ObjectID: v.ObjectID, Name: v.Name,
				Source: source, RunID: &runID, Body: []byte(`{"deleted":true}`), Deleted: true,
			})
			if err == nil && changed {
				res.Changed++
				_ = e.Store.AddRunItem(store.RunItem{RunID: runID, Kind: v.Kind, ObjectID: v.ObjectID,
					Name: v.Name, Result: "deleted-in-tenant", Detail: fmt.Sprintf("version %d", ver), AfterVer: &ver})
			}
		}
	}

	_ = e.Store.UpsertTenant(store.Tenant{ID: tenantID, Name: tenantNameFallback(e, tenantID), LastSeenAt: time.Now().UTC().Format(time.RFC3339), Status: "connected"})
	_ = e.Store.FinishRun(runID, fmt.Sprintf("%d objects read, %d new versions", res.Captured, res.Changed))
	return res, nil
}

func tenantNameFallback(e *Engine, tenantID string) string {
	if t, err := e.Store.Tenant(tenantID); err == nil && t != nil && t.Name != "" {
		return t.Name
	}
	return tenantID
}

// ---- compare ----

type TemplateStatus struct {
	Template    catalog.Template `json:"template"`
	State       string           `json:"state"`               // missing | matches | drifted | equivalent | error
	CoveredBy   string           `json:"coveredBy,omitempty"` // live policy doing the same job under another name
	Exact       bool             `json:"exact,omitempty"`     // equivalent and not merely broader
	Does        string           `json:"does,omitempty"`      // plain account of what the template does
	ObjectID    string           `json:"objectId"`
	LiveState   string           `json:"liveState"` // CA only: enabled / report-only / disabled
	Changes     []diff.Change    `json:"changes,omitempty"`
	ChangeCount int              `json:"changeCount"`
	Note        string           `json:"note,omitempty"`
}

type CompareResult struct {
	TenantID  string           `json:"tenantId"`
	CheckedAt string           `json:"checkedAt"`
	Items     []TemplateStatus `json:"items"`
	Unmanaged []store.Version  `json:"unmanaged"` // live objects with no matching template
	// Unreadable names kinds the application is not permitted to read in this
	// tenant. Their templates are reported as "error", never as "missing", so a
	// missing permission is not mistaken for a missing policy.
	Unreadable []string `json:"unreadable,omitempty"`
	// Excluded lists templates this client is not expected to have, and why.
	Excluded []ExcludedTemplate `json:"excluded,omitempty"`
}

// ExcludedTemplate is a template left out for one client.
type ExcludedTemplate struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Owner  string `json:"owner"`
}

// Compare matches each template to a live object by name and reports drift.
// Tokens are supplied so placeholder values do not show up as differences.
func (e *Engine) Compare(ctx context.Context, tenantID string, tokens map[string]string, state string) (*CompareResult, error) {
	return e.CompareAgainst(ctx, tenantID, tokens, state, "")
}

// CompareAgainst measures a tenant against one chosen baseline: "" is the House
// standard, anything else is the name of a template category such as an imported
// library (oib-windows). It reads only; nothing is deployed. Objects in the
// tenant that the baseline does not mention are not listed for a chosen
// baseline, because against a partial set that would just be everything else.
func (e *Engine) CompareAgainst(ctx context.Context, tenantID string, tokens map[string]string, state, baseline string) (*CompareResult, error) {
	g := e.Reader(tenantID)
	live := map[string]map[string]any{} // kind|name -> object
	unreadable := map[catalog.Kind]bool{}
	var unreadableNames []string
	for _, kind := range catalog.ManagedKinds() {
		items, err := g.List(ctx, listURI(kind))
		if graph.IsForbidden(err) {
			unreadable[kind] = true
			unreadableNames = append(unreadableNames, string(kind))
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, obj := range items {
			live[string(kind)+"|"+strings.ToLower(nameOf(obj, kind))] = obj
		}
	}
	if len(unreadable) == len(catalog.ManagedKinds()) {
		return nil, fmt.Errorf("the application is not permitted to read anything in this tenant; consent may have been removed")
	}

	// Shapes of the live Conditional Access policies, for matching by behavior
	// when a template's name is not found.
	type liveCA struct {
		key   string
		obj   map[string]any
		shape *equiv.Shape
	}
	var liveShapes []liveCA
	for key, obj := range live {
		if !strings.HasPrefix(key, string(catalog.KindConditionalAccess)+"|") {
			continue
		}
		b, _ := json.Marshal(obj)
		if sh, err := equiv.Parse(b); err == nil {
			liveShapes = append(liveShapes, liveCA{key: key, obj: obj, shape: sh})
		}
	}
	// Prefer an enforced policy over a report-only one, and an exact match over
	// a broader one, so the report credits the strongest real protection.
	sort.Slice(liveShapes, func(i, j int) bool {
		ei, ej := liveShapes[i].shape.State == "enabled", liveShapes[j].shape.State == "enabled"
		if ei != ej {
			return ei
		}
		return liveShapes[i].key < liveShapes[j].key
	})

	res := &CompareResult{TenantID: tenantID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Unreadable: unreadableNames}
	matched := map[string]bool{}
	tailoring, err := e.LoadTailoring(tenantID)
	if err != nil {
		return nil, err
	}
	// A policy can be recognised by the id the console wrote into it, so a rename
	// or a changed name prefix does not turn it into "missing" plus "extra".
	byMarker := map[string]string{} // kind|templateId -> live key
	for key, obj := range live {
		if m := markerOf(obj); m != "" {
			byMarker[strings.SplitN(key, "|", 2)[0]+"|"+m] = key
		}
	}
	// Only kinds the baseline has templates for can have "extra" objects. Against the
	// read only kinds (update rings, Autopilot profiles) everything would be extra.
	kindHasTemplates := map[string]bool{}
	for _, base := range e.Catalog.All() {
		if inBaseline(base.Category, baseline) {
			kindHasTemplates[string(base.Kind)] = true
		}
	}
	for _, base := range e.Catalog.All() {
		t, tstatus := tailoring.Apply(base)
		if tstatus.State == "excluded" {
			if inBaseline(base.Category, baseline) {
				res.Excluded = append(res.Excluded, ExcludedTemplate{ID: base.ID, Name: base.Name, Reason: tstatus.Reason, Owner: tstatus.Owner})
			}
			continue
		}
		// Microsoft's templates are compared separately (internal/mstemplates);
		// counting them here would change what "the baseline" means.
		if !inBaseline(t.Category, baseline) {
			continue
		}
		st := TemplateStatus{Template: t}
		if unreadable[t.Kind] {
			st.State = "error"
			st.Note = "the application is not permitted to read this kind of policy in this tenant, so it was not checked"
			res.Items = append(res.Items, st)
			continue
		}
		key := string(t.Kind) + "|" + strings.ToLower(t.Name)
		var tShape *equiv.Shape
		if t.Kind == catalog.KindConditionalAccess {
			if sh, err := equiv.Parse(t.Body); err == nil {
				tShape = sh
				st.Does = equiv.Describe(sh)
			}
		}
		obj, ok := live[key]
		if !ok {
			if k, found := byMarker[string(t.Kind)+"|"+base.ID]; found {
				key, obj, ok = k, live[k], true
			}
		}
		if !ok {
			st.State = "missing"
			if tShape != nil {
				var best *liveCA
				var bestV equiv.Verdict
				for i := range liveShapes {
					v := equiv.Covers(liveShapes[i].shape, tShape)
					if !v.Covers {
						continue
					}
					if best == nil || (v.Exact && !bestV.Exact && liveShapes[i].shape.State == best.shape.State) {
						best, bestV = &liveShapes[i], v
					}
				}
				if best != nil {
					st.State = "equivalent"
					st.CoveredBy = best.shape.Name
					st.ObjectID = idOf(best.obj)
					st.LiveState = best.shape.State
					st.Exact = bestV.Exact
					st.Note = strings.Join(bestV.Reasons, "; ")
					matched[best.key] = true
				}
			}
			res.Items = append(res.Items, st)
			continue
		}
		matched[key] = true
		st.ObjectID = idOf(obj)
		if s, ok := obj["state"].(string); ok {
			st.LiveState = s
		}
		rendered, err := t.Render(tokens, state)
		if err != nil {
			st.State = "error"
			st.Note = err.Error()
			res.Items = append(res.Items, st)
			continue
		}
		liveBody, _ := json.Marshal(withoutMarker(obj))
		changes, err := diff.Compare(normalizeForCompare(t.Kind, rendered), normalizeForCompare(t.Kind, liveBody))
		if err != nil {
			st.State = "error"
			st.Note = err.Error()
		} else if len(changes) == 0 {
			st.State = "matches"
		} else {
			st.State = "drifted"
			st.Changes = changes
			st.ChangeCount = len(changes)
		}
		res.Items = append(res.Items, st)
	}

	for key, obj := range live {
		if matched[key] || baseline != "" || !kindHasTemplates[strings.SplitN(key, "|", 2)[0]] {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		body, _ := json.Marshal(obj)
		res.Unmanaged = append(res.Unmanaged, store.Version{
			TenantID: tenantID, Kind: parts[0], ObjectID: idOf(obj),
			Name: nameOf(obj, catalog.Kind(parts[0])), Body: body,
		})
	}
	sort.Slice(res.Unmanaged, func(i, j int) bool { return res.Unmanaged[i].Name < res.Unmanaged[j].Name })
	return res, nil
}

// ---- deploy ----

type DeployRequest struct {
	TenantID    string            `json:"tenantId"`
	TemplateIDs []string          `json:"templateIds"`
	Tokens      map[string]string `json:"tokens"`
	State       string            `json:"state"`
	Preview     bool              `json:"preview"`
	Actor       string            `json:"actor"`
	Rollout     string            `json:"rollout"`      // pilot | all | none
	PilotGroup  string            `json:"pilotGroupId"` // required for pilot
}

type DeployResult struct {
	RunID    int64                      `json:"runId"`
	Mode     string                     `json:"mode"`
	Items    []store.RunItem            `json:"items"`
	Rendered map[string]json.RawMessage `json:"rendered,omitempty"`
}

// Deploy creates the selected templates. An object whose name already exists is
// left alone and reported, never overwritten: replacing a live policy is the
// Modify operation, which snapshots first and asks for confirmation.
func (e *Engine) Deploy(ctx context.Context, req DeployRequest) (*DeployResult, error) {
	mode := "live"
	if req.Preview {
		mode = "preview"
	}
	runID, err := e.Store.StartRun(store.Run{TenantID: req.TenantID, Action: "deploy", Mode: mode, Actor: req.Actor})
	if err != nil {
		return nil, err
	}
	out := &DeployResult{RunID: runID, Mode: mode, Rendered: map[string]json.RawMessage{}}
	if !req.Preview {
		defer e.Gate.BeginWrite(req.TenantID)()
	}

	var g *graph.Client
	existing := map[string]map[string]any{}
	unreadable := map[catalog.Kind]bool{}
	if !req.Preview {
		g = e.NewGraph(req.TenantID)
		for _, kind := range catalog.ManagedKinds() {
			items, err := g.List(ctx, listURI(kind))
			if graph.IsForbidden(err) {
				unreadable[kind] = true
				continue
			}
			if err != nil {
				_ = e.Store.FinishRun(runID, "failed to read tenant: "+err.Error())
				return nil, err
			}
			for _, obj := range items {
				existing[string(kind)+"|"+strings.ToLower(nameOf(obj, kind))] = obj
				if m := markerOf(obj); m != "" {
					existing[string(kind)+"|marker:"+m] = obj // found by its id even if renamed
				}
			}
		}
	}

	tailoring, err := e.LoadTailoring(req.TenantID)
	if err != nil {
		_ = e.Store.FinishRun(runID, "could not read the client's profile: "+err.Error())
		return nil, err
	}
	for _, id := range req.TemplateIDs {
		t := e.Catalog.Get(id)
		if t == nil {
			out.Items = append(out.Items, store.RunItem{RunID: runID, TemplateID: id, Name: id, Result: "failed", Detail: "unknown template"})
			continue
		}
		baseID := t.ID
		tailored, tstatus := tailoring.Apply(*t)
		if tstatus.State == "excluded" {
			item := store.RunItem{RunID: runID, TemplateID: baseID, Kind: string(t.Kind), Name: t.Name, Result: "skipped",
				Detail: "not deployed: this client is not expected to have it (" + tstatus.Reason + ")"}
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}
		t = &tailored
		item := store.RunItem{RunID: runID, TemplateID: baseID, Kind: string(t.Kind), Name: t.Name}
		body, err := t.Render(req.Tokens, req.State)
		if err != nil {
			item.Result, item.Detail = "failed", err.Error()
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}
		pilotNote := ""
		if req.Rollout == RolloutPilot && t.Kind == catalog.KindConditionalAccess {
			if strings.TrimSpace(req.PilotGroup) == "" {
				item.Result, item.Detail = "failed", "pilot rollout needs a pilot group id"
				out.Items = append(out.Items, item)
				_ = e.Store.AddRunItem(item)
				continue
			}
			if nb, note, err := applyPilot(body, req.PilotGroup); err == nil {
				body, pilotNote = nb, note
			}
		}
		out.Rendered[t.ID] = json.RawMessage(body)

		// Never create a policy that blocks every user from everything. This is
		// checked on the rendered body, so it holds for any template source.
		if t.Kind == catalog.KindConditionalAccess {
			if sh, err := equiv.Parse(body); err == nil && equiv.BlocksEveryone(sh) {
				item.Result, item.Detail = "failed", "refused: this policy would block every user from every app and lock the tenant out"
				out.Items = append(out.Items, item)
				_ = e.Store.AddRunItem(item)
				continue
			}
		}

		if req.Preview {
			item.Result, item.Detail = "preview", "would be created"
			if pilotNote != "" {
				item.Detail += "; " + pilotNote
			}
			if t.Kind == catalog.KindConfigPolicy {
				switch req.Rollout {
				case RolloutPilot:
					item.Detail += "; assigned to the pilot group"
				case RolloutAll:
					item.Detail += "; assigned to all devices"
				default:
					item.Detail += "; not assigned, so it would apply to no devices"
				}
			}
			if isExtended(t.Kind) {
				item.Detail += "; not assigned, so it would apply to no one (assignment is not supported for this kind yet)"
			}
			if _, clash := existing[string(t.Kind)+"|"+strings.ToLower(t.Name)]; clash {
				item.Detail = "already exists, would be left unchanged"
			}
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}

		if unreadable[t.Kind] {
			item.Result, item.Detail = "failed", "not created: the application cannot read this kind of policy in the tenant, so it cannot tell whether it already exists"
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}
		obj, clash := existing[string(t.Kind)+"|"+strings.ToLower(t.Name)]
		if !clash {
			obj, clash = existing[string(t.Kind)+"|marker:"+baseID]
		}
		if clash {
			item.Result, item.ObjectID, item.Detail = "exists", idOf(obj), "left unchanged"
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}

		createURI := catalog.Collections[t.Kind].URI
		if t.Kind == catalog.KindConditionalAccess && usesBetaOnly(body) {
			// v1.0 silently drops beta-only fields, which would create a policy
			// that does less than the template says. Create it through beta.
			createURI = "/beta/identity/conditionalAccess/policies"
		}
		createBody, apps, err := forCreate(t.Kind, withMarker(t.Kind, body, baseID))
		if err != nil {
			item.Result, item.Detail = "failed", err.Error()
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}
		created, err := g.Post(ctx, createURI, createBody)
		if err != nil {
			item.Result, item.Detail = "failed", err.Error()
			out.Items = append(out.Items, item)
			_ = e.Store.AddRunItem(item)
			continue
		}
		item.ObjectID = idOf(created)
		item.Result, item.Detail = "created", "new object"
		if pilotNote != "" {
			item.Detail += "; " + pilotNote
		}
		if isAppProtection(t.Kind) && item.ObjectID != "" && len(apps) > 0 {
			tb, n := targetAppsBody(apps)
			if err := g.PostAction(ctx, catalog.Collections[t.Kind].URI+"/"+item.ObjectID+"/targetApps", tb); err != nil {
				item.Detail += "; created but its apps were NOT attached: " + err.Error()
			} else {
				item.Detail += fmt.Sprintf("; %d apps attached", n)
			}
		}
		if isExtended(t.Kind) && item.ObjectID != "" {
			if req.Rollout == RolloutPilot || req.Rollout == RolloutAll {
				item.Detail += "; NOT assigned: assignment is not supported for this kind of policy yet, so it applies to no one"
			} else {
				item.Detail += "; not assigned, so it applies to no one yet"
			}
		}
		if t.Kind == catalog.KindConfigPolicy && item.ObjectID != "" {
			if req.Rollout == RolloutPilot || req.Rollout == RolloutAll {
				if err := assign(ctx, g, item.ObjectID, req.Rollout, req.PilotGroup); err != nil {
					item.Detail += "; created but NOT assigned: " + err.Error()
				} else if req.Rollout == RolloutPilot {
					item.Detail += "; assigned to the pilot group"
				} else {
					item.Detail += "; assigned to all devices"
				}
			} else {
				item.Detail += "; not assigned, so it applies to no devices yet"
			}
		}
		if item.ObjectID != "" {
			if full, err := g.Get(ctx, itemURI(t.Kind, item.ObjectID)); err == nil {
				fb, _ := json.Marshal(full)
				if ver, _, err := e.Store.SaveVersion(store.Version{TenantID: req.TenantID, Kind: string(t.Kind),
					ObjectID: item.ObjectID, Name: t.Name, Source: "post-change", RunID: &runID, Body: fb}); err == nil {
					item.AfterVer = &ver
				}
			}
		}
		out.Items = append(out.Items, item)
		_ = e.Store.AddRunItem(item)
	}

	created, failed := 0, 0
	for _, it := range out.Items {
		switch it.Result {
		case "created":
			created++
		case "failed":
			failed++
		}
	}
	_ = e.Store.FinishRun(runID, fmt.Sprintf("%s: %d created, %d failed, %d total", mode, created, failed, len(out.Items)))
	return out, nil
}

// ---- modify and revert ----

// Write applies a body to an existing object, snapshotting before and after.
// It is the single path for both a hand edit and a revert to an old version.
func (e *Engine) Write(ctx context.Context, tenantID string, kind catalog.Kind, objectID string, body []byte, action, actor, detail string) (*store.RunItem, error) {
	defer e.Gate.BeginWrite(tenantID)()
	g := e.NewGraph(tenantID)
	runID, err := e.Store.StartRun(store.Run{TenantID: tenantID, Action: action, Mode: "live", Actor: actor})
	if err != nil {
		return nil, err
	}
	item := store.RunItem{RunID: runID, Kind: string(kind), ObjectID: objectID, Detail: detail}

	before, err := g.Get(ctx, itemURI(kind, objectID))
	if err != nil {
		item.Result, item.Detail = "failed", "could not read current state: "+err.Error()
		_ = e.Store.AddRunItem(item)
		_ = e.Store.FinishRun(runID, item.Detail)
		return &item, err
	}
	item.Name = nameOf(before, kind)
	bb, _ := json.Marshal(before)
	if ver, _, err := e.Store.SaveVersion(store.Version{TenantID: tenantID, Kind: string(kind), ObjectID: objectID,
		Name: item.Name, Source: "pre-change", RunID: &runID, Body: bb}); err == nil {
		item.BeforeVer = &ver
	}

	if store.HasRedaction(body) {
		// The stored copy hides its secrets, so writing it back would overwrite the real ones with the marker.
		item.Result, item.Detail = "failed", "refused: this version contains secrets that are not stored (shown as [redacted]), so it cannot be written back automatically. Edit the live policy, or set the secret again by hand"
		_ = e.Store.AddRunItem(item)
		_ = e.Store.FinishRun(runID, item.Detail)
		return &item, fmt.Errorf("%s", item.Detail)
	}
	clean, notRestored, err := forUpdate(kind, body)
	if err != nil {
		item.Result, item.Detail = "failed", err.Error()
		_ = e.Store.AddRunItem(item)
		_ = e.Store.FinishRun(runID, item.Detail)
		return &item, err
	}
	if err := g.Patch(ctx, catalog.Collections[kind].URI+"/"+objectID, clean); err != nil {
		item.Result, item.Detail = "failed", err.Error()
		_ = e.Store.AddRunItem(item)
		_ = e.Store.FinishRun(runID, item.Detail)
		return &item, err
	}

	if after, err := g.Get(ctx, itemURI(kind, objectID)); err == nil {
		ab, _ := json.Marshal(after)
		if ver, _, err := e.Store.SaveVersion(store.Version{TenantID: tenantID, Kind: string(kind), ObjectID: objectID,
			Name: nameOf(after, kind), Source: "post-change", RunID: &runID, Body: ab}); err == nil {
			item.AfterVer = &ver
		}
	}
	if action == "revert" {
		item.Result = "reverted"
	} else {
		item.Result = "updated"
	}
	if notRestored != "" {
		item.Detail = strings.TrimSpace(item.Detail + "; " + notRestored)
	}
	_ = e.Store.AddRunItem(item)
	_ = e.Store.FinishRun(runID, fmt.Sprintf("%s %s", item.Result, item.Name))
	return &item, nil
}

// Revert writes a stored version back over the live object.
func (e *Engine) Revert(ctx context.Context, tenantID string, kind catalog.Kind, objectID string, version int, actor string) (*store.RunItem, error) {
	v, err := e.Store.VersionBody(tenantID, string(kind), objectID, version)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("no stored version %d for that object", version)
	}
	if v.Deleted {
		return nil, fmt.Errorf("version %d is a deletion marker; there is nothing to write back", version)
	}
	return e.Write(ctx, tenantID, kind, objectID, v.Body, "revert",
		actor, fmt.Sprintf("restored version %d captured %s", v.Version, v.CapturedAt))
}

func storeRun(tenantID, action, actor string) store.Run {
	return store.Run{TenantID: tenantID, Action: action, Mode: "live", Actor: actor}
}

// betaOnlyPaths are Conditional Access fields that exist only in Graph beta.
var betaOnlyPaths = [][]string{
	{"sessionControls", "continuousAccessEvaluation"},
	{"sessionControls", "secureSignInSession"},
	{"conditions", "agentIdRiskLevels"},
	{"conditions", "agentSessionRiskLevels"},
	{"conditions", "clientApplications"},
	{"conditions", "agents"},
	{"conditions", "agentContext"},
}

func usesBetaOnly(body []byte) bool {
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	for _, path := range betaOnlyPaths {
		cur := any(doc)
		ok := true
		for _, k := range path {
			m, isMap := cur.(map[string]any)
			if !isMap {
				ok = false
				break
			}
			cur, ok = m[k]
			if !ok || cur == nil {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// inStandard reports whether a template's category is part of the baseline a
// tenant is measured against. Microsoft's and the Praxis sets are compared
// separately, and library categories are optional, so none of them count as
// missing when a client does not have them.
func inStandard(category string) bool {
	return category != "microsoft" && category != "praxis" && !catalog.IsLibrary(category)
}

// inBaseline reports whether a template belongs to the baseline being assessed.
func inBaseline(category, baseline string) bool {
	if baseline == "" {
		return inStandard(category)
	}
	return category == baseline
}
