package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/anthonyonazure/policy-console/internal/consent"
	"github.com/anthonyonazure/policy-console/internal/engine"
)

type fleetRow struct {
	TenantID   string         `json:"tenantId"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	LastSeen   string         `json:"lastSeen"`
	Critical   int            `json:"critical"`
	Warning    int            `json:"warning"`
	Info       int            `json:"info"`
	Acked      int            `json:"acknowledgedOrSnoozed"`
	Exceptions int            `json:"exceptions"`
	Rollouts   int            `json:"activeRollouts"`
	Consent    map[string]int `json:"consentKindsGranted"` // per registration: kinds fully granted
	ConsentOf  int            `json:"consentKindsTotal"`
	Buildout   *buildoutBrief `json:"buildout,omitempty"`
}

type buildoutBrief struct {
	ID   int64 `json:"id"`
	Done int   `json:"done"`
	Of   int   `json:"of"`
}

// fleetBoard is the one page that says which clients need attention, worst first.
func (s *Server) fleetBoard(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.Store.Tenants()
	if err != nil {
		fail(w, 500, err)
		return
	}
	now := time.Now()
	rows := make([]fleetRow, 0, len(tenants))
	for _, t := range tenants {
		row := fleetRow{TenantID: t.ID, Name: t.Name, Status: t.Status, LastSeen: t.LastSeenAt, Consent: map[string]int{}}
		if open, err := s.Store.OpenFindings(t.ID); err == nil {
			for _, f := range open {
				if st := f.StateAt(now); st != "new" {
					row.Acked++
					continue
				}
				switch f.Severity {
				case "critical":
					row.Critical++
				case "warning":
					row.Warning++
				default:
					row.Info++
				}
			}
		}
		if ex, err := s.Store.Exceptions(t.ID); err == nil {
			for _, e := range ex {
				if e.Active(now) {
					row.Exceptions++
				}
			}
		}
		if ros, err := s.Store.Rollouts(t.ID, true); err == nil {
			row.Rollouts = len(ros)
		}
		for _, profile := range []string{consent.ProfileRead, consent.ProfileWrite} {
			have, _ := s.Store.Consents(t.ID, profile)
			granted := map[string]bool{}
			for p := range have {
				granted[p] = true
			}
			kinds := consent.KindStates(profile, granted)
			for _, k := range kinds {
				if k.State == "granted" {
					row.Consent[profile]++
				}
			}
			row.ConsentOf = len(kinds)
		}
		if bs, err := s.Store.Buildouts(t.ID); err == nil && len(bs) > 0 {
			v := s.buildoutView(&bs[0])
			p := v["progress"].(map[string]int)
			row.Buildout = &buildoutBrief{ID: bs[0].ID, Done: p["done"], Of: p["total"]}
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.Warning != b.Warning {
			return a.Warning > b.Warning
		}
		return a.Name < b.Name
	})
	writeJSON(w, 200, rows)
}

type fleetReq struct {
	TemplateIDs []string `json:"templateIds"`
	TenantIDs   []string `json:"tenantIds"`
	Canary      string   `json:"canaryTenantId"` // goes first; the rest wait for it
	Hash        string   `json:"hash"`
	Confirm     bool     `json:"confirm"`
}

func fleetHash(q fleetReq, tokensByTenant map[string]string) string {
	ids := append([]string(nil), q.TemplateIDs...)
	ts := append([]string(nil), q.TenantIDs...)
	sort.Strings(ids)
	sort.Strings(ts)
	h := sha256.Sum256([]byte(strings.Join(ids, ",") + "|" + strings.Join(ts, ",") + "|" + q.Canary + "|" + fmt.Sprint(tokensByTenant)))
	return hex.EncodeToString(h[:])
}

// fleetOrder puts the canary first and the rest in a steady order.
func fleetOrder(q fleetReq) ([]string, error) {
	if len(q.TenantIDs) == 0 || len(q.TemplateIDs) == 0 {
		return nil, errors.New("choose at least one client and one template")
	}
	seen := map[string]bool{}
	var rest []string
	for _, id := range q.TenantIDs {
		if !seen[id] {
			seen[id] = true
			if id != q.Canary {
				rest = append(rest, id)
			}
		}
	}
	sort.Strings(rest)
	if q.Canary != "" {
		if !seen[q.Canary] {
			return nil, errors.New("the canary client must be one of the chosen clients")
		}
		return append([]string{q.Canary}, rest...), nil
	}
	if len(rest) > 1 {
		return nil, errors.New("choose a canary client: a change to several clients starts with one")
	}
	return rest, nil
}

func (s *Server) fleetInputs(q fleetReq) ([]string, map[string]string, error) {
	order, err := fleetOrder(q)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range q.TemplateIDs {
		if s.Cat.Get(id) == nil {
			return nil, nil, fmt.Errorf("unknown template %q", id)
		}
	}
	tokens := map[string]string{}
	for _, tn := range order {
		if t, err := s.Store.Tenant(tn); err != nil || t == nil {
			return nil, nil, fmt.Errorf("unknown client %q", tn)
		}
		tk, _ := s.Store.Tokens(tn)
		tokens[tn] = fmt.Sprint(tk)
	}
	return order, tokens, nil
}

// fleetPreview says how many policies would be created in how many clients and
// which would be left alone. It creates nothing.
func (s *Server) fleetPreview(w http.ResponseWriter, r *http.Request) {
	q, err := body[fleetReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected templateIds, tenantIds and a canaryTenantId"))
		return
	}
	order, tokens, err := s.fleetInputs(q)
	if err != nil {
		fail(w, 400, err)
		return
	}
	type perTenant struct {
		TenantID string `json:"tenantId"`
		Name     string `json:"name"`
		Would    int    `json:"wouldCreate"`
		Skipped  int    `json:"skipped"`
		Failed   int    `json:"failed"`
	}
	var rows []perTenant
	total := 0
	for _, tn := range order {
		t, _ := s.Store.Tenant(tn)
		tk, _ := s.Store.Tokens(tn)
		res, err := s.Engine.Deploy(r.Context(), engine.DeployRequest{TenantID: tn, TemplateIDs: q.TemplateIDs, Tokens: tk,
			State: "enabledForReportingButNotEnforced", Preview: true, Actor: actor(r), Rollout: engine.RolloutNone})
		if err != nil {
			fail(w, 502, err)
			return
		}
		p := perTenant{TenantID: tn, Name: t.Name}
		for _, it := range res.Items {
			switch it.Result {
			case "preview":
				p.Would++
			case "skipped":
				p.Skipped++
			case "failed":
				p.Failed++
			}
		}
		total += p.Would
		rows = append(rows, p)
	}
	writeJSON(w, 200, map[string]any{
		"summary": fmt.Sprintf("%d policy creation(s) across %d client(s), starting with %s", total, len(order), rows[0].Name),
		"clients": rows, "order": order, "hash": fleetHash(q, tokens), "unassigned": true,
	})
}

// fleetApply creates the previewed policies, canary first. If the canary has any
// failure, nothing else is touched. Policies are created unassigned, so this
// never changes what a user experiences by itself.
func (s *Server) fleetApply(w http.ResponseWriter, r *http.Request) {
	q, err := body[fleetReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected templateIds, tenantIds, a canaryTenantId, hash and confirm"))
		return
	}
	if s.Cfg.ReadOnly {
		fail(w, 403, errors.New("the console is in read-only mode, so it will not create anything in a client"))
		return
	}
	if !s.isApprover(actor(r)) {
		fail(w, 403, errors.New("only an approver can apply a change to several clients"))
		return
	}
	if !q.Confirm || q.Hash == "" {
		fail(w, 400, errors.New("preview first, then confirm with the preview's hash"))
		return
	}
	order, tokens, err := s.fleetInputs(q)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if fleetHash(q, tokens) != q.Hash {
		fail(w, 409, errors.New("the selection or a client's values changed since the preview; preview again"))
		return
	}
	type outcome struct {
		TenantID string `json:"tenantId"`
		Name     string `json:"name"`
		Created  int    `json:"created"`
		Existed  int    `json:"alreadyThere"`
		Failed   int    `json:"failed"`
		Detail   string `json:"detail,omitempty"`
		RunID    int64  `json:"runId,omitempty"`
	}
	var outs []outcome
	stoppedAt := ""
	for i, tn := range order {
		t, _ := s.Store.Tenant(tn)
		tk, _ := s.Store.Tokens(tn)
		o := outcome{TenantID: tn, Name: t.Name}
		res, err := s.Engine.Deploy(r.Context(), engine.DeployRequest{TenantID: tn, TemplateIDs: q.TemplateIDs, Tokens: tk,
			State: "enabledForReportingButNotEnforced", Actor: actor(r), Rollout: engine.RolloutNone})
		if err != nil {
			o.Failed, o.Detail = len(q.TemplateIDs), err.Error()
		} else {
			o.RunID = res.RunID
			for _, it := range res.Items {
				switch it.Result {
				case "created":
					o.Created++
				case "exists":
					o.Existed++
				case "failed":
					o.Failed++
					o.Detail = it.Name + ": " + it.Detail
				}
			}
		}
		outs = append(outs, o)
		if o.Failed > 0 && i == 0 && len(order) > 1 && q.Canary != "" {
			stoppedAt = t.Name
			break
		}
	}
	msg := "applied to every chosen client"
	if stoppedAt != "" {
		msg = fmt.Sprintf("stopped after the canary (%s) had a failure; no other client was touched", stoppedAt)
	}
	writeJSON(w, 200, map[string]any{"summary": msg, "stoppedAtCanary": stoppedAt != "", "clients": outs})
}
