// Package planner posts a build out plan to Microsoft Planner and keeps it up
// to date: one bucket per pack, one task per step. It only ever creates and
// updates. It never deletes a task, and it never reopens one a person finished.
package planner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/graph"
)

// ErrNotConfigured means no Planner plan or group was set up for the console.
var ErrNotConfigured = errors.New("Planner is not set up: set PC_PLANNER_PLAN_ID (post into an existing plan) or PC_PLANNER_GROUP_ID (create one plan per build out in that group)")

// API is the part of Graph this package calls, so tests can stand in.
type API interface {
	Request(ctx context.Context, method, uri string, body []byte, headers map[string]string) ([]byte, error)
}

// Task is one step as it should appear in Planner.
type Task struct {
	StepID      string
	Title       string
	Bucket      string
	Description string
	Done        bool
}

// Spec is the whole plan as it should appear.
type Spec struct {
	Title string
	Tasks []Task
}

// Link remembers which Planner task a step became, and what was last sent.
type Link struct {
	TaskID   string
	BucketID string
	Hash     string
}

// State is where the console remembers what it has already posted.
type State interface {
	Plan() string
	SetPlan(id string) error
	Links() map[string]Link
	Save(stepID string, l Link) error
}

// Syncer posts and updates. PlanID wins over GroupID when both are set.
type Syncer struct {
	API     API
	PlanID  string
	GroupID string
}

// Result says what a sync did, in counts a person can read.
type Result struct {
	PlanID             string   `json:"planId"`
	Created            int      `json:"created"`
	Updated            int      `json:"updated"`
	Unchanged          int      `json:"unchanged"`
	CompletedInPlanner []string `json:"completedInPlanner,omitempty"` // finished by a person; the console left them alone
	RemovedInPlanner   []string `json:"removedInPlanner,omitempty"`   // deleted by a person; the console did not bring them back
	Failed             []string `json:"failed,omitempty"`
}

// Preview is what a sync would do, worked out without calling Planner.
type Preview struct {
	Posted    bool `json:"posted"`
	WouldPost int  `json:"wouldCreate"`
	WouldEdit int  `json:"wouldUpdate"`
	Unchanged int  `json:"unchanged"`
}

func hashOf(t Task) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%v", t.Title, t.Bucket, t.Description, t.Done)))
	return hex.EncodeToString(h[:])
}

// Plan works out what Sync would do from what was posted before.
func Plan(spec Spec, st State) Preview {
	links := st.Links()
	p := Preview{Posted: st.Plan() != ""}
	for _, t := range spec.Tasks {
		switch l, ok := links[t.StepID]; {
		case !ok:
			p.WouldPost++
		case l.Hash != hashOf(t):
			p.WouldEdit++
		default:
			p.Unchanged++
		}
	}
	return p
}

func (s *Syncer) ensurePlan(ctx context.Context, spec Spec, st State) (string, error) {
	if id := st.Plan(); id != "" {
		return id, nil
	}
	id := s.PlanID
	switch {
	case id != "":
		if _, err := s.get(ctx, "/v1.0/planner/plans/"+id); err != nil {
			return "", fmt.Errorf("cannot open the Planner plan: %w", explain(err))
		}
	case s.GroupID != "":
		body, _ := json.Marshal(map[string]any{
			"container": map[string]string{"url": "https://graph.microsoft.com/v1.0/groups/" + s.GroupID},
			"title":     spec.Title,
		})
		out, err := s.send(ctx, http.MethodPost, "/v1.0/planner/plans", body, nil)
		if err != nil {
			return "", fmt.Errorf("cannot create the Planner plan: %w", explain(err))
		}
		id = str(out, "id")
	default:
		return "", ErrNotConfigured
	}
	if id == "" {
		return "", errors.New("Planner did not return a plan id")
	}
	return id, st.SetPlan(id)
}

// Sync creates what is missing and updates what changed.
func (s *Syncer) Sync(ctx context.Context, spec Spec, st State) (*Result, error) {
	planID, err := s.ensurePlan(ctx, spec, st)
	if err != nil {
		return nil, err
	}
	res := &Result{PlanID: planID}

	links := st.Links()
	var buckets map[string]string
	for _, t := range spec.Tasks {
		if _, posted := links[t.StepID]; !posted {
			if buckets, err = s.buckets(ctx, planID, spec); err != nil {
				return res, err
			}
			break // only needed when something is new
		}
	}
	for _, t := range spec.Tasks {
		h := hashOf(t)
		l, posted := links[t.StepID]
		switch {
		case !posted:
			l, err = s.create(ctx, planID, buckets[t.Bucket], t, h)
			if err != nil {
				if l.TaskID != "" { // made but not filled in: remember it so the next sync finishes it instead of duplicating it
					l.Hash = ""
					if serr := st.Save(t.StepID, l); serr != nil {
						return res, serr
					}
				}
				res.Failed = append(res.Failed, t.Title+": "+err.Error())
				if graph.IsForbidden(err) {
					return res, explain(err)
				}
				continue
			}
			res.Created++
		case l.Hash == h:
			res.Unchanged++
			continue
		default:
			state, err := s.update(ctx, l, t)
			if err != nil {
				res.Failed = append(res.Failed, t.Title+": "+err.Error())
				continue
			}
			switch state {
			case "removed":
				res.RemovedInPlanner = append(res.RemovedInPlanner, t.Title)
			case "finished":
				res.CompletedInPlanner = append(res.CompletedInPlanner, t.Title)
				res.Updated++
			default:
				res.Updated++
			}
			l.Hash = h
		}
		if err := st.Save(t.StepID, l); err != nil {
			return res, err
		}
	}
	return res, nil
}

// buckets returns bucket ids by name, creating the missing ones. They are made
// last pack first, because Planner puts each new bucket at the front.
func (s *Syncer) buckets(ctx context.Context, planID string, spec Spec) (map[string]string, error) {
	out, err := s.get(ctx, "/v1.0/planner/plans/"+planID+"/buckets")
	if err != nil {
		return nil, explain(err)
	}
	ids := map[string]string{}
	if vals, ok := out["value"].([]any); ok {
		for _, v := range vals {
			if m, ok := v.(map[string]any); ok {
				ids[str(m, "name")] = str(m, "id")
			}
		}
	}
	var order []string
	seen := map[string]bool{}
	for _, t := range spec.Tasks {
		if !seen[t.Bucket] {
			seen[t.Bucket] = true
			order = append(order, t.Bucket)
		}
	}
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		if ids[name] != "" {
			continue
		}
		body, _ := json.Marshal(map[string]string{"name": name, "planId": planID, "orderHint": " !"})
		made, err := s.send(ctx, http.MethodPost, "/v1.0/planner/buckets", body, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot create bucket %q: %w", name, explain(err))
		}
		ids[name] = str(made, "id")
	}
	return ids, nil
}

func (s *Syncer) create(ctx context.Context, planID, bucketID string, t Task, h string) (Link, error) {
	body := map[string]any{"planId": planID, "bucketId": bucketID, "title": t.Title}
	if t.Done {
		body["percentComplete"] = 100
	}
	raw, _ := json.Marshal(body)
	made, err := s.send(ctx, http.MethodPost, "/v1.0/planner/tasks", raw, nil)
	if err != nil {
		return Link{}, err
	}
	l := Link{TaskID: str(made, "id"), BucketID: bucketID}
	if l.TaskID == "" {
		return l, errors.New("Planner did not return a task id")
	}
	if err := s.setDescription(ctx, l.TaskID, t.Description); err != nil {
		return l, fmt.Errorf("task created but its notes were not set: %w", err)
	}
	l.Hash = h
	return l, nil
}

// update brings an existing task up to date. It reports "finished" when a
// person already completed it in Planner, and "removed" when it is gone.
func (s *Syncer) update(ctx context.Context, l Link, t Task) (string, error) {
	state := "updated"
	for attempt := 0; attempt < 2; attempt++ {
		cur, err := s.get(ctx, "/v1.0/planner/tasks/"+l.TaskID)
		if isStatus(err, http.StatusNotFound) {
			return "removed", nil
		}
		if err != nil {
			return "", err
		}
		patch := map[string]any{}
		if str(cur, "title") != t.Title {
			patch["title"] = t.Title
		}
		pct, _ := cur["percentComplete"].(float64)
		switch {
		case t.Done && pct < 100:
			patch["percentComplete"] = 100
		case !t.Done && pct == 100:
			state = "finished" // a person did this; never reopen it
		}
		if len(patch) == 0 {
			break
		}
		raw, _ := json.Marshal(patch)
		_, err = s.send(ctx, http.MethodPatch, "/v1.0/planner/tasks/"+l.TaskID, raw, map[string]string{"If-Match": str(cur, "@odata.etag")})
		if isStatus(err, http.StatusPreconditionFailed) {
			continue // someone edited it between our read and write: read again
		}
		if err != nil {
			return "", err
		}
		break
	}
	if err := s.setDescription(ctx, l.TaskID, t.Description); err != nil {
		return "", err
	}
	return state, nil
}

func (s *Syncer) setDescription(ctx context.Context, taskID, desc string) error {
	raw, _ := json.Marshal(map[string]string{"description": desc})
	for attempt := 0; attempt < 2; attempt++ {
		cur, err := s.get(ctx, "/v1.0/planner/tasks/"+taskID+"/details")
		if err != nil {
			return err
		}
		if str(cur, "description") == desc {
			return nil
		}
		_, err = s.send(ctx, http.MethodPatch, "/v1.0/planner/tasks/"+taskID+"/details", raw, map[string]string{"If-Match": str(cur, "@odata.etag")})
		if isStatus(err, http.StatusPreconditionFailed) {
			continue
		}
		return err
	}
	return errors.New("the task kept changing while the console tried to update it; it will retry next sync")
}

func (s *Syncer) get(ctx context.Context, uri string) (map[string]any, error) {
	return s.send(ctx, http.MethodGet, uri, nil, nil)
}

func (s *Syncer) send(ctx context.Context, method, uri string, body []byte, hdr map[string]string) (map[string]any, error) {
	if method != http.MethodGet {
		hdr = merge(hdr, map[string]string{"Prefer": "return=representation"})
	}
	raw, err := s.API.Request(ctx, method, uri, body, hdr)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func isStatus(err error, code int) bool {
	var ae *graph.APIError
	return errors.As(err, &ae) && ae.Status == code
}

// explain turns a permission refusal into words that say what to fix.
func explain(err error) error {
	if graph.IsForbidden(err) {
		return fmt.Errorf("Microsoft refused: the console's write app needs the Tasks.ReadWrite.All permission in this tenant, and access to the plan's group (%w)", err)
	}
	return err
}
