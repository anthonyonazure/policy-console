package impact

import (
	"context"
	"fmt"
	"strings"
)

// ObservedDevice is what Intune itself says about one device and one policy.
type ObservedDevice struct {
	Name   string `json:"name"`
	User   string `json:"user"`
	Status string `json:"status"` // compliant | noncompliant | error | conflict | notApplicable | unknown
}

// Observed is the real result after a policy has been assigned to some devices.
type Observed struct {
	Compliant     int              `json:"compliant"`
	NonCompliant  int              `json:"nonCompliant"`
	Problems      int              `json:"problems"`      // error or conflict: the policy did not evaluate cleanly
	NotApplicable int              `json:"notApplicable"` // devices the policy does not apply to
	Unknown       int              `json:"unknown"`       // not reported yet
	Devices       []ObservedDevice `json:"devices"`
}

// Judged is how many devices gave a clear answer.
func (o Observed) Judged() int { return o.Compliant + o.NonCompliant + o.Problems }

// PercentCompliant is the real share of judged devices that comply. The second
// value is false when no device has reported yet, so the caller cannot mistake
// silence for success.
func (o Observed) PercentCompliant() (int, bool) {
	if o.Judged() == 0 {
		return 0, false
	}
	return 100 * o.Compliant / o.Judged(), true
}

// ObservedFromGraph reads a policy's per device status.
func ObservedFromGraph(ctx context.Context, g Lister, policyID string) (*Observed, error) {
	items, err := g.List(ctx, "/beta/deviceManagement/deviceCompliancePolicies/"+policyID+"/deviceStatuses")
	if err != nil {
		return nil, err
	}
	return ParseObserved(items), nil
}

// ParseObserved maps Intune's per device statuses.
func ParseObserved(items []map[string]any) *Observed {
	o := &Observed{}
	for _, m := range items {
		d := ObservedDevice{}
		d.Name, _ = m["deviceDisplayName"].(string)
		d.User, _ = m["userPrincipalName"].(string)
		st, _ := m["status"].(string)
		d.Status = st
		switch strings.ToLower(st) {
		case "compliant":
			o.Compliant++
		case "noncompliant":
			o.NonCompliant++
		case "error", "conflict":
			o.Problems++
		case "notapplicable":
			o.NotApplicable++
		default:
			o.Unknown++
			d.Status = "unknown"
		}
		o.Devices = append(o.Devices, d)
	}
	return o
}

// Comparison sets the prediction beside what happened, per device, so the
// preview earns trust or shows where it was wrong.
type Comparison struct {
	Agreed    int          `json:"agreed"`
	Disagreed int          `json:"disagreed"`
	NotInBoth int          `json:"notInBoth"` // devices only one side knows about
	Rows      []CompareRow `json:"disagreements"`
}

type CompareRow struct {
	Device    string `json:"device"`
	Predicted string `json:"predicted"`
	Observed  string `json:"observed"`
}

// Compare joins predicted verdicts and observed statuses by device name. A
// "cannot tell" prediction never counts as a disagreement: it made no claim.
func Compare(predicted []DeviceVerdict, observed *Observed) Comparison {
	obs := map[string]string{}
	for _, d := range observed.Devices {
		obs[strings.ToLower(d.Name)] = d.Status
	}
	var c Comparison
	seen := map[string]bool{}
	for _, p := range predicted {
		key := strings.ToLower(p.Name)
		os, ok := obs[key]
		if !ok {
			c.NotInBoth++
			continue
		}
		seen[key] = true
		if p.Verdict == Unknown || p.Verdict == Stale || os == "unknown" || os == "notApplicable" {
			continue
		}
		pc := p.Verdict == OK
		oc := strings.EqualFold(os, "compliant")
		if pc == oc {
			c.Agreed++
		} else {
			c.Disagreed++
			c.Rows = append(c.Rows, CompareRow{Device: p.Name, Predicted: verdictWord(p.Verdict), Observed: os})
		}
	}
	for k := range obs {
		if !seen[k] {
			c.NotInBoth++
		}
	}
	return c
}

func verdictWord(v string) string {
	if v == OK {
		return "compliant"
	}
	return "would fail"
}

func (o Observed) String() string {
	return fmt.Sprintf("%d compliant, %d not compliant, %d problems", o.Compliant, o.NonCompliant, o.Problems)
}
