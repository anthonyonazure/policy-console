// Package impact predicts, before a compliance policy is deployed, which of a
// client's devices would pass it, which would fail and why. It judges only what
// the device data can show; anything else is reported as "cannot tell", never
// guessed. It reads devices and writes nothing.
package impact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	OK      = "ok"      // would be compliant
	Fail    = "fail"    // would fail at least one setting that is on
	Unknown = "unknown" // passes what can be judged, but something that is on cannot be judged
	Stale   = "stale"   // not seen recently; counted, not judged

	StaleAfter = 30 * 24 * time.Hour
)

// Device is the slice of an enrolled device the preview needs. A nil pointer
// means the service did not say, which is different from "no".
type Device struct {
	ID, Name, User string
	Platform       string // Windows, macOS, iOS, Android
	OSVersion      string
	Encrypted      *bool
	JailBroken     *bool
	SecureBoot     *bool
	CodeIntegrity  *bool
	LastSync       time.Time
}

// Setting is one compliance setting the preview knows how to judge.
type Setting struct {
	Key         string
	Label       string
	Platform    string
	Kind        string // "version" or "bool"
	Recommended any    // shown when the setting is off, so "what if I switch it on" has an answer
	judge       func(d Device, want any) (verdict, reason string)
}

// Registry is every judgeable setting. Anything in a policy that is not here is
// listed as not predictable.
var Registry = []Setting{
	{Key: "osMinimumVersion", Label: "Minimum operating system", Platform: "Windows", Kind: "version", Recommended: "10.0.22621", judge: judgeMinOS},
	{Key: "bitLockerEnabled", Label: "Disk encryption (BitLocker) required", Platform: "Windows", Kind: "bool", Recommended: true, judge: judgeEncrypted},
	{Key: "storageRequireEncryption", Label: "Storage encryption required", Platform: "Windows", Kind: "bool", Recommended: true, judge: judgeEncrypted},
	{Key: "secureBootEnabled", Label: "Secure Boot required", Platform: "Windows", Kind: "bool", Recommended: true, judge: judgeFlag(func(d Device) *bool { return d.SecureBoot }, "Secure Boot is off")},
	{Key: "codeIntegrityEnabled", Label: "Code integrity required", Platform: "Windows", Kind: "bool", Recommended: true, judge: judgeFlag(func(d Device) *bool { return d.CodeIntegrity }, "Code integrity is off")},

	{Key: "osMinimumVersion", Label: "Minimum operating system", Platform: "macOS", Kind: "version", Recommended: "14.0", judge: judgeMinOS},
	{Key: "storageRequireEncryption", Label: "Disk encryption (FileVault) required", Platform: "macOS", Kind: "bool", Recommended: true, judge: judgeEncrypted},

	{Key: "osMinimumVersion", Label: "Minimum operating system", Platform: "iOS", Kind: "version", Recommended: "17.0", judge: judgeMinOS},
	{Key: "securityBlockJailbrokenDevices", Label: "Block jailbroken devices", Platform: "iOS", Kind: "bool", Recommended: true, judge: judgeJailbreak},

	{Key: "osMinimumVersion", Label: "Minimum operating system", Platform: "Android", Kind: "version", Recommended: "13.0", judge: judgeMinOS},
	{Key: "storageRequireEncryption", Label: "Storage encryption required", Platform: "Android", Kind: "bool", Recommended: true, judge: judgeEncrypted},
	{Key: "securityBlockJailbrokenDevices", Label: "Block rooted devices", Platform: "Android", Kind: "bool", Recommended: true, judge: judgeJailbreak},
}

// PlatformOf names the platform a compliance policy applies to from its type.
func PlatformOf(odataType string) string {
	t := strings.ToLower(odataType)
	switch {
	case strings.Contains(t, "windows"):
		return "Windows"
	case strings.Contains(t, "macos"):
		return "macOS"
	case strings.Contains(t, "ios"):
		return "iOS"
	case strings.Contains(t, "android"):
		return "Android"
	}
	return ""
}

// ---- judging ----

func judgeMinOS(d Device, want any) (string, string) {
	req, _ := want.(string)
	if req == "" {
		return "", ""
	}
	if d.OSVersion == "" {
		return Unknown, "The device has not reported its operating system version"
	}
	if CompareVersions(d.OSVersion, req) < 0 {
		return Fail, fmt.Sprintf("%s %s is older than the required %s", d.Platform, d.OSVersion, req)
	}
	return OK, ""
}

func judgeEncrypted(d Device, want any) (string, string) {
	if b, _ := want.(bool); !b {
		return "", ""
	}
	switch {
	case d.Encrypted == nil:
		return Unknown, "The device has not reported whether its disk is encrypted"
	case !*d.Encrypted:
		return Fail, "The disk is not encrypted"
	}
	return OK, ""
}

func judgeJailbreak(d Device, want any) (string, string) {
	if b, _ := want.(bool); !b {
		return "", ""
	}
	switch {
	case d.JailBroken == nil:
		return Unknown, "The device has not reported whether it is jailbroken or rooted"
	case *d.JailBroken:
		return Fail, "The device is jailbroken or rooted"
	}
	return OK, ""
}

func judgeFlag(get func(Device) *bool, failText string) func(Device, any) (string, string) {
	return func(d Device, want any) (string, string) {
		if b, _ := want.(bool); !b {
			return "", ""
		}
		v := get(d)
		switch {
		case v == nil:
			return Unknown, "The service has no health attestation for this device, so this cannot be checked"
		case !*v:
			return Fail, failText
		}
		return OK, ""
	}
}

// CompareVersions compares dotted version strings numerically, treating a
// missing part as zero, so 10.0.22621 equals 10.0.22621.0 and 10.0.22631.4460
// is newer than 10.0.22621. Non numeric parts compare as zero.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimSpace(pa[i]))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.TrimSpace(pb[i]))
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ---- configuration ----

// Config says which settings are on and at what value. A policy body provides
// the starting point and Overrides change it for a what-if: a value turns a
// setting on at that value, null turns it off.
type Config map[string]any

// ConfigFromPolicy reads the judgeable settings that are on in a policy body.
// "On" means a true boolean or a non empty version string.
func ConfigFromPolicy(body []byte) (cfg Config, platform string, notPredictable []string, err error) {
	var doc map[string]any
	if err = json.Unmarshal(body, &doc); err != nil {
		return nil, "", nil, err
	}
	ot, _ := doc["@odata.type"].(string)
	platform = PlatformOf(ot)
	if platform == "" {
		return nil, "", nil, fmt.Errorf("this policy type is not a compliance policy the preview understands")
	}
	cfg = Config{}
	known := map[string]bool{}
	for _, s := range Registry {
		if s.Platform != platform {
			continue
		}
		known[s.Key] = true
		switch v := doc[s.Key].(type) {
		case bool:
			if v {
				cfg[s.Key] = true
			}
		case string:
			if v != "" {
				cfg[s.Key] = v
			}
		}
	}
	// Settings that are on in the policy but that device data cannot judge.
	for k, v := range doc {
		if known[k] || strings.Contains(k, "@odata") || reserved[k] {
			continue
		}
		switch x := v.(type) {
		case bool:
			if x {
				notPredictable = append(notPredictable, k)
			}
		case string:
			if x != "" && !strings.HasPrefix(x, "unavailable") && x != "deviceDefault" && x != "notConfigured" {
				notPredictable = append(notPredictable, k)
			}
		case float64:
			if x != 0 && x != 65535 {
				notPredictable = append(notPredictable, k)
			}
		}
	}
	sort.Strings(notPredictable)
	return cfg, platform, notPredictable, nil
}

var reserved = map[string]bool{"displayName": true, "description": true, "roleScopeTagIds": true, "scheduledActionsForRule": true, "version": true, "id": true}

// Apply returns cfg with overrides applied. The original is not changed.
func (c Config) Apply(overrides map[string]any) Config {
	out := Config{}
	for k, v := range c {
		out[k] = v
	}
	for k, v := range overrides {
		if v == nil || v == false || v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// ---- evaluation ----

type DeviceVerdict struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	User    string   `json:"user"`
	OS      string   `json:"osVersion"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}

type Fleet struct {
	Oldest  string `json:"oldest,omitempty"` // for version settings
	Newest  string `json:"newest,omitempty"`
	Median  string `json:"median,omitempty"`
	Yes     int    `json:"yes"` // for yes or no settings
	No      int    `json:"no"`
	Unknown int    `json:"unknown"`
}

type SettingImpact struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Kind        string `json:"kind"`
	On          bool   `json:"on"`
	Value       any    `json:"value,omitempty"`
	Recommended any    `json:"recommended"`
	// Hypothetical is true when the setting is off and the counts show what would
	// happen if it were switched on at the recommended value.
	Hypothetical bool     `json:"hypothetical"`
	Fails        int      `json:"fails"`
	Unknown      int      `json:"unknown"`
	FailNames    []string `json:"failNames,omitempty"`
	Fleet        Fleet    `json:"fleet"`
}

type Counts struct {
	OK        int `json:"compliant"`
	Fail      int `json:"fail"`
	Unknown   int `json:"cannotTell"`
	Stale     int `json:"notSeen"`
	Active    int `json:"judged"` // devices that were judged (not stale)
	PercentOK int `json:"percentCompliant"`
}

type Result struct {
	Platform       string          `json:"platform"`
	Counts         Counts          `json:"counts"`
	Oldest         *DeviceVerdict  `json:"oldestActiveDevice,omitempty"`
	Settings       []SettingImpact `json:"settings"`
	Devices        []DeviceVerdict `json:"devices"`
	NotPredictable []string        `json:"notPredictable,omitempty"`
}

// Evaluate judges the devices of one platform against the settings that are on in cfg.
func Evaluate(platform string, cfg Config, notPredictable []string, devices []Device, now time.Time) *Result {
	var fleet []Device
	for _, d := range devices {
		if d.Platform == platform {
			fleet = append(fleet, d)
		}
	}
	res := &Result{Platform: platform, NotPredictable: notPredictable}
	var active []Device
	for _, d := range fleet {
		if !d.LastSync.IsZero() && now.Sub(d.LastSync) > StaleAfter {
			days := int(now.Sub(d.LastSync).Hours() / 24)
			res.Devices = append(res.Devices, verdict(d, Stale, []string{fmt.Sprintf("Not seen for %d days", days)}))
			res.Counts.Stale++
			continue
		}
		active = append(active, d)
	}

	for _, d := range active {
		var fails, unknowns []string
		for _, s := range Registry {
			if s.Platform != platform {
				continue
			}
			want, on := cfg[s.Key]
			if !on {
				continue
			}
			v, why := s.judge(d, want)
			switch v {
			case Fail:
				fails = append(fails, why)
			case Unknown:
				unknowns = append(unknowns, why)
			}
		}
		switch {
		case len(fails) > 0:
			res.Devices = append(res.Devices, verdict(d, Fail, fails))
			res.Counts.Fail++
		case len(unknowns) > 0:
			res.Devices = append(res.Devices, verdict(d, Unknown, unknowns))
			res.Counts.Unknown++
		default:
			res.Devices = append(res.Devices, verdict(d, OK, nil))
			res.Counts.OK++
		}
	}
	res.Counts.Active = len(active)
	if res.Counts.Active > 0 {
		res.Counts.PercentOK = 100 * res.Counts.OK / res.Counts.Active
	}
	order := map[string]int{Fail: 0, Unknown: 1, OK: 2, Stale: 3}
	sort.SliceStable(res.Devices, func(i, j int) bool {
		if order[res.Devices[i].Verdict] != order[res.Devices[j].Verdict] {
			return order[res.Devices[i].Verdict] < order[res.Devices[j].Verdict]
		}
		return res.Devices[i].Name < res.Devices[j].Name
	})

	if o := oldestOf(active); o != nil {
		v := verdict(*o, "", nil)
		res.Oldest = &v
	}
	for _, s := range Registry {
		if s.Platform != platform {
			continue
		}
		res.Settings = append(res.Settings, impactOf(s, cfg, active))
	}
	return res
}

func verdict(d Device, v string, reasons []string) DeviceVerdict {
	return DeviceVerdict{ID: d.ID, Name: d.Name, User: d.User, OS: d.OSVersion, Verdict: v, Reasons: reasons}
}

func oldestOf(ds []Device) *Device {
	var o *Device
	for i := range ds {
		if ds[i].OSVersion == "" {
			continue
		}
		if o == nil || CompareVersions(ds[i].OSVersion, o.OSVersion) < 0 {
			o = &ds[i]
		}
	}
	return o
}

func impactOf(s Setting, cfg Config, active []Device) SettingImpact {
	want, on := cfg[s.Key]
	si := SettingImpact{Key: s.Key, Label: s.Label, Kind: s.Kind, On: on, Recommended: s.Recommended}
	if on {
		si.Value = want
	} else {
		want, si.Hypothetical = s.Recommended, true
	}
	for _, d := range active {
		switch v, _ := s.judge(d, want); v {
		case Fail:
			si.Fails++
			si.FailNames = append(si.FailNames, d.Name)
		case Unknown:
			si.Unknown++
		}
	}
	sort.Strings(si.FailNames)
	si.Fleet = fleetOf(s, active)
	return si
}

func fleetOf(s Setting, active []Device) Fleet {
	var f Fleet
	switch s.Key {
	case "osMinimumVersion":
		var vs []string
		for _, d := range active {
			if d.OSVersion != "" {
				vs = append(vs, d.OSVersion)
			}
		}
		sort.Slice(vs, func(i, j int) bool { return CompareVersions(vs[i], vs[j]) < 0 })
		if len(vs) > 0 {
			f.Oldest, f.Newest, f.Median = vs[0], vs[len(vs)-1], vs[len(vs)/2]
		}
	default:
		for _, d := range active {
			var v *bool
			switch s.Key {
			case "bitLockerEnabled", "storageRequireEncryption":
				v = d.Encrypted
			case "securityBlockJailbrokenDevices":
				if d.JailBroken != nil {
					nb := !*d.JailBroken // "yes" here means the device is fine
					v = &nb
				}
			case "secureBootEnabled":
				v = d.SecureBoot
			case "codeIntegrityEnabled":
				v = d.CodeIntegrity
			}
			switch {
			case v == nil:
				f.Unknown++
			case *v:
				f.Yes++
			default:
				f.No++
			}
		}
	}
	return f
}
