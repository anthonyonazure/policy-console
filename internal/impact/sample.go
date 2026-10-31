package impact

import (
	"context"
	"fmt"
	"time"
)

// SampleSource returns 42 invented Windows devices and a few phones. It exists
// so the screens can be built and shown before a tenant with devices is
// connected. Nothing here is real and the API labels every answer built from it.
type SampleSource struct{}

// IsSample marks the source so the API can say the data is invented.
func (SampleSource) IsSample() bool { return true }

func (SampleSource) Devices(_ context.Context, _ string) ([]Device, error) {
	now := time.Now().UTC()
	tr, fa := true, false
	people := []string{"Ada", "Ben", "Cora", "Dev", "Eli", "Fay", "Gus", "Hana", "Ivo", "Jun", "Kai", "Lena"}
	plan := []struct {
		ver   string
		count int
	}{{"10.0.19044.5011", 1}, {"10.0.19045.5011", 5}, {"10.0.22621.4460", 6}, {"10.0.22631.4460", 14}, {"10.0.26100.2314", 16}}
	var out []Device
	n := 0
	for _, p := range plan {
		for i := 0; i < p.count; i++ {
			n++
			d := Device{
				ID: fmt.Sprintf("sample-%02d", n), Name: fmt.Sprintf("SAMPLE-LT-%02d", n),
				User: fmt.Sprintf("%s.%c@sample.invalid", people[n%len(people)], 'a'+rune(n%26)), Platform: "Windows", OSVersion: p.ver,
				Encrypted: &tr, SecureBoot: &tr, CodeIntegrity: &tr, LastSync: now.Add(-24 * time.Hour),
			}
			switch n {
			case 3, 9, 30:
				d.Encrypted = &fa
			case 4, 22:
				d.SecureBoot = &fa
			case 17, 18:
				d.SecureBoot = nil
			case 8, 40:
				d.LastSync = now.Add(-61 * 24 * time.Hour)
			}
			out = append(out, d)
		}
	}
	for i, v := range []string{"17.4", "17.6", "16.7", "18.0"} {
		d := Device{ID: fmt.Sprintf("sample-ios-%d", i), Name: fmt.Sprintf("SAMPLE-IPHONE-%d", i+1), User: "phone.user@sample.invalid",
			Platform: "iOS", OSVersion: v, JailBroken: &fa, LastSync: now.Add(-2 * time.Hour)}
		if i == 2 {
			d.JailBroken = &tr
		}
		out = append(out, d)
	}
	return out, nil
}
