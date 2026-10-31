package impact

import (
	"context"
	"strings"
	"time"
)

// Lister is the part of the Graph client the device source needs.
type Lister interface {
	List(ctx context.Context, uri string) ([]map[string]any, error)
}

// Source reads a client's enrolled devices.
type Source interface {
	Devices(ctx context.Context, tenantID string) ([]Device, error)
}

// GraphSource reads devices through Microsoft Graph with a read credential.
type GraphSource struct {
	New func(tenantID string) Lister
}

const devicesURI = "/beta/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,isEncrypted,jailBroken,lastSyncDateTime,deviceHealthAttestationState"

func (g GraphSource) Devices(ctx context.Context, tenantID string) ([]Device, error) {
	items, err := g.New(tenantID).List(ctx, devicesURI)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(items))
	for _, m := range items {
		out = append(out, DeviceFromGraph(m))
	}
	return out, nil
}

// DeviceFromGraph maps one managed device. Fields the service leaves out stay
// nil, so "unknown" is never turned into "no".
func DeviceFromGraph(m map[string]any) Device {
	s := func(k string) string { v, _ := m[k].(string); return v }
	d := Device{ID: s("id"), Name: s("deviceName"), User: s("userPrincipalName"), OSVersion: s("osVersion"), Platform: platformName(s("operatingSystem"))}
	if b, ok := m["isEncrypted"].(bool); ok {
		d.Encrypted = &b
	}
	if v, ok := m["jailBroken"].(string); ok {
		switch strings.ToLower(v) {
		case "true":
			t := true
			d.JailBroken = &t
		case "false":
			f := false
			d.JailBroken = &f
		}
	}
	if t, err := time.Parse(time.RFC3339, s("lastSyncDateTime")); err == nil && t.Year() > 1 {
		d.LastSync = t
	}
	if att, ok := m["deviceHealthAttestationState"].(map[string]any); ok {
		d.SecureBoot = attestation(att, "secureBoot")
		d.CodeIntegrity = attestation(att, "codeIntegrityCheck", "codeIntegrity")
	}
	return d
}

// attestation reads an "enabled" or "disabled" health attestation value; anything
// else, including "unknown" and a missing key, is not an answer.
func attestation(att map[string]any, keys ...string) *bool {
	for _, k := range keys {
		v, _ := att[k].(string)
		switch strings.ToLower(v) {
		case "enabled":
			t := true
			return &t
		case "disabled":
			f := false
			return &f
		}
	}
	return nil
}

func platformName(os string) string {
	switch strings.ToLower(os) {
	case "windows":
		return "Windows"
	case "macos":
		return "macOS"
	case "ios", "ipados":
		return "iOS"
	case "android":
		return "Android"
	}
	return os
}
