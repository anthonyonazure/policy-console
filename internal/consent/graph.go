package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const graphBase = "https://graph.microsoft.com/v1.0"

// ServicePrincipal is the slice of a Graph service principal this package needs.
type ServicePrincipal struct {
	ID       string    `json:"id"`
	AppID    string    `json:"appId"`
	AppRoles []AppRole `json:"appRoles,omitempty"`
}

type AppRole struct {
	ID                 string   `json:"id"`
	Value              string   `json:"value"`
	IsEnabled          bool     `json:"isEnabled"`
	AllowedMemberTypes []string `json:"allowedMemberTypes"`
}

// Assignment is an application permission already granted to a service principal.
type Assignment struct {
	AppRoleID  string `json:"appRoleId"`
	ResourceID string `json:"resourceId"`
}

// APIError carries Graph's status so callers can tell "already there" from "failed".
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("graph returned %d: %s", e.Status, e.Body) }

// API is the Graph surface consent needs, small enough to fake in tests.
type API interface {
	FindServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error) // nil, nil when absent
	CreateServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error)
	Assignments(ctx context.Context, spID string) ([]Assignment, error)
	Assign(ctx context.Context, spID, resourceID, roleID string) error
}

// HTTPAPI is the real API, authenticated with one delegated bearer token for a
// single client tenant. The token is held for the length of one request and never stored.
type HTTPAPI struct {
	Token  string
	Base   string // defaults to Microsoft Graph v1.0; tests point it elsewhere
	Client *http.Client
	Sleep  func(time.Duration)
}

func (h *HTTPAPI) base() string {
	if h.Base != "" {
		return h.Base
	}
	return graphBase
}

func (h *HTTPAPI) do(ctx context.Context, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	sleep := h.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, h.base()+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+h.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		// Microsoft says slow down with 429 or 503; wait as long as it asks, a few times.
		if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < 4 {
			wait := time.Duration(1<<attempt) * time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 60 {
				wait = time.Duration(s) * time.Second
			}
			sleep(wait)
			continue
		}
		if resp.StatusCode/100 != 2 {
			return &APIError{Status: resp.StatusCode, Body: truncate(string(b), 300)}
		}
		if out != nil && len(b) > 0 {
			return json.Unmarshal(b, out)
		}
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (h *HTTPAPI) FindServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error) {
	var out struct {
		Value []ServicePrincipal `json:"value"`
	}
	q := "/servicePrincipals?$filter=appId%20eq%20'" + appID + "'&$select=id,appId,appRoles"
	if err := h.do(ctx, http.MethodGet, q, nil, &out); err != nil {
		return nil, err
	}
	if len(out.Value) == 0 {
		return nil, nil
	}
	return &out.Value[0], nil
}

func (h *HTTPAPI) CreateServicePrincipal(ctx context.Context, appID string) (*ServicePrincipal, error) {
	var sp ServicePrincipal
	if err := h.do(ctx, http.MethodPost, "/servicePrincipals", map[string]string{"appId": appID}, &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}

func (h *HTTPAPI) Assignments(ctx context.Context, spID string) ([]Assignment, error) {
	var all []Assignment
	path := "/servicePrincipals/" + spID + "/appRoleAssignments?$top=999"
	for path != "" {
		var page struct {
			Value []Assignment `json:"value"`
			Next  string       `json:"@odata.nextLink"`
		}
		if err := h.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		path = ""
		if page.Next != "" {
			if len(page.Next) <= len(graphBase) || page.Next[:len(graphBase)] != graphBase {
				return nil, fmt.Errorf("refusing to follow a next link outside Microsoft Graph")
			}
			path = page.Next[len(graphBase):]
		}
	}
	return all, nil
}

func (h *HTTPAPI) Assign(ctx context.Context, spID, resourceID, roleID string) error {
	return h.do(ctx, http.MethodPost, "/servicePrincipals/"+spID+"/appRoleAssignments",
		map[string]string{"principalId": spID, "resourceId": resourceID, "appRoleId": roleID}, nil)
}
