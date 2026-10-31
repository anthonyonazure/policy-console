// Package graph is a small Microsoft Graph client for the collections this
// console manages. It uses client credentials against a multi-tenant app
// registration, so a tenant becomes reachable once its admin has consented.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const base = "https://graph.microsoft.com"

// ErrReadOnly is returned when the console is running with writes disabled.
var ErrReadOnly = fmt.Errorf("console is in read-only mode; write refused")

type Client struct {
	TenantID     string
	clientID     string
	clientSecret string
	readOnly     bool
	http         *http.Client

	// baseURL and fixedToken exist so tests can point the client at a local
	// server. Production clients leave both empty.
	baseURL    string
	fixedToken string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func New(tenantID, clientID, clientSecret string, readOnly bool) *Client {
	return &Client{
		TenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		readOnly:     readOnly,
		http:         &http.Client{Timeout: 60 * time.Second},
	}
}

// NewForTest returns a client that talks to a local server with a fixed token
// and no OAuth exchange. It is for tests only.
func NewForTest(serverURL string, readOnly bool) *Client {
	return &Client{TenantID: "test", readOnly: readOnly, http: &http.Client{Timeout: 10 * time.Second}, baseURL: serverURL, fixedToken: "test-token"}
}

// IsForbidden reports whether err is Graph refusing because the app lacks
// permission. Only 403 counts. A 401 means the credential itself is bad (an
// expired secret, a revoked app), which is an outage, not a missing grant, and
// must never be read as "nothing is wrong".
func IsForbidden(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusForbidden
}

// APIError carries the Graph status and body so the UI can show the real reason
// a call failed instead of a generic failure.
type APIError struct {
	Status int
	Body   string
	URI    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("graph %s returned %d: %s", e.URI, e.Status, truncate(e.Body, 600))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	if c.fixedToken != "" {
		return c.fixedToken, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry.Add(-2*time.Minute)) {
		return c.token, nil
	}
	if c.clientID == "" || c.clientSecret == "" {
		return "", fmt.Errorf("no app credentials configured (set PC_CLIENT_ID and PC_CLIENT_SECRET)")
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {base + "/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{Status: resp.StatusCode, Body: string(body), URI: endpoint}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	c.token = tok.AccessToken
	c.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) do(ctx context.Context, method, uri string, body []byte) ([]byte, error) {
	return c.doH(ctx, method, uri, body, nil)
}

// Request is a call with extra headers, for APIs such as Planner that require
// If-Match on every change. It returns the raw response body.
func (c *Client) Request(ctx context.Context, method, uri string, body []byte, headers map[string]string) ([]byte, error) {
	return c.doH(ctx, method, uri, body, headers)
}

func (c *Client) doH(ctx context.Context, method, uri string, body []byte, hdr map[string]string) ([]byte, error) {
	if method != http.MethodGet && c.readOnly {
		return nil, ErrReadOnly
	}
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	full := uri
	if strings.HasPrefix(uri, "/") {
		root := base
		if c.baseURL != "" {
			root = c.baseURL
		}
		full = root + uri
	}
	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, full, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Microsoft says slow down with 429 (and sometimes 503). Wait as long as it
		// asks and try again a few times, so a busy fleet slows down instead of failing.
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < maxRetries {
			wait := backoff(attempt, resp.Header.Get("Retry-After"))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return nil, &APIError{Status: resp.StatusCode, Body: string(out), URI: full}
		}
		return out, nil
	}
}

// List follows @odata.nextLink and returns every item in a collection.
func (c *Client) List(ctx context.Context, uri string) ([]map[string]any, error) {
	var items []map[string]any
	next := uri
	for next != "" {
		raw, err := c.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value    []map[string]any `json:"value"`
			NextLink string           `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		items = append(items, page.Value...)
		next = page.NextLink
	}
	return items, nil
}

// FirstPage returns only the first page of a collection. Some Graph
// collections are histories: /security/secureScores returns one entry per day
// and still offers a nextLink even with $top=1, so following pagination there
// walks the tenant's whole history to answer "what is the score now".
func (c *Client) FirstPage(ctx context.Context, uri string) ([]map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	var page struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, err
	}
	return page.Value, nil
}

func (c *Client) Get(ctx context.Context, uri string) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

func (c *Client) Post(ctx context.Context, uri string, body []byte) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodPost, uri, body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	return out, json.Unmarshal(raw, &out)
}

func (c *Client) Patch(ctx context.Context, uri string, body []byte) error {
	_, err := c.do(ctx, http.MethodPatch, uri, body)
	return err
}

func (c *Client) Delete(ctx context.Context, uri string) error {
	_, err := c.do(ctx, http.MethodDelete, uri, nil)
	return err
}

// Probe confirms the app can reach a tenant and reports the organization name,
// which is how the console proves consent actually landed.
func (c *Client) Probe(ctx context.Context) (string, error) {
	out, err := c.Get(ctx, "/v1.0/organization?$select=displayName,id")
	if err != nil {
		return "", err
	}
	if vals, ok := out["value"].([]any); ok && len(vals) > 0 {
		if org, ok := vals[0].(map[string]any); ok {
			if name, ok := org["displayName"].(string); ok {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("tenant reachable but returned no organization record")
}

// PostAction calls an action endpoint such as targetApps, which answers with
// no body on success.
func (c *Client) PostAction(ctx context.Context, uri string, body []byte) error {
	_, err := c.do(ctx, http.MethodPost, uri, body)
	return err
}

// maxRetries is how many times a throttled call is retried.
const maxRetries = 4

// retryScale lets tests shrink the waits; production leaves it at 1.
var retryScale = time.Duration(1)

// backoff returns how long to wait: what Retry-After says (capped at a minute),
// otherwise 1, 2, 4, 8 seconds.
func backoff(attempt int, retryAfter string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s > 0 {
		if s > 60 {
			s = 60
		}
		return time.Duration(s) * time.Second / retryScale
	}
	return time.Duration(1<<attempt) * time.Second / retryScale
}
