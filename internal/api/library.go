package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/anthonyonazure/policy-console/internal/catalog"
	"github.com/anthonyonazure/policy-console/internal/diff"
	"github.com/anthonyonazure/policy-console/internal/equiv"
	"github.com/anthonyonazure/policy-console/internal/store"
)

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,80}$`)

// InitLibrary loads the operator's published templates into the catalog, on top
// of the built in set. A published template with the id of a built in one replaces
// it. It remembers which ids were built in so edits can say so.
func (s *Server) InitLibrary() (int, error) {
	s.builtin = map[string]bool{}
	for _, t := range s.Cat.All() {
		s.builtin[t.ID] = true
	}
	pub, err := s.Store.PublishedLibrary()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, p := range pub {
		t, err := catalog.Build(id, p.Category, p.Body)
		if err != nil {
			return n, fmt.Errorf("published template %q: %w", id, err)
		}
		s.Cat.Upsert(t)
		n++
	}
	return n, nil
}

// checkPublishable is the gate every published template passes. It reuses the
// guards deploy applies, so an unsafe template cannot get as far as a deploy.
func checkPublishable(id, category string, body []byte) error {
	t, err := catalog.Build(id, category, body)
	if err != nil {
		return fmt.Errorf("this is not a usable template: %w", err)
	}
	if strings.TrimSpace(t.Name) == "" || t.Name == id {
		var probe map[string]any
		if err := jsonUnmarshal(body, &probe); err != nil || probe[catalog.Collections[t.Kind].NameProperty] == nil {
			return errors.New("a template needs a name")
		}
	}
	if store.HasRedaction(body) {
		return errors.New("this copy contains a [redacted] marker; the real value is not stored. Put a placeholder such as ${WIFI_KEY} there")
	}
	if secrets := store.FindSecrets(body); len(secrets) > 0 {
		return fmt.Errorf("a shared template must not contain a secret written out (%s). Use a placeholder such as ${WIFI_KEY} and give the real value per client", strings.Join(secrets, ", "))
	}
	if t.Kind == catalog.KindConditionalAccess {
		if sh, err := equiv.Parse(body); err == nil && equiv.BlocksEveryone(sh) {
			return errors.New("this policy would block every user from every app and lock a tenant out, so it cannot be published")
		}
	}
	return nil
}

func (s *Server) libraryList(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Store.LibraryTemplates()
	if err != nil {
		fail(w, 500, err)
		return
	}
	for i := range ts {
		_ = i
	}
	type view struct {
		store.LibraryTemplate
		OverridesBuiltIn bool `json:"overridesBuiltIn"`
	}
	out := make([]view, 0, len(ts))
	for _, t := range ts {
		out = append(out, view{t, s.builtin[t.ID]})
	}
	writeJSON(w, 200, out)
}

type libraryReq struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Body      string `json:"body"`
	CloneFrom string `json:"cloneFrom"`
	Reason    string `json:"reason"`
	Version   int    `json:"version"`
}

// libraryCreate starts a template: from a body, or as a copy of an existing one.
func (s *Server) libraryCreate(w http.ResponseWriter, r *http.Request) {
	q, err := body[libraryReq](r)
	if err != nil {
		fail(w, 400, errors.New("expected id, category and body, or cloneFrom"))
		return
	}
	if !idRE.MatchString(q.ID) {
		fail(w, 400, errors.New("the id must be lower case letters, numbers and hyphens"))
		return
	}
	text, cat := q.Body, q.Category
	if q.CloneFrom != "" {
		src := s.Cat.Get(q.CloneFrom)
		if src == nil {
			fail(w, 404, fmt.Errorf("unknown template %q", q.CloneFrom))
			return
		}
		text = string(src.Body)
		if cat == "" {
			cat = src.Category
		}
	}
	if cat == "" || text == "" {
		fail(w, 400, errors.New("a template needs a category and a body"))
		return
	}
	if _, err := catalog.Build(q.ID, cat, []byte(text)); err != nil {
		fail(w, 400, fmt.Errorf("this is not a usable template: %w", err))
		return
	}
	// Reusing a built in id edits that built in template (the original stays in the
	// program; the published edit replaces it at runtime). Any other id must be new.
	if s.Cat.Get(q.ID) != nil && !s.builtin[q.ID] {
		fail(w, 409, store.ErrTemplateExists)
		return
	}
	if err := s.Store.CreateLibraryTemplate(q.ID, cat, q.CloneFrom, actor(r), []byte(text)); err != nil {
		code := 400
		if errors.Is(err, store.ErrTemplateExists) {
			code = 409
		}
		fail(w, code, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": q.ID, "state": "draft"})
}

func (s *Server) libraryDraft(w http.ResponseWriter, r *http.Request) {
	q, err := body[libraryReq](r)
	if err != nil || q.Body == "" {
		fail(w, 400, errors.New("expected the new body"))
		return
	}
	id := r.PathValue("id")
	vs, err := s.Store.LibraryVersions(id, false)
	if err != nil || len(vs) == 0 {
		fail(w, 404, store.ErrNoTemplate)
		return
	}
	cat := s.libraryCategory(id)
	if _, err := catalog.Build(id, cat, []byte(q.Body)); err != nil {
		fail(w, 400, fmt.Errorf("this is not a usable template: %w", err))
		return
	}
	if err := s.Store.SaveDraft(id, actor(r), []byte(q.Body)); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "state": "draft"})
}

func (s *Server) libraryCategory(id string) string {
	ts, _ := s.Store.LibraryTemplates()
	for _, t := range ts {
		if t.ID == id {
			return t.Category
		}
	}
	return ""
}

// libraryPublish makes the draft current. Only an approver can, a reason is
// required, and the template must pass the same safety checks as a deploy.
func (s *Server) libraryPublish(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q, _ := body[libraryReq](r)
	who := actor(r)
	if !s.isApprover(who) {
		fail(w, 403, errors.New("only an approver can publish a template"))
		return
	}
	vs, err := s.Store.LibraryVersions(id, true)
	if err != nil || len(vs) == 0 {
		fail(w, 404, store.ErrNoTemplate)
		return
	}
	if vs[0].State != "draft" {
		fail(w, 400, errors.New("there is no draft to publish"))
		return
	}
	cat := s.libraryCategory(id)
	if err := checkPublishable(id, cat, []byte(vs[0].Body)); err != nil {
		fail(w, 400, err)
		return
	}
	v, err := s.Store.PublishDraft(id, who, q.Reason)
	if err != nil {
		fail(w, 400, err)
		return
	}
	t, _ := catalog.Build(id, cat, []byte(vs[0].Body))
	s.Cat.Upsert(t)
	writeJSON(w, 200, map[string]any{"id": id, "publishedVersion": v})
}

func (s *Server) libraryVersions(w http.ResponseWriter, r *http.Request) {
	vs, err := s.Store.LibraryVersions(r.PathValue("id"), r.URL.Query().Get("bodies") == "true")
	if err != nil || len(vs) == 0 {
		fail(w, 404, store.ErrNoTemplate)
		return
	}
	writeJSON(w, 200, vs)
}

// libraryDiff compares two versions in plain terms.
func (s *Server) libraryDiff(w http.ResponseWriter, r *http.Request) {
	from, e1 := strconv.Atoi(r.URL.Query().Get("from"))
	to, e2 := strconv.Atoi(r.URL.Query().Get("to"))
	if e1 != nil || e2 != nil {
		fail(w, 400, errors.New("give from and to version numbers"))
		return
	}
	vs, err := s.Store.LibraryVersions(r.PathValue("id"), true)
	if err != nil || len(vs) == 0 {
		fail(w, 404, store.ErrNoTemplate)
		return
	}
	var a, b *store.LibraryVersion
	for i := range vs {
		if vs[i].Version == from {
			a = &vs[i]
		}
		if vs[i].Version == to {
			b = &vs[i]
		}
	}
	if a == nil || b == nil {
		fail(w, 404, errors.New("no such version"))
		return
	}
	changes, err := diff.Compare([]byte(a.Body), []byte(b.Body))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"from": from, "to": to, "changes": changes})
}

// libraryRevert makes an old version the new current one. It is a new version,
// so the history keeps both and the revert can itself be reverted.
func (s *Server) libraryRevert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q, _ := body[libraryReq](r)
	if !s.isApprover(actor(r)) {
		fail(w, 403, errors.New("only an approver can publish a template"))
		return
	}
	vs, err := s.Store.LibraryVersions(id, true)
	if err != nil || len(vs) == 0 {
		fail(w, 404, store.ErrNoTemplate)
		return
	}
	var old *store.LibraryVersion
	for i := range vs {
		if vs[i].Version == q.Version && vs[i].State == "published" {
			old = &vs[i]
		}
	}
	if old == nil {
		fail(w, 404, errors.New("no such published version"))
		return
	}
	cat := s.libraryCategory(id)
	if err := checkPublishable(id, cat, []byte(old.Body)); err != nil {
		fail(w, 400, err)
		return
	}
	if err := s.Store.SaveDraft(id, actor(r), []byte(old.Body)); err != nil {
		fail(w, 500, err)
		return
	}
	reason := strings.TrimSpace(q.Reason)
	if reason == "" {
		reason = fmt.Sprintf("reverted to version %d", old.Version)
	}
	v, err := s.Store.PublishDraft(id, actor(r), reason)
	if err != nil {
		fail(w, 500, err)
		return
	}
	t, _ := catalog.Build(id, cat, []byte(old.Body))
	s.Cat.Upsert(t)
	writeJSON(w, 200, map[string]any{"id": id, "publishedVersion": v, "revertedTo": old.Version})
}
