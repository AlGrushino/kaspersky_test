package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kaspersky_test/internal/domain"
)

type fakeService struct {
	createFn func(ctx context.Context, in domain.CreateThreatInput) (*domain.Threat, error)
	getFn    func(ctx context.Context, md5 string) (*domain.Threat, error)
	updateFn func(ctx context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error)
}

func (f *fakeService) Create(ctx context.Context, in domain.CreateThreatInput) (*domain.Threat, error) {
	if f.createFn == nil {
		return nil, errors.New("createFn not set")
	}
	return f.createFn(ctx, in)
}

func (f *fakeService) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	if f.getFn == nil {
		return nil, errors.New("getFn not set")
	}
	return f.getFn(ctx, md5)
}

func (f *fakeService) Update(ctx context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error) {
	if f.updateFn == nil {
		return nil, errors.New("updateFn not set")
	}
	return f.updateFn(ctx, md5, in)
}

func ptr[T any](v T) *T { return &v }

const (
	testMD5 = "d41d8cd98f00b204e9800998ecf8427e"
)

func sampleThreat() *domain.Threat {
	now := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	return &domain.Threat{
		MD5:       testMD5,
		Name:      "Trojan.Win32.Generic",
		Severity:  ptr(domain.SeverityHigh),
		Tags:      []string{"windows"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newTestRouter(svc ThreatService) http.Handler {
	h := NewHandler(svc)
	health := NewHealthHandler(fakePinger{})
	return NewRouter(h, health, testLogger(), 1000, 1000, "")
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakePinger struct{}

func (fakePinger) Ping(context.Context) error { return nil }

func do(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestCreateThreat_201(t *testing.T) {
	svc := &fakeService{
		createFn: func(_ context.Context, in domain.CreateThreatInput) (*domain.Threat, error) {
			if in.MD5 != testMD5 {
				t.Fatalf("md5 passed to service = %q, want %q", in.MD5, testMD5)
			}
			return sampleThreat(), nil
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info",
		`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/info/"+testMD5 {
		t.Fatalf("Location = %q, want /info/%s", loc, testMD5)
	}

	var resp ThreatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Md5 != testMD5 {
		t.Fatalf("md5 = %q, want %q", resp.Md5, testMD5)
	}
}

func TestCreateThreat_400_InvalidJSON(t *testing.T) {
	svc := &fakeService{}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info", `{invalid`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCreateThreat_400_InvalidMD5(t *testing.T) {
	svc := &fakeService{}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info", `{"md5":"bad","name":"X"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestCreateThreat_400_Validation(t *testing.T) {
	svc := &fakeService{
		createFn: func(context.Context, domain.CreateThreatInput) (*domain.Threat, error) {
			return nil, domain.ErrValidation
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info",
		`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"X"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCreateThreat_409_Conflict(t *testing.T) {
	svc := &fakeService{
		createFn: func(context.Context, domain.CreateThreatInput) (*domain.Threat, error) {
			return nil, domain.ErrConflict
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info",
		`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"X"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestCreateThreat_500(t *testing.T) {
	svc := &fakeService{
		createFn: func(context.Context, domain.CreateThreatInput) (*domain.Threat, error) {
			return nil, errors.New("db down")
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPost, "/info",
		`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"X"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "db down") {
		t.Fatal("internal error must not leak to client")
	}
}

func TestCreateThreat_415_WrongContentType(t *testing.T) {
	router := newTestRouter(&fakeService{})

	r := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", w.Code)
	}
}

func TestGetInfoByMd5_200(t *testing.T) {
	svc := &fakeService{
		getFn: func(_ context.Context, md5 string) (*domain.Threat, error) {
			if md5 != testMD5 {
				t.Fatalf("md5 = %q, want %q", md5, testMD5)
			}
			return sampleThreat(), nil
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodGet, "/info/"+testMD5, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp ThreatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Md5 != testMD5 {
		t.Fatalf("md5 = %q, want %q", resp.Md5, testMD5)
	}
}

func TestGetInfoByMd5_400_InvalidMD5(t *testing.T) {
	router := newTestRouter(&fakeService{})

	w := do(t, router, http.MethodGet, "/info/bad", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetInfoByMd5_404(t *testing.T) {
	svc := &fakeService{
		getFn: func(context.Context, string) (*domain.Threat, error) {
			return nil, domain.ErrNotFound
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodGet, "/info/"+testMD5, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetInfoByMd5_500(t *testing.T) {
	svc := &fakeService{
		getFn: func(context.Context, string) (*domain.Threat, error) {
			return nil, errors.New("boom")
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodGet, "/info/"+testMD5, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestUpdateThreat_200(t *testing.T) {
	svc := &fakeService{
		updateFn: func(_ context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error) {
			if md5 != testMD5 {
				t.Fatalf("md5 = %q, want %q", md5, testMD5)
			}
			if in.Name != "Updated.Name" {
				t.Fatalf("name = %q, want Updated.Name", in.Name)
			}
			th := sampleThreat()
			th.Name = "Updated.Name"
			return th, nil
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPut, "/info/"+testMD5, `{"name":"Updated.Name"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp ThreatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Name != "Updated.Name" {
		t.Fatalf("name = %q, want Updated.Name", resp.Name)
	}
}

func TestUpdateThreat_400_InvalidMD5(t *testing.T) {
	router := newTestRouter(&fakeService{})

	w := do(t, router, http.MethodPut, "/info/bad", `{"name":"X"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestUpdateThreat_400_Validation(t *testing.T) {
	svc := &fakeService{
		updateFn: func(context.Context, string, domain.UpdateThreatInput) (*domain.Threat, error) {
			return nil, domain.ErrValidation
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPut, "/info/"+testMD5, `{"name":"X"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestUpdateThreat_404(t *testing.T) {
	svc := &fakeService{
		updateFn: func(context.Context, string, domain.UpdateThreatInput) (*domain.Threat, error) {
			return nil, domain.ErrNotFound
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPut, "/info/"+testMD5, `{"name":"X"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestUpdateThreat_500(t *testing.T) {
	svc := &fakeService{
		updateFn: func(context.Context, string, domain.UpdateThreatInput) (*domain.Threat, error) {
			return nil, errors.New("boom")
		},
	}
	router := newTestRouter(svc)

	w := do(t, router, http.MethodPut, "/info/"+testMD5, `{"name":"X"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestHealthz(t *testing.T) {
	router := newTestRouter(&fakeService{})
	w := do(t, router, http.MethodGet, "/healthz", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestNotFound_JSON(t *testing.T) {
	router := newTestRouter(&fakeService{})
	w := do(t, router, http.MethodGet, "/unknown", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
}

func TestMethodNotAllowed_JSON(t *testing.T) {
	router := newTestRouter(&fakeService{})
	w := do(t, router, http.MethodGet, "/info", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
}
