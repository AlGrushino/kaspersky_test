package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"kaspersky_test/internal/domain"
)

type fakeRepo struct {
	store map[string]*domain.Threat

	createErr error
	getErr    error
	updateErr error

	createCalls int
	getCalls    int
	updateCalls int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{store: make(map[string]*domain.Threat)}
}

func (f *fakeRepo) Create(_ context.Context, t *domain.Threat) (*domain.Threat, error) {
	f.createCalls++
	if f.createErr != nil {
		return nil, f.createErr
	}
	if _, ok := f.store[t.MD5]; ok {
		return nil, domain.ErrConflict
	}
	cp := *t
	f.store[t.MD5] = &cp
	return &cp, nil
}

func (f *fakeRepo) GetByMD5(_ context.Context, md5 string) (*domain.Threat, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	t, ok := f.store[md5]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (f *fakeRepo) Update(_ context.Context, t *domain.Threat) (*domain.Threat, error) {
	f.updateCalls++
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	existing, ok := f.store[t.MD5]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *t
	cp.CreatedAt = existing.CreatedAt
	f.store[t.MD5] = &cp
	return &cp, nil
}

type fakeCache struct {
	store map[string]*domain.Threat
}

func (f *fakeCache) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	t, ok := f.store[md5]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return t, nil
}

func (f *fakeCache) Set(ctx context.Context, t *domain.Threat) error {
	_, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	f.store["threat:"+t.MD5] = t
	return nil
}

func (f *fakeCache) Delete(ctx context.Context, md5 string) error {
	delete(f.store, md5)
	return nil
}

func newFakeCache() *fakeCache {
	return &fakeCache{store: make(map[string]*domain.Threat)}
}

func ptr[T any](v T) *T { return &v }

const (
	testMD5    = "d41d8cd98f00b204e9800998ecf8427e"
	testMD5Alt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func validInput() domain.CreateThreatInput {
	return domain.CreateThreatInput{
		MD5:      testMD5,
		Name:     "Trojan.Win32.Generic",
		Severity: ptr(domain.SeverityHigh),
		Tags:     []string{"windows"},
	}
}

func TestCreate_Success(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	before := time.Now().UTC()

	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MD5 != testMD5 {
		t.Fatalf("md5 = %q, want %q", got.MD5, testMD5)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatal("timestamps must be set")
	}
	if got.CreatedAt.Before(before) {
		t.Fatal("created_at must be >= test start")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Fatal("created_at and updated_at must be equal on create")
	}
	if repo.createCalls != 1 {
		t.Fatalf("repo.Create calls = %d, want 1", repo.createCalls)
	}
}

func TestCreate_NormalizesMD5(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.MD5 = "D41D8CD98F00B204E9800998ECF8427E"

	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MD5 != testMD5 {
		t.Fatalf("md5 = %q, want lower-case %q", got.MD5, testMD5)
	}
}

func TestCreate_NormalizesSHA256(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.SHA256 = ptr("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")

	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got.SHA256 == nil || *got.SHA256 != want {
		t.Fatalf("sha256 = %v, want %q", got.SHA256, want)
	}
}

func TestCreate_InvalidMD5(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.MD5 = "not-a-md5"

	_, err := svc.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
	if repo.createCalls != 0 {
		t.Fatal("repo.Create must not be called on validation error")
	}
}

func TestCreate_ValidationError(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.Name = ""

	_, err := svc.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
	if repo.createCalls != 0 {
		t.Fatal("repo.Create must not be called on validation error")
	}
}

func TestCreate_Conflict(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	if _, err := svc.Create(context.Background(), validInput()); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	_, err := svc.Create(context.Background(), validInput())
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestCreate_TagsNilBecomesEmpty(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.Tags = nil

	got, err := svc.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Tags == nil {
		t.Fatal("tags must be non-nil empty slice")
	}
}

func TestGet_Success(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	if _, err := svc.Create(context.Background(), validInput()); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	got, err := svc.Get(context.Background(), testMD5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MD5 != testMD5 {
		t.Fatalf("md5 = %q, want %q", got.MD5, testMD5)
	}
}

func TestGet_NormalizesMD5(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	if _, err := svc.Create(context.Background(), validInput()); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	got, err := svc.Get(context.Background(), "D41D8CD98F00B204E9800998ECF8427E")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MD5 != testMD5 {
		t.Fatalf("md5 = %q, want %q", got.MD5, testMD5)
	}
}

func TestGet_NotFound(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	_, err := svc.Get(context.Background(), testMD5Alt)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGet_InvalidMD5(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	_, err := svc.Get(context.Background(), "bad")
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
	if repo.getCalls != 0 {
		t.Fatal("repo.GetByMD5 must not be called on invalid md5")
	}
}

func TestUpdate_Success(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	created, err := svc.Create(context.Background(), validInput())
	if err != nil {
		t.Fatalf("seed create failed: %v", err)
	}
	createdAt := created.CreatedAt

	time.Sleep(2 * time.Millisecond)

	in := domain.UpdateThreatInput{
		Name:     "Updated.Name",
		Severity: ptr(domain.SeverityCritical),
	}
	got, err := svc.Update(context.Background(), testMD5, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "Updated.Name" {
		t.Fatalf("name = %q, want Updated.Name", got.Name)
	}
	if got.Severity == nil || *got.Severity != domain.SeverityCritical {
		t.Fatal("severity must be critical")
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Fatal("created_at must not change on update")
	}
	if !got.UpdatedAt.After(createdAt) {
		t.Fatal("updated_at must be after created_at")
	}
}

func TestUpdate_FullReplace(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	in := validInput()
	in.Description = ptr("original description")
	in.Family = ptr("OriginalFamily")
	if _, err := svc.Create(context.Background(), in); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	update := domain.UpdateThreatInput{Name: "Only.Name"}
	got, err := svc.Update(context.Background(), testMD5, update)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Description != nil {
		t.Fatal("description must be nil after full replace")
	}
	if got.Family != nil {
		t.Fatal("family must be nil after full replace")
	}
	if got.Severity != nil {
		t.Fatal("severity must be nil after full replace")
	}
	if len(got.Tags) != 0 {
		t.Fatal("tags must be empty after full replace")
	}
}

func TestUpdate_NotFound(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	_, err := svc.Update(context.Background(), testMD5Alt, domain.UpdateThreatInput{Name: "X"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdate_InvalidMD5(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	_, err := svc.Update(context.Background(), "bad", domain.UpdateThreatInput{Name: "X"})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
	if repo.updateCalls != 0 {
		t.Fatal("repo.Update must not be called on invalid md5")
	}
}

func TestUpdate_ValidationError(t *testing.T) {
	repo := newFakeRepo()
	cache := newFakeCache()
	svc := New(repo, cache)

	if _, err := svc.Create(context.Background(), validInput()); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	_, err := svc.Update(context.Background(), testMD5, domain.UpdateThreatInput{Name: ""})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}
