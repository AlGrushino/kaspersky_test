//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kaspersky_test/internal/api"
	"kaspersky_test/internal/repository/postgres"
	"kaspersky_test/internal/service"
	"kaspersky_test/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	testMD5    = "d41d8cd98f00b204e9800998ecf8427e"
	testMD5Alt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type e2eEnv struct {
	server *httptest.Server
	client *http.Client
}

func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpContext(ctx, db, "."))

	repo := postgres.New(pool)
	svc := service.New(repo)
	handler := api.NewHandler(svc)
	health := api.NewHealthHandler(pool)

	logger := testLogger()
	router := api.NewRouter(handler, health, logger, 1000, 1000, "")

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &e2eEnv{
		server: srv,
		client: srv.Client(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (e *e2eEnv) do(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, e.server.URL+path, bytes.NewBufferString(body))
	} else {
		req, err = http.NewRequest(method, e.server.URL+path, nil)
	}
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := e.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, data
}

func (e *e2eEnv) createValid(t *testing.T) map[string]any {
	t.Helper()
	body := `{
		"md5": "` + testMD5 + `",
		"name": "Trojan.Win32.Generic",
		"severity": "high",
		"type": "trojan",
		"status": "active",
		"confidence": 95,
		"tags": ["windows", "executable"]
	}`
	status, data := e.do(t, http.MethodPost, "/info", body)
	require.Equal(t, http.StatusCreated, status, "body: %s", string(data))

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func TestE2E_Create_201(t *testing.T) {
	env := setupE2E(t)

	body := `{"md5":"` + testMD5 + `","name":"Trojan.Win32.Generic","severity":"high"}`
	status, data := env.do(t, http.MethodPost, "/info", body)
	require.Equal(t, http.StatusCreated, status, "body: %s", string(data))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	require.Equal(t, testMD5, resp["md5"])
	require.Equal(t, "Trojan.Win32.Generic", resp["name"])
	require.NotEmpty(t, resp["created_at"])
	require.NotEmpty(t, resp["updated_at"])

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/info/"+testMD5, nil)
	resp2, err := env.client.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestE2E_Create_201_LocationHeader(t *testing.T) {
	env := setupE2E(t)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/info",
		bytes.NewBufferString(`{"md5":"`+testMD5+`","name":"X"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, "/info/"+testMD5, resp.Header.Get("Location"))
}

func TestE2E_Create_409_Conflict(t *testing.T) {
	env := setupE2E(t)
	env.createValid(t)

	status, data := env.do(t, http.MethodPost, "/info",
		`{"md5":"`+testMD5+`","name":"Duplicate"}`)
	require.Equal(t, http.StatusConflict, status, "body: %s", string(data))
}

func TestE2E_Create_400_InvalidMD5(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodPost, "/info", `{"md5":"bad","name":"X"}`)
	require.Equal(t, http.StatusBadRequest, status, "body: %s", string(data))
}

func TestE2E_Create_400_EmptyName(t *testing.T) {
	env := setupE2E(t)

	status, _ := env.do(t, http.MethodPost, "/info",
		`{"md5":"`+testMD5+`","name":""}`)
	require.Equal(t, http.StatusBadRequest, status)
}

func TestE2E_Create_400_InvalidJSON(t *testing.T) {
	env := setupE2E(t)

	status, _ := env.do(t, http.MethodPost, "/info", `{invalid`)
	require.Equal(t, http.StatusBadRequest, status)
}

func TestE2E_Create_415_WrongContentType(t *testing.T) {
	env := setupE2E(t)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/info",
		bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := env.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestE2E_Create_413_BodyTooLarge(t *testing.T) {
	env := setupE2E(t)

	big := bytes.Repeat([]byte("a"), 2*1024*1024)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/info", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestE2E_Get_200(t *testing.T) {
	env := setupE2E(t)
	env.createValid(t)

	status, data := env.do(t, http.MethodGet, "/info/"+testMD5, "")
	require.Equal(t, http.StatusOK, status, "body: %s", string(data))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	require.Equal(t, testMD5, resp["md5"])
	require.Equal(t, "Trojan.Win32.Generic", resp["name"])
}

func TestE2E_Get_404(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodGet, "/info/"+testMD5Alt, "")
	require.Equal(t, http.StatusNotFound, status, "body: %s", string(data))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	require.Equal(t, "threat not found", resp["message"])
}

func TestE2E_Get_400_InvalidMD5(t *testing.T) {
	env := setupE2E(t)

	status, _ := env.do(t, http.MethodGet, "/info/bad", "")
	require.Equal(t, http.StatusBadRequest, status)
}

func TestE2E_Update_200(t *testing.T) {
	env := setupE2E(t)
	created := env.createValid(t)
	originalCreatedAt := created["created_at"].(string)

	time.Sleep(10 * time.Millisecond)

	status, data := env.do(t, http.MethodPut, "/info/"+testMD5,
		`{"name":"Updated.Name","severity":"critical"}`)
	require.Equal(t, http.StatusOK, status, "body: %s", string(data))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	require.Equal(t, "Updated.Name", resp["name"])
	require.Equal(t, "critical", resp["severity"])
	require.Equal(t, originalCreatedAt, resp["created_at"], "created_at must not change")
	require.NotEqual(t, created["updated_at"], resp["updated_at"], "updated_at must change")
}

func TestE2E_Update_FullReplace(t *testing.T) {
	env := setupE2E(t)
	env.createValid(t)

	status, data := env.do(t, http.MethodPut, "/info/"+testMD5, `{"name":"Only.Name"}`)
	require.Equal(t, http.StatusOK, status, "body: %s", string(data))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	require.Equal(t, "Only.Name", resp["name"])
	require.Nil(t, resp["severity"])
	require.Nil(t, resp["type"])
	require.Nil(t, resp["status"])
	require.Nil(t, resp["confidence"])
	require.Nil(t, resp["tags"])
}

func TestE2E_Update_404(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodPut, "/info/"+testMD5Alt, `{"name":"X"}`)
	require.Equal(t, http.StatusNotFound, status, "body: %s", string(data))
}

func TestE2E_Update_400_InvalidMD5(t *testing.T) {
	env := setupE2E(t)

	status, _ := env.do(t, http.MethodPut, "/info/bad", `{"name":"X"}`)
	require.Equal(t, http.StatusBadRequest, status)
}

func TestE2E_Update_400_EmptyName(t *testing.T) {
	env := setupE2E(t)
	env.createValid(t)

	status, _ := env.do(t, http.MethodPut, "/info/"+testMD5, `{"name":""}`)
	require.Equal(t, http.StatusBadRequest, status)
}

func TestE2E_Healthz(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodGet, "/healthz", "")
	require.Equal(t, http.StatusOK, status, "body: %s", string(data))
}

func TestE2E_Readyz(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodGet, "/readyz", "")
	require.Equal(t, http.StatusOK, status, "body: %s", string(data))
}

func TestE2E_NotFound_JSON(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodGet, "/unknown", "")
	require.Equal(t, http.StatusNotFound, status)
	require.Contains(t, string(data), `"message"`)
}

func TestE2E_MethodNotAllowed_JSON(t *testing.T) {
	env := setupE2E(t)

	status, data := env.do(t, http.MethodGet, "/info", "")
	require.Equal(t, http.StatusMethodNotAllowed, status)
	require.Contains(t, string(data), `"message"`)
}

func TestE2E_RequestIDHeader(t *testing.T) {
	env := setupE2E(t)

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/healthz", nil)
	resp, err := env.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.NotEmpty(t, resp.Header.Get("X-Request-Id"))
}

func TestE2E_ErrorResponseFormat(t *testing.T) {
	env := setupE2E(t)

	_, data := env.do(t, http.MethodGet, "/info/"+testMD5Alt, "")
	var resp api.ErrorResponse
	require.NoError(t, json.Unmarshal(data, &resp))
	require.NotEmpty(t, resp.Message)
}

func assertJSONError(t *testing.T, data []byte) {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp), "not JSON: %s", string(data))
	require.Contains(t, resp, "message")
}

var _ = fmt.Sprintf
