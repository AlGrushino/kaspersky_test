package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Pinger checks whether a dependency, usually the database, is available.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthHandler serves liveness and readiness probes.
type HealthHandler struct {
	db    Pinger
	cache Pinger
}

// NewHealthHandler returns a HealthHandler that uses pinger for readiness checks.
func NewHealthHandler(db, cache Pinger) *HealthHandler {
	return &HealthHandler{db: db, cache: cache}
}

// Healthz reports that the process is alive.
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz reports readiness by pinging the database.
func (h *HealthHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp := map[string]string{"status": "ready"}

	if err := h.db.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"error":  "db:" + err.Error(),
		})
		return
	}

	if h.cache != nil {
		if err := h.cache.Ping(ctx); err != nil {
			resp["cache"] = "unavailable"
		} else {
			resp["cache"] = "ok"
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
