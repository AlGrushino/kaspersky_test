package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"kaspersky_test/internal/domain"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	middlewarestd "github.com/slok/go-http-metrics/middleware/std"
)

// ThreatService defines the business operations used by HTTP handlers.
type ThreatService interface {
	Create(ctx context.Context, in domain.CreateThreatInput) (*domain.Threat, error)
	Get(ctx context.Context, md5 string) (*domain.Threat, error)
	Update(ctx context.Context, md5 string, in domain.UpdateThreatInput) (*domain.Threat, error)
}

// ThreatHandler implements the generated strict server interface.
type ThreatHandler struct {
	service ThreatService
}

// NewHandler returns a ThreatHandler backed by service.
func NewHandler(service ThreatService) *ThreatHandler {
	return &ThreatHandler{service: service}
}

var _ StrictServerInterface = (*ThreatHandler)(nil)

// GetInfoByMd5 handles GET /info/{md5}.
func (h *ThreatHandler) GetInfoByMd5(ctx context.Context, request GetInfoByMd5RequestObject) (GetInfoByMd5ResponseObject, error) {
	md5, err := domain.NormalizeMD5(request.Md5)
	if err != nil {
		return GetInfoByMd5400JSONResponse(errorBody("invalid md5", err.Error())), nil
	}

	threat, err := h.service.Get(ctx, md5)
	switch {
	case err == nil:
		return GetInfoByMd5200JSONResponse(toThreatResponse(threat)), nil
	case errors.Is(err, domain.ErrNotFound):
		return GetInfoByMd5404JSONResponse(errorBody("threat not found", err.Error())), nil
	default:
		slog.ErrorContext(ctx, "failed to get threat", "md5", request.Md5, "error", err)
		return GetInfoByMd5500JSONResponse(errorBody("internal server error", "")), nil
	}
}

// CreateThreat handles POST /info.
func (h *ThreatHandler) CreateThreat(ctx context.Context, request CreateThreatRequestObject) (CreateThreatResponseObject, error) {
	if request.Body == nil {
		return CreateThreat400JSONResponse(errorBody("invalid request body", "body is required")), nil
	}

	in, err := fromCreateRequest(*request.Body)
	if err != nil {
		return CreateThreat400JSONResponse(errorBody("invalid request", err.Error())), nil
	}

	threat, err := h.service.Create(ctx, in)
	switch {
	case err == nil:
		location := "/info/" + threat.MD5
		return CreateThreat201JSONResponse{
			Body: toThreatResponse(threat),
			Headers: CreateThreat201ResponseHeaders{
				Location: &location,
			},
		}, nil
	case errors.Is(err, domain.ErrValidation):
		return CreateThreat400JSONResponse(errorBody("invalid request", err.Error())), nil
	case errors.Is(err, domain.ErrConflict):
		return CreateThreat409JSONResponse(errorBody("threat already exists", err.Error())), nil
	default:
		slog.ErrorContext(ctx, "failed to create threat", "error", err)
		return CreateThreat500JSONResponse(errorBody("internal server error", "")), nil
	}
}

// UpdateThreat handles PUT /info/{md5} as a full replacement.
func (h *ThreatHandler) UpdateThreat(ctx context.Context, request UpdateThreatRequestObject) (UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return UpdateThreat400JSONResponse(errorBody("invalid request body", "body is required")), nil
	}

	md5, err := domain.NormalizeMD5(request.Md5)
	if err != nil {
		return UpdateThreat400JSONResponse(errorBody("invalid md5", err.Error())), nil
	}

	in, err := fromUpdateRequest(*request.Body)
	if err != nil {
		return UpdateThreat400JSONResponse(errorBody("invalid request", err.Error())), nil
	}

	threat, err := h.service.Update(ctx, md5, in)
	switch {
	case err == nil:
		return UpdateThreat200JSONResponse(toThreatResponse(threat)), nil
	case errors.Is(err, domain.ErrValidation):
		return UpdateThreat400JSONResponse(errorBody("invalid request", err.Error())), nil
	case errors.Is(err, domain.ErrNotFound):
		return UpdateThreat404JSONResponse(errorBody("threat not found", err.Error())), nil
	default:
		slog.ErrorContext(ctx, "failed to update threat", "md5", request.Md5, "error", err)
		return UpdateThreat500JSONResponse(errorBody("internal server error", "")), nil
	}
}

// fromCreateRequest converts an OpenAPI create request into a domain input.
func fromCreateRequest(r ThreatCreateRequest) (domain.CreateThreatInput, error) {
	md5, err := domain.NormalizeMD5(r.Md5)
	if err != nil {
		return domain.CreateThreatInput{}, err
	}

	in := domain.CreateThreatInput{
		MD5:         md5,
		Name:        r.Name,
		Description: r.Description,
		Family:      r.Family,
		Source:      r.Source,
		Confidence:  r.Confidence,
		FileSize:    r.FileSize,
		FileType:    r.FileType,
		FirstSeenAt: r.FirstSeenAt,
		LastSeenAt:  r.LastSeenAt,
	}
	if r.Severity != nil {
		v := domain.Severity(*r.Severity)
		in.Severity = &v
	}
	if r.Type != nil {
		v := domain.ThreatType(*r.Type)
		in.Type = &v
	}
	if r.Status != nil {
		v := domain.ThreatStatus(*r.Status)
		in.Status = &v
	}
	if r.Sha256 != nil {
		sha, err := domain.NormalizeSHA256(*r.Sha256)
		if err != nil {
			return domain.CreateThreatInput{}, err
		}
		in.SHA256 = &sha
	}
	if r.Tags != nil {
		in.Tags = *r.Tags
	}
	return in, nil
}

// fromUpdateRequest converts an OpenAPI update request into a domain input.
func fromUpdateRequest(r ThreatUpdateRequest) (domain.UpdateThreatInput, error) {
	in := domain.UpdateThreatInput{
		Name:        r.Name,
		Description: r.Description,
		Family:      r.Family,
		Source:      r.Source,
		Confidence:  r.Confidence,
		FileSize:    r.FileSize,
		FileType:    r.FileType,
		FirstSeenAt: r.FirstSeenAt,
		LastSeenAt:  r.LastSeenAt,
	}
	if r.Severity != nil {
		v := domain.Severity(*r.Severity)
		in.Severity = &v
	}
	if r.Type != nil {
		v := domain.ThreatType(*r.Type)
		in.Type = &v
	}
	if r.Status != nil {
		v := domain.ThreatStatus(*r.Status)
		in.Status = &v
	}
	if r.Sha256 != nil {
		sha, err := domain.NormalizeSHA256(*r.Sha256)
		if err != nil {
			return domain.UpdateThreatInput{}, err
		}
		in.SHA256 = &sha
	}
	if r.Tags != nil {
		in.Tags = *r.Tags
	}
	return in, nil
}

// toThreatResponse converts a domain threat into the API response model.
func toThreatResponse(t *domain.Threat) ThreatResponse {
	resp := ThreatResponse{
		Md5:         t.MD5,
		Name:        t.Name,
		Description: t.Description,
		Family:      t.Family,
		Source:      t.Source,
		Confidence:  t.Confidence,
		FileSize:    t.FileSize,
		FileType:    t.FileType,
		FirstSeenAt: t.FirstSeenAt,
		LastSeenAt:  t.LastSeenAt,
	}
	if t.Severity != nil {
		v := Severity(*t.Severity)
		resp.Severity = &v
	}
	if t.Type != nil {
		v := ThreatType(*t.Type)
		resp.Type = &v
	}
	if t.Status != nil {
		v := ThreatStatus(*t.Status)
		resp.Status = &v
	}
	if t.SHA256 != nil {
		v := *t.SHA256
		resp.Sha256 = &v
	}
	if len(t.Tags) > 0 {
		tags := append([]string(nil), t.Tags...)
		resp.Tags = &tags
	}

	createdAt := t.CreatedAt
	updatedAt := t.UpdatedAt
	if createdAt.IsZero() || updatedAt.IsZero() {
		slog.Warn("service returned threat with zero timestamps",
			"md5", t.MD5,
			"created_at_zero", createdAt.IsZero(),
			"updated_at_zero", updatedAt.IsZero(),
		)
		now := time.Now().UTC()
		if createdAt.IsZero() {
			createdAt = now
		}
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}
	}

	resp.CreatedAt = &createdAt
	resp.UpdatedAt = &updatedAt
	return resp
}

// errorBody builds an ErrorResponse, omitting empty details.
func errorBody(message, details string) ErrorResponse {
	body := ErrorResponse{Message: message}
	if details != "" {
		body.Details = &details
	}
	return body
}

// NewRouter builds the HTTP router with middleware, health checks and API routes.
func NewRouter(
	handler *ThreatHandler,
	health *HealthHandler,
	log *slog.Logger,
	rateLimitRPS float64,
	rateLimitBurst int,
	apiKey string,
) http.Handler {
	strict := NewStrictHandlerWithOptions(
		handler,
		nil,
		StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large", "")
					return
				}
				writeJSONError(w, http.StatusBadRequest, "invalid request body", err.Error())
			},
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				log.ErrorContext(r.Context(), "request failed", "error", err)
				writeJSONError(w, http.StatusInternalServerError, "internal server error", "")
			},
		},
	)

	r := chi.NewRouter()
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	recorder := metrics.NewRecorder(metrics.Config{
		Registry: registry,
	})

	mdlw := middleware.New(middleware.Config{
		Recorder: recorder,
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not found", r.URL.Path)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed", r.Method)
	})

	r.Use(func(next http.Handler) http.Handler {
		return middlewarestd.Handler("", mdlw, next)
	})
	r.Use(RequestID)
	r.Use(Logger(log))
	r.Use(Recovery(log))

	r.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	r.Get("/healthz", health.Healthz)
	r.Get("/readyz", health.Readyz)

	r.Group(func(r chi.Router) {
		r.Use(RateLimit(rateLimitRPS, rateLimitBurst))
		r.Use(APIKey(apiKey))
		r.Use(JSONBodyGuard)

		HandlerWithOptions(strict, ChiServerOptions{
			BaseRouter: r,
			ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSONError(w, http.StatusBadRequest, "invalid request", err.Error())
			},
		})
	})
	return r
}

// writeJSONError writes a JSON ErrorResponse with the given status code.
func writeJSONError(w http.ResponseWriter, status int, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody(message, details))
}
