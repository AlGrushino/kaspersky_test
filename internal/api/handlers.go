package api

import (
	"context"
	"encoding/json"
	"errors"
	"kaspersky_test/internal/domain"
	"log/slog"
	"net/http"
)

type ThreatService interface {
	Create(ctx context.Context, req ThreatCreateRequest) (*ThreatResponse, error)
	Get(ctx context.Context, md5 string) (*ThreatResponse, error)
	Update(ctx context.Context, md5 string, req ThreatUpdateRequest) (*ThreatResponse, error)
}

type ThreatHandler struct {
	service ThreatService
}

func NewHandler(service ThreatService) *ThreatHandler {
	return &ThreatHandler{service: service}
}

var _ StrictServerInterface = (*ThreatHandler)(nil)

// GET /info/{md5}

func (h ThreatHandler) GetInfoByMd5(ctx context.Context, request GetInfoByMd5RequestObject) (GetInfoByMd5ResponseObject, error) {
	threat, err := h.service.Get(ctx, request.Md5)

	switch {
	case err == nil:
		return GetInfoByMd5200JSONResponse(*threat), nil

	case errors.Is(err, domain.ErrValidation):
		return GetInfoByMd5400JSONResponse(errorBody("invalid md5", err.Error())), nil

	case errors.Is(err, domain.ErrNotFound):
		return GetInfoByMd5404JSONResponse(errorBody("threat not found", err.Error())), nil

	default:
		slog.ErrorContext(ctx, "failed to get threat", "md5", request.Md5, "error", err)
		return GetInfoByMd5500JSONResponse(errorBody("internal server error", "")), nil
	}
}

// POST /info

func (h *ThreatHandler) CreateThreat(ctx context.Context, request CreateThreatRequestObject) (CreateThreatResponseObject, error) {
	if request.Body == nil {
		return CreateThreat400JSONResponse(errorBody("invalid request body", "body is required")), nil
	}

	threat, err := h.service.Create(ctx, *request.Body)

	switch {
	case err == nil:
		location := "/info/" + threat.Md5
		return CreateThreat201JSONResponse{
			Body: *threat,
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

// PUT /info/{md5}

func (h *ThreatHandler) UpdateThreat(ctx context.Context, request UpdateThreatRequestObject) (UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return UpdateThreat400JSONResponse(errorBody("invalid request body", "body is required")), nil
	}

	threat, err := h.service.Update(ctx, request.Md5, *request.Body)

	switch {
	case err == nil:
		return UpdateThreat200JSONResponse(*threat), nil
	case errors.Is(err, domain.ErrValidation):
		return UpdateThreat400JSONResponse(errorBody("invalid request", err.Error())), nil
	case errors.Is(err, domain.ErrNotFound):
		return UpdateThreat404JSONResponse(errorBody("threat not found", err.Error())), nil
	default:
		slog.ErrorContext(ctx, "failed to update threat", "md5", request.Md5, "error", err)
		return UpdateThreat500JSONResponse(errorBody("internal server error", "")), nil
	}
}

func errorBody(message, details string) ErrorResponse {
	body := ErrorResponse{Message: message}
	if details != "" {
		body.Details = &details
	}
	return body
}

func NewRouter(handler *ThreatHandler) http.Handler {
	strict := NewStrictHandlerWithOptions(
		handler,
		nil,
		StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSONError(w, http.StatusBadRequest, "invalid request body", err.Error())
			},
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				slog.ErrorContext(r.Context(), "request failed", "error", err)
				writeJSONError(w, http.StatusInternalServerError, "internal server error", "")
			},
		},
	)
	return Handler(strict)
}

func writeJSONError(w http.ResponseWriter, status int, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody(message, details))
}
