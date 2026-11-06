package api

import (
	"net/http"
	"strings"
)

const maxBodyBytes int64 = 1 << 20

func JSONBodyGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}

		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			writeJSONError(w, http.StatusUnsupportedMediaType,
				"unsupported media type", "expected application/json")
			return
		}

		if r.ContentLength > maxBodyBytes {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				"request body too large", "")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		next.ServeHTTP(w, r)
	})
}
