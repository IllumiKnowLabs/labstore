package middleware

import (
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"

	"github.com/klauspost/compress/zstd"
)

func CompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body

		switch r.Header.Get("Content-Encoding") {
		case "gzip":
			slog.Debug("decompressing gzip request")

			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "invalid gzip", http.StatusBadRequest)
				return
			}
			defer gz.Close()

			reader = gz

		case "zstd":
			slog.Debug("decompressing zstd request")

			zr, err := zstd.NewReader(r.Body)
			if err != nil {
				http.Error(w, "invalid zstd", http.StatusBadRequest)
				return
			}
			defer zr.Close()

			reader = zr
		}

		r.Body = io.NopCloser(reader)
		next.ServeHTTP(w, r)
	})
}
