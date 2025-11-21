package middleware

import (
	"log/slog"
	"net/http"
)

type Middleware func(http.Handler) http.Handler

func Stack(mw ...Middleware) Middleware {
	slog.Debug("Stacking middleware")

	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			next = mw[i](next)
		}

		return next
	}
}
