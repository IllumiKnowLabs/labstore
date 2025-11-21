package middleware

import (
	"context"
	"net/http"

	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/iam"
)

const iamActionCtx ContextKey = "iamAction"

func WithIAM(action iam.Action, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), iamActionCtx, action)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetRequestAction(r *http.Request) string {
	if action := r.Context().Value(iamActionCtx); action != nil {
		return action.(string)
	}

	return ""
}

func IAMMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := GetRequestAction(r)
		if action == "" {
			next.ServeHTTP(w, r)
			return
		}

		bucket := r.PathValue("bucket")
		if bucket == "" {
			next.ServeHTTP(w, r)
			return
		}

		accessKey := GetRequestAccessKey(r)

		if !iam.CheckPolicy(accessKey, bucket, action) {
			// !FIXME: AWS compliant error handling?
			core.HandleError(w, core.ErrorAccessDenied())
			return
		}

		next.ServeHTTP(w, r)
	})
}
