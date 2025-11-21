package object

import (
	"net/http"

	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
)

func ErrorNoSuchKey(key string) *core.S3Error {
	return &core.S3Error{
		Key:        key,
		Code:       "NoSuchKey",
		Message:    "Object not found",
		StatusCode: http.StatusNotFound,
	}
}
