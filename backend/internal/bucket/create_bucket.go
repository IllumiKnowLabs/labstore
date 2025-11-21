package bucket

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/IllumiKnowLabs/labstore/backend/internal/config"
	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
)

func ErrorBucketAlreadyExists() *core.S3Error {
	return &core.S3Error{
		Code:       "BucketAlreadyExists",
		Message:    "Could not create bucket, because it already exists",
		StatusCode: http.StatusConflict,
	}
}

func CreateBucket(bucket string) error {
	path := filepath.Join(config.Env.StorageRoot, bucket)

	if _, err := os.Stat(path); err == nil {
		return ErrorBucketAlreadyExists()
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("could not create bucket: %w", err)
	}

	return nil
}

// CreateBucket: PUT /:bucket
func PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")

	if err := CreateBucket(bucket); err != nil {
		core.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
