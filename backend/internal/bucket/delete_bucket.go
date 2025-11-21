package bucket

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/IllumiKnowLabs/labstore/backend/internal/config"
	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
)

func DeleteBucket(bucket string) error {
	path := filepath.Join(config.Env.StorageRoot, bucket)

	err := os.RemoveAll(path)
	if err != nil {
		return core.ErrorNoSuchBucket()
	}

	return nil
}

// DeleteBucketHandler: DELETE /:bucket
func DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")

	if err := DeleteBucket(bucket); err != nil {
		core.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
