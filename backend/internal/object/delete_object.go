package object

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/DataLabTechTV/labstore/backend/internal/config"
	"github.com/DataLabTechTV/labstore/backend/internal/core"
)

func DeleteObject(bucket, key string) error {
	objPath := filepath.Join(config.Env.StorageRoot, bucket, key)

	err := os.Remove(objPath)
	if err != nil {
		return ErrorNoSuchKey(key)
	}

	return nil
}

// DeleteObjectHandler: DELETE /:bucket/:key
func DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")

	if err := DeleteObject(bucket, key); err != nil {
		core.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
