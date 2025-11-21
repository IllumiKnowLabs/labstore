package object

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/IllumiKnowLabs/labstore/backend/internal/config"
	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
)

func PutObject(bucket string, key string, data []byte) error {
	bucketPath := filepath.Join(config.Env.StorageRoot, bucket)
	if _, err := os.Stat(bucketPath); os.IsNotExist(err) {
		return core.ErrorNoSuchBucket()
	}

	objPath := filepath.Join(bucketPath, key)
	objDir := filepath.Dir(objPath)
	os.MkdirAll(objDir, 0755)

	f, err := os.Create(objPath)
	if err != nil {
		return core.ErrorInternalError("Failed to create object")
	}
	defer f.Close()

	_, err = io.Copy(f, bytes.NewReader(data))
	if err != nil {
		return core.ErrorInternalError("Failed to write object")
	}

	return nil
}

// PutObjectHandler: PUT /:bucket/:key
func PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")

	data, err := io.ReadAll(r.Body)
	if err != nil {
		core.HandleError(w, err)
		return
	}

	if err := PutObject(bucket, key, data); err != nil {
		core.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
