package object

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/DataLabTechTV/labstore/backend/internal/config"
	"github.com/DataLabTechTV/labstore/backend/internal/core"
)

type GetObjectResult struct {
	Content      io.ReadSeekCloser
	ObjectSize   int
	DateModified time.Time
}

func GetObject(bucket, key string) (*GetObjectResult, error) {
	objPath := filepath.Join(config.Env.StorageRoot, bucket, key)

	file, err := os.Open(objPath)
	if err != nil {
		return nil, ErrorNoSuchKey(key)
	}

	info, err := file.Stat()
	if err != nil {
		return nil, core.ErrorInternalError("Couldn't compute file size")
	}

	res := &GetObjectResult{
		Content:      file,
		ObjectSize:   int(info.Size()),
		DateModified: info.ModTime(),
	}

	return res, nil
}

// GetObjectHandler: GET /:bucket/:key
func GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")

	res, err := GetObject(bucket, key)
	if err != nil {
		core.HandleError(w, err)
		return
	}
	defer res.Content.Close()

	http.ServeContent(w, r, r.URL.Path, res.DateModified, res.Content)
}
