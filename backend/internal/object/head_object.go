package object

import (
	"io"
	"net/http"
	"strconv"

	"github.com/DataLabTechTV/labstore/backend/internal/core"
	"github.com/DataLabTechTV/labstore/backend/internal/helper"
)

// HeadObjectHandler: Head /:bucket/:key
func HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")

	if !core.BucketExists(bucket) {
		core.HandleError(w, core.ErrorNoSuchBucket())
		return
	}

	path := core.BucketKeyPath(bucket, key)
	if helper.IsDir(path) {
		core.HandleError(w, ErrorNoSuchKey(key))
		return
	}

	res, err := GetObject(bucket, key)
	if err != nil {
		core.HandleError(w, err)
		return
	}
	defer res.Content.Close()

	buf := make([]byte, 512)

	n, err := res.Content.Read(buf)
	if err != nil {
		core.HandleError(w, err)
		return
	}
	res.Content.Seek(0, io.SeekStart)

	w.Header().Set("Content-Type", http.DetectContentType(buf[:n]))
	w.Header().Set("Content-Length", strconv.Itoa(res.ObjectSize))
	w.Header().Set("Last-Modified", res.DateModified.UTC().Format(http.TimeFormat))

	w.WriteHeader(http.StatusOK)
}
