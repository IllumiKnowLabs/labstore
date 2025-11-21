package object

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/IllumiKnowLabs/labstore/backend/internal/config"
	"github.com/IllumiKnowLabs/labstore/backend/internal/core"
)

type DeleteObjectsRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Object  []core.ObjectIdentifier
	Quiet   bool
}

type DeleteResult struct {
	Deleted []DeletedObject
	Error   []core.S3Error
}

type DeletedObject struct {
	DeleteMarker          bool
	DeleteMarkerVersionId string
	Key                   string
	VersionId             string
}

func (req DeleteObjectsRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("XMLName", req.XMLName),
		slog.Int("Objects", len(req.Object)),
		slog.Bool("Quiet", req.Quiet),
	)
}

func DeleteObjects(bucket string, r *DeleteObjectsRequest) *DeleteResult {
	res := &DeleteResult{}
	bucketPath := filepath.Join(config.Env.StorageRoot, bucket)

	for _, obj := range r.Object {
		objPath := filepath.Join(bucketPath, obj.Key)

		err := os.RemoveAll(objPath)
		if err != nil {
			res.Error = append(res.Error, *ErrorNoSuchKey(obj.Key))
			continue
		}

		deleted := DeletedObject{
			DeleteMarker: false,
			Key:          obj.Key,
		}
		res.Deleted = append(res.Deleted, deleted)
	}

	return res
}

// DeleteObjectsHandler: POST /:bucket?delete=
func DeleteObjectsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if !q.Has("delete") {
		http.Error(w, "Only delete requests are supported", http.StatusBadRequest)
		return
	}

	bucket := r.PathValue("bucket")

	var req DeleteObjectsRequest
	err := core.ReadXML(w, r, &req)
	if err != nil {
		core.HandleError(w, err)
		return
	}

	slog.Debug("Processing DeleteObjects", "request", req)

	resp := DeleteObjects(bucket, &req)
	core.WriteXML(w, http.StatusOK, resp)
}
