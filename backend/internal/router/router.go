package router

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/DataLabTechTV/labstore/backend/internal/bucket"
	"github.com/DataLabTechTV/labstore/backend/internal/config"
	"github.com/DataLabTechTV/labstore/backend/internal/middleware"
	"github.com/DataLabTechTV/labstore/backend/internal/object"
	"github.com/DataLabTechTV/labstore/backend/internal/service"
	"github.com/DataLabTechTV/labstore/backend/pkg/iam"
)

func Start() {
	ensureDirectories()

	router := http.NewServeMux()
	loadRoutes(router)

	addr := fmt.Sprintf("%s:%d", config.Env.Host, config.Env.Port)

	middleware := Middleware.Stack(
		middleware.CompressionMiddleware,
		middleware.AuthMiddleware,
		middleware.IAMMiddleware,
		middleware.NormalizeMiddleware,
	)

	slog.Info(
		"Starting S3-compatible object store server",
		"host", config.Env.Host,
		"port", config.Env.Port,
	)

	server := http.Server{
		Addr:    addr,
		Handler: middleware(router),
	}

	fmt.Printf("\n🌐 Backend listening on http://%s\n\n", addr)

	log.Fatal(server.ListenAndServe())
}

func ensureDirectories() {
	slog.Debug("Ensuring directories")
	os.MkdirAll(config.Env.StorageRoot, 0755)
}

func loadRoutes(router *http.ServeMux) {
	slog.Debug("Loading routes")

	// Service
	router.Handle("GET /", middleware.WithIAM(iam.ListAllMyBuckets, http.HandlerFunc(service.ListBucketsHandler)))

	// Bucket
	router.Handle("HEAD /{bucket}", middleware.WithIAM(iam.ListBucket, http.HandlerFunc(bucket.HeadBucketHandler)))
	router.Handle("GET /{bucket}", middleware.WithIAM(iam.ListBucket, http.HandlerFunc(bucket.ListObjectsHandler)))
	router.Handle("PUT /{bucket}", middleware.WithIAM(iam.CreateBucket, http.HandlerFunc(bucket.PutBucketHandler)))
	router.Handle("DELETE /{bucket}", middleware.WithIAM(iam.DeleteBucket, http.HandlerFunc(bucket.DeleteBucketHandler)))

	// Object
	router.Handle("HEAD /{bucket}/{key...}", middleware.WithIAM(iam.GetObject, http.HandlerFunc(object.HeadObjectHandler)))
	router.Handle("GET /{bucket}/{key...}", middleware.WithIAM(iam.GetObject, http.HandlerFunc(object.GetObjectHandler)))
	router.Handle("PUT /{bucket}/{key...}", middleware.WithIAM(iam.PutObject, http.HandlerFunc(object.PutObjectHandler)))
	router.Handle("DELETE /{bucket}/{key...}", middleware.WithIAM(iam.DeleteObject, http.HandlerFunc(object.DeleteObjectHandler)))
	router.Handle("POST /{bucket}", middleware.WithIAM(iam.DeleteBucket, http.HandlerFunc(object.DeleteObjectsHandler)))
}
