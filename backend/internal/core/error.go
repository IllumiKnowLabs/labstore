package core

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

func ErrorAccessDenied() *S3Error {
	return &S3Error{
		Code:       "AccessDenied",
		Message:    "AccessDenied",
		StatusCode: 403,
	}
}

func ErrorNotImplemented() *S3Error {
	return &S3Error{
		Code:       "NotImplemented",
		Message:    "Operation not implemented",
		StatusCode: http.StatusNotImplemented,
	}
}

func ErrorInternalError(message string) *S3Error {
	return &S3Error{
		Code:       "InternalError",
		Message:    message,
		StatusCode: http.StatusInternalServerError,
	}
}

func ErrorNoSuchBucket() *S3Error {
	return &S3Error{
		Code:       "NoSuckBucket",
		Message:    "Bucket does not exist",
		StatusCode: http.StatusNotFound,
	}
}

func ErrorSignatureDoesNotMatch() *S3Error {
	return &S3Error{
		Code:       "SignatureDoesNotMatch",
		Message:    "The request signature we calculate does not match the signature you provided.",
		StatusCode: http.StatusForbidden,
	}
}

type S3Error struct {
	XMLName    xml.Name `xml:"Error"`
	Key        string
	Code       string
	Message    string
	VersionId  string
	RequestId  string `xml:"-"`
	HostId     string `xml:"-"`
	StatusCode int    `xml:"-"`
}

func (e *S3Error) Error() string {
	if e.Key == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}

	return fmt.Sprintf("%s: %s: %s", e.Code, e.Message, e.Key)
}

func (e *S3Error) WithRequestID(requestID string) *S3Error {
	e.RequestId = requestID
	return e
}

func (e *S3Error) WithHostID(hostID string) *S3Error {
	e.HostId = hostID
	return e
}

func HandleError(w http.ResponseWriter, err error) {

	var s3Error *S3Error

	if errors.As(err, &s3Error) {
		slog.Error("HTTP: S3 error", "error", s3Error)
		WriteXML(w, s3Error.StatusCode, s3Error)
	} else {
		slog.Error("HTTP: Internal Server Error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
