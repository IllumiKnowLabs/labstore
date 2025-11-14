package core

import (
	"encoding/xml"
	"time"
)

const ISO8601 = "2006-01-02T15:04:05Z"

type BaseObject struct {
	Key          string
	ETag         string
	LastModified Timestamp
	Size         int64
}

type Object struct {
	BaseObject
	ChecksumAlgorithm []string
	ChecksumType      string
	Owner             *Owner
	RestoreStatus     RestoreStatus
	StorageClass      string
}

type ObjectIdentifier struct {
	BaseObject
	VersionId string
}

type Owner struct {
	ID          string
	DisplayName string // deprecated, but we'll support it
}

type RestoreStatus struct {
	IsRestoreInProgress bool
	RestoreExpiryDate   Timestamp
}

type Timestamp time.Time

func (t Timestamp) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	formatted := time.Time(t).Format(ISO8601)
	return e.EncodeElement(formatted, start)
}
