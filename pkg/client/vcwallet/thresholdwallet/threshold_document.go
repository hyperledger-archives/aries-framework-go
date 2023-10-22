package thresholdwallet

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ContentType is the document content type.
type ContentType string

const (
	Credential     ContentType = "credential"
	Precomputation ContentType = "precomputation"
	PublicKey      ContentType = "public_key"

	// ID templates
	CollectionIDTemplate string = "did:collection:%s"
	DocumentIDTemplate   string = "did:%s:%s"
)

type Document struct {
	ID           string      `json:"id"`           // Unique Identifier for the document.
	Type         ContentType `json:"type"`         // Type of the document.
	Content      []byte      `json:"content"`      // The content of the document.
	CollectionID string      `json:"collectionID"` // Identifier for linking documents.
	Indices      []int       `json:"indices,omitempty"`
	MsgIndex     int         `json:"msgIndex,omitempty"`
	Created      *time.Time
}

func NewDocument(
	contentType ContentType,
	content []byte,
	collectionID string) *Document {
	return &Document{
		ID:           fmt.Sprintf(DocumentIDTemplate, contentType, uuid.New().URN()),
		Type:         contentType,
		Content:      content,
		CollectionID: collectionID,
		Indices:      nil,
		MsgIndex:     -1,
	}
}
