package thresholdwallet

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/perun-network/bbs-plus-threshold-wallet/wallet"
)

type ThresholdWalletCollection struct {
	Context []string `json:"@context,omitempty"`
	ID      string   `json:"id,omitempty"`
	Type    string   `json:"type,omitempty"`
	Name    string   `json:"name,omitempty"`
}

type ThresholdWalletMetaData struct {
	Context []string         `json:"@context,omitempty"`
	ID      string           `json:"id,omitempty"`
	Type    string           `json:"type,omitempty"`
	Subject *wallet.Document `json:"subject,omitempty"`
}

func newCollection(id, name string) *ThresholdWalletCollection {
	return &ThresholdWalletCollection{
		Context: []string{"https://w3id.org/wallet/v1"},
		ID:      id,
		Type:    "collection",
		Name:    name,
	}
}

func newCredential(document *wallet.Document) (*verifiable.Credential, error) {
	if document == nil {
		return nil, errors.New("nil pointer to document")
	}
	if document.Type != wallet.Credential {
		return nil, errors.New("incorrect type of document")
	}
	return &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		ID:      document.ID,
		Types:   []string{"ThresholdCredential"},
		Subject: document,
		Issuer: verifiable.Issuer{
			ID: document.Author,
		},
	}, nil
}

func newMetadata(document *wallet.Document) (*ThresholdWalletMetaData, error) {
	if document == nil {
		return nil, errors.New("nil pointer to document")
	}
	return &ThresholdWalletMetaData{
		Context: []string{"https://w3id.org/wallet/v1"},
		ID:      document.ID,
		Type:    string(document.Type),
		Subject: document,
	}, nil
}

func documentFromSubject(subject interface{}) (*wallet.Document, error) {
	subjectMap, ok := subject.(map[string]interface{})
	if !ok {
		return nil, errors.New("incorrect interface type: not a map[string]interface{}")
	}

	documentID, ok := subjectMap["id"].(string)
	if !ok {
		return nil, errors.New("missing id")
	}

	contentType, ok := subjectMap["type"].(string)
	if !ok {
		return nil, errors.New("missing content type")
	}

	content, ok := subjectMap["content"].(string)
	if !ok {
		return nil, errors.New("missing content")
	}

	collectionID, ok := subjectMap["collectionID"].(string)
	if !ok {
		return nil, errors.New("missing collectionID")
	}

	author, ok := subjectMap["author"].(string)
	if !ok {
		return nil, errors.New("missing author")
	}
	return &wallet.Document{
		ID:           documentID,
		Type:         wallet.ContentType(contentType),
		Content:      []byte(content),
		CollectionID: collectionID,
		Author:       author,
	}, nil
}
