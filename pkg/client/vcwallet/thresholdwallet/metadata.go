package thresholdwallet

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

type ThresholdWalletCollection struct {
	Context []string `json:"@context,omitempty"`
	ID      string   `json:"id,omitempty"`
	Type    string   `json:"type,omitempty"`
	Name    string   `json:"name,omitempty"`
}

type ThresholdWalletMetaData struct {
	Context []string  `json:"@context,omitempty"`
	ID      string    `json:"id,omitempty"`
	Type    string    `json:"type,omitempty"`
	Subject *Document `json:"subject,omitempty"`
}

func newCollection(id, name string) *ThresholdWalletCollection {
	return &ThresholdWalletCollection{
		Context: []string{"https://w3id.org/wallet/v1"},
		ID:      id,
		Type:    "collection",
		Name:    name,
	}
}

func credentialFromDocument(document *Document) (*verifiable.Credential, error) {
	if document == nil {
		return nil, errors.New("nil pointer to document")
	}
	if document.Type != Credential {
		return nil, errors.New("incorrect type of document")
	}
	vc, err := verifiable.ParseCredential(document.Content,
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(),
	)
	if err != nil {
		return nil, err
	}
	return vc, nil
}

func documentFromCredential(vcByte []byte, collectionID string) (*Document, error) {
	vc, err := verifiable.ParseCredential(vcByte, verifiable.WithCredDisableValidation())
	if err != nil {
		return nil, err
	}
	return &Document{
		ID:           vc.ID,
		Type:         Credential,
		Content:      vcByte,
		CollectionID: collectionID,
	}, nil
}

func newMetadata(document *Document) (*ThresholdWalletMetaData, error) {
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
