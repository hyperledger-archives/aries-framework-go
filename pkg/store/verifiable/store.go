/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// NameSpace for vc store
	NameSpace = "verifiable"

	credentialNameKey              = "vcname_"
	presentationNameKey            = "vpname_"
	credentialNameDataKeyPattern   = credentialNameKey + "%s"
	presentationNameDataKeyPattern = presentationNameKey + "%s"

	// limitPattern for the iterator
	limitPattern = "%s" + storage.EndKeySuffix
)

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")

// Store provides interface for storing and managing verifiable credentials
type Store interface {
	SaveCredential(name string, vc *verifiable.Credential) error
	SavePresentation(name string, vp *verifiable.Presentation) error
	GetCredential(id string) (*verifiable.Credential, error)
	GetPresentation(id string) (*verifiable.Presentation, error)
	GetCredentialIDByName(name string) (string, error)
	GetPresentationIDByName(name string) (string, error)
	GetCredentials() ([]*Record, error)
	GetPresentations() ([]*Record, error)
}

type record struct {
	ID        string   `json:"id,omitempty"`
	Context   []string `json:"context,omitempty"`
	Type      []string `json:"type,omitempty"`
	SubjectID string   `json:"subjectId,omitempty"`
}

// StoreImplementation stores vc
type StoreImplementation struct {
	store storage.Store
}

type provider interface {
	StorageProvider() storage.Provider
}

// New returns a new vc store
func New(ctx provider) (*StoreImplementation, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	return &StoreImplementation{store: store}, nil
}

// SaveCredential saves a verifiable credential.
func (s *StoreImplementation) SaveCredential(name string, vc *verifiable.Credential) error {
	if name == "" {
		return errors.New("credential name is mandatory")
	}

	id, err := s.GetCredentialIDByName(name)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get credential id using name : %w", err)
	}

	if id != "" {
		return errors.New("credential name already exists")
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal vc: %w", err)
	}

	id = vc.ID
	if id == "" {
		// ID in VCs are not mandatory, use uuid to save in DB if id missing
		id = uuid.New().String()
	}

	if e := s.store.Put(id, vcBytes); e != nil {
		return fmt.Errorf("failed to put vc: %w", e)
	}

	recordBytes, err := getRecord(id, getVCSubjectID(vc), vc.Context, vc.Types)
	if err != nil {
		return fmt.Errorf("failed to prepare record: %w", err)
	}

	if err := s.store.Put(credentialNameDataKey(name), recordBytes); err != nil {
		return fmt.Errorf("store vc name to id map : %w", err)
	}

	return nil
}

// SavePresentation saves a verifiable presentation.
func (s *StoreImplementation) SavePresentation(name string, vp *verifiable.Presentation) error {
	if name == "" {
		return errors.New("presentation name is mandatory")
	}

	id, err := s.GetPresentationIDByName(name)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get presentation id using name : %w", err)
	}

	if id != "" {
		return errors.New("presentation name already exists")
	}

	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal vp: %w", err)
	}

	id = vp.ID
	if id == "" {
		// ID in VPs are not mandatory, use uuid to save in DB
		id = uuid.New().String()
	}

	recordBytes, err := getRecord(id, vp.Holder, vp.Context, vp.Type)
	if err != nil {
		return fmt.Errorf("failed to prepare record: %w", err)
	}

	if err := s.store.Put(id, vpBytes); err != nil {
		return fmt.Errorf("failed to put vp: %w", err)
	}

	if err := s.store.Put(presentationNameDataKey(name), recordBytes); err != nil {
		return fmt.Errorf("store vp name to id map : %w", err)
	}

	return nil
}

// GetCredential retrieves a verifiable credential based on ID.
func (s *StoreImplementation) GetCredential(id string) (*verifiable.Credential, error) {
	vcBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}

	vc, err := verifiable.ParseUnverifiedCredential(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("new credential failed: %w", err)
	}

	return vc, nil
}

// GetPresentation retrieves a verifiable presentation based on ID.
func (s *StoreImplementation) GetPresentation(id string) (*verifiable.Presentation, error) {
	vpBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}

	vp, err := verifiable.ParsePresentation(vpBytes, verifiable.WithDisabledPresentationProofCheck())
	if err != nil {
		return nil, fmt.Errorf("new presentation failed: %w", err)
	}

	return vp, nil
}

// GetCredentialIDByName retrieves verifiable credential id based on name.
func (s *StoreImplementation) GetCredentialIDByName(name string) (string, error) {
	recordBytes, err := s.store.Get(credentialNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch credential id based on name : %w", err)
	}

	var r record

	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal record : %w", err)
	}

	return r.ID, nil
}

// GetPresentationIDByName retrieves verifiable presentation id based on name.
func (s *StoreImplementation) GetPresentationIDByName(name string) (string, error) {
	recordBytes, err := s.store.Get(presentationNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch presentation id based on name : %w", err)
	}

	var r record

	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal record : %w", err)
	}

	return r.ID, nil
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (s *StoreImplementation) GetCredentials() ([]*Record, error) {
	return s.getAllRecords(credentialNameDataKey(""), getCredentialName)
}

// GetPresentations retrieves the verifiable presenations records containing name and fields of interest.
func (s *StoreImplementation) GetPresentations() ([]*Record, error) {
	return s.getAllRecords(presentationNameDataKey(""), getPresentationName)
}

func (s *StoreImplementation) getAllRecords(searchKey string, keyPrefix func(string) string) ([]*Record, error) {
	itr := s.store.Iterator(searchKey, fmt.Sprintf(limitPattern, searchKey))
	defer itr.Release()

	var records []*Record

	for itr.Next() {
		var r record

		err := json.Unmarshal(itr.Value(), &r)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record : %w", err)
		}

		record := &Record{
			Name:      keyPrefix(string(itr.Key())),
			ID:        r.ID,
			Context:   r.Context,
			Type:      r.Type,
			SubjectID: r.SubjectID,
		}

		records = append(records, record)
	}

	return records, nil
}

func getVCSubjectID(vc *verifiable.Credential) string {
	if subjectID, err := verifiable.SubjectID(vc.Subject); err == nil {
		return subjectID
	}

	return ""
}

func getRecord(id, subjectID string, contexts, types []string) ([]byte, error) {
	recordBytes, err := json.Marshal(&record{id, contexts, types, subjectID})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vc record: %w", err)
	}

	return recordBytes, nil
}

func credentialNameDataKey(name string) string {
	return fmt.Sprintf(credentialNameDataKeyPattern, name)
}

func presentationNameDataKey(name string) string {
	return fmt.Sprintf(presentationNameDataKeyPattern, name)
}

func getCredentialName(dataKey string) string {
	return dataKey[len(credentialNameKey):]
}

func getPresentationName(dataKey string) string {
	return dataKey[len(presentationNameKey):]
}
