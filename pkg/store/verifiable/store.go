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
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable/internal"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// NameSpace for vc store.
const NameSpace = "verifiable"

var logger = log.New("aries-framework/store/verifiable")

// Opt represents option function.
type Opt func(o *options)

type options struct {
	MyDID    string
	TheirDID string
}

// WithMyDID allows specifying MyDID for credential or presentation that is being issued.
func WithMyDID(val string) Opt {
	return func(o *options) {
		o.MyDID = val
	}
}

// WithTheirDID allows specifying TheirDID for credential or presentation that is being issued.
func WithTheirDID(val string) Opt {
	return func(o *options) {
		o.TheirDID = val
	}
}

// Store provides interface for storing and managing verifiable credentials.
type Store interface {
	SaveCredential(name string, vc *verifiable.Credential, opts ...Opt) error
	SavePresentation(name string, vp *verifiable.Presentation, opts ...Opt) error
	GetCredential(id string) (*verifiable.Credential, error)
	GetPresentation(id string) (*verifiable.Presentation, error)
	GetCredentialIDByName(name string) (string, error)
	GetPresentationIDByName(name string) (string, error)
	GetCredentials() ([]*Record, error)
	GetPresentations() ([]*Record, error)
	RemoveCredentialByName(name string) error
	RemovePresentationByName(name string) error
}

// StoreImplementation stores vc.
type StoreImplementation struct {
	store          storage.Store
	documentLoader ld.DocumentLoader
}

type provider interface {
	StorageProvider() storage.Provider
	JSONLDDocumentLoader() ld.DocumentLoader
}

// New returns a new vc store.
func New(ctx provider) (*StoreImplementation, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	err = ctx.StorageProvider().SetStoreConfig(NameSpace,
		storage.StoreConfiguration{TagNames: []string{internal.CredentialNameKey, internal.PresentationNameKey}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &StoreImplementation{
		store:          store,
		documentLoader: ctx.JSONLDDocumentLoader(),
	}, nil
}

// SaveCredential saves a verifiable credential.
func (s *StoreImplementation) SaveCredential(name string, vc *verifiable.Credential, opts ...Opt) error {
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
		// ID in VCs are not mandatory, use uuid to save in DB if id missing.
		id = uuid.New().String()
	}

	if e := s.store.Put(id, vcBytes); e != nil {
		return fmt.Errorf("failed to put vc: %w", e)
	}

	o := &options{}

	for _, opt := range opts {
		opt(o)
	}

	recordBytes, err := json.Marshal(&Record{
		ID:        id,
		Name:      name,
		Context:   vc.Context,
		Type:      vc.Types,
		MyDID:     o.MyDID,
		TheirDID:  o.TheirDID,
		SubjectID: getVCSubjectID(vc),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	return s.store.Put(internal.CredentialNameDataKey(name), recordBytes, storage.Tag{Name: internal.CredentialNameKey})
}

// SavePresentation saves a verifiable presentation.
func (s *StoreImplementation) SavePresentation(name string, vp *verifiable.Presentation, opts ...Opt) error {
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
		// ID in VPs are not mandatory, use uuid to save in DB.
		id = uuid.New().String()
	}

	o := &options{}

	for _, opt := range opts {
		opt(o)
	}

	recordBytes, err := json.Marshal(&Record{
		ID:        id,
		Name:      name,
		Context:   vp.Context,
		Type:      vp.Type,
		MyDID:     o.MyDID,
		TheirDID:  o.TheirDID,
		SubjectID: vp.Holder,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	if err := s.store.Put(id, vpBytes); err != nil {
		return fmt.Errorf("failed to put vp: %w", err)
	}

	return s.store.Put(internal.PresentationNameDataKey(name), recordBytes,
		storage.Tag{Name: internal.PresentationNameKey})
}

// GetCredential retrieves a verifiable credential based on ID.
func (s *StoreImplementation) GetCredential(id string) (*verifiable.Credential, error) {
	vcBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}

	vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
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

	vp, err := verifiable.ParsePresentation(vpBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("new presentation failed: %w", err)
	}

	return vp, nil
}

// GetCredentialIDByName retrieves verifiable credential id based on name.
func (s *StoreImplementation) GetCredentialIDByName(name string) (string, error) {
	recordBytes, err := s.store.Get(internal.CredentialNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch credential id based on name : %w", err)
	}

	var r Record

	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal record : %w", err)
	}

	return r.ID, nil
}

// GetPresentationIDByName retrieves verifiable presentation id based on name.
func (s *StoreImplementation) GetPresentationIDByName(name string) (string, error) {
	recordBytes, err := s.store.Get(internal.PresentationNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch presentation id based on name : %w", err)
	}

	var r Record

	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal record : %w", err)
	}

	return r.ID, nil
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (s *StoreImplementation) GetCredentials() ([]*Record, error) {
	return s.getAllRecords(internal.CredentialNameDataKey(""))
}

// GetPresentations retrieves the verifiable presentations records containing name and fields of interest.
func (s *StoreImplementation) GetPresentations() ([]*Record, error) {
	return s.getAllRecords(internal.PresentationNameDataKey(""))
}

// RemoveCredentialByName removes the verifiable credential and its records containing given name.
func (s *StoreImplementation) RemoveCredentialByName(name string) error {
	if name == "" {
		return errors.New("credential name is mandatory")
	}

	id, err := s.GetCredentialIDByName(name)
	if err != nil {
		return fmt.Errorf("get credential id using name : %w", err)
	}

	err = s.remove(id, internal.CredentialNameDataKey(name))
	if err != nil {
		return fmt.Errorf("unable to delete credential : %w", err)
	}

	return nil
}

// RemovePresentationByName removes the verifiable presentation and its records containing given name.
func (s *StoreImplementation) RemovePresentationByName(name string) error {
	if name == "" {
		return errors.New("presentation name is mandatory")
	}

	id, err := s.GetPresentationIDByName(name)
	if err != nil {
		return fmt.Errorf("get presentation id using name : %w", err)
	}

	err = s.remove(id, internal.PresentationNameDataKey(name))
	if err != nil {
		return fmt.Errorf("unable to delete presentation : %w", err)
	}

	return nil
}

func (s *StoreImplementation) remove(id, recordKey string) error {
	err := s.store.Delete(id)
	if err != nil {
		return fmt.Errorf("unable to delete from store : %w", err)
	}

	err = s.store.Delete(recordKey)
	if err != nil {
		return fmt.Errorf("unable to delete record : %w", err)
	}

	return nil
}

func (s *StoreImplementation) getAllRecords(searchKey string) ([]*Record, error) {
	itr, err := s.store.Query(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close iterator: %s", errClose.Error())
		}
	}()

	var records []*Record

	more, err := itr.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next set of data from iterator")
	}

	for more {
		var r *Record

		value, err := itr.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		err = json.Unmarshal(value, &r)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record : %w", err)
		}

		records = append(records, r)

		more, err = itr.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next set of data from iterator")
		}
	}

	return records, nil
}

func getVCSubjectID(vc *verifiable.Credential) string {
	if subjectID, err := verifiable.SubjectID(vc.Subject); err == nil {
		return subjectID
	}

	return ""
}
