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
	// NameSpace for vc store.
	NameSpace = "verifiable"

	credentialNameKey              = "vcname_"
	presentationNameKey            = "vpname_"
	credentialNameDataKeyPattern   = credentialNameKey + "%s"
	presentationNameDataKeyPattern = presentationNameKey + "%s"

	// limitPattern for the iterator.
	limitPattern = "%s" + storage.EndKeySuffix
)

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
	store storage.Store
}

type provider interface {
	StorageProvider() storage.Provider
}

// New returns a new vc store.
func New(ctx provider) (*StoreImplementation, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	return &StoreImplementation{store: store}, nil
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

	return s.store.Put(credentialNameDataKey(name), recordBytes)
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

	return s.store.Put(presentationNameDataKey(name), recordBytes)
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

	vp, err := verifiable.ParsePresentation(vpBytes, verifiable.WithPresDisabledProofCheck())
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

	var r Record

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

	var r Record

	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal record : %w", err)
	}

	return r.ID, nil
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (s *StoreImplementation) GetCredentials() ([]*Record, error) {
	return s.getAllRecords(credentialNameDataKey(""))
}

// GetPresentations retrieves the verifiable presenations records containing name and fields of interest.
func (s *StoreImplementation) GetPresentations() ([]*Record, error) {
	return s.getAllRecords(presentationNameDataKey(""))
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

	err = s.remove(id, credentialNameDataKey(name))
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

	err = s.remove(id, presentationNameDataKey(name))
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
	itr := s.store.Iterator(searchKey, fmt.Sprintf(limitPattern, searchKey))
	defer itr.Release()

	var records []*Record

	for itr.Next() {
		var r *Record

		err := json.Unmarshal(itr.Value(), &r)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record : %w", err)
		}

		records = append(records, r)
	}

	return records, nil
}

func getVCSubjectID(vc *verifiable.Credential) string {
	if subjectID, err := verifiable.SubjectID(vc.Subject); err == nil {
		return subjectID
	}

	return ""
}

func credentialNameDataKey(name string) string {
	return fmt.Sprintf(credentialNameDataKeyPattern, name)
}

func presentationNameDataKey(name string) string {
	return fmt.Sprintf(presentationNameDataKeyPattern, name)
}
