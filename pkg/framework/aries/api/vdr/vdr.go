/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID not found")

// DIDCommServiceType default DID Communication service endpoint type.
const DIDCommServiceType = "did-communication"

// JSONWebKey2020 key type for general encryption key as key agreement, see following discussion:
// https://github.com/w3c/did-core/issues/240#issuecomment-663230565.
const JSONWebKey2020 = "JsonWebKey2020"

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...ResolveOpts) (*did.Doc, error)
	Store(doc *did.Doc) error
	Create(method string, opts ...DocOpts) (*did.Doc, error)
	Close() error
}

// VDR verifiable data registry interface.
type VDR interface {
	Read(did string, opts ...ResolveOpts) (*did.Doc, error)
	Store(doc *did.Doc, by *[]ModifiedBy) error
	Build(pubKey *PubKey, opts ...DocOpts) (*did.Doc, error)
	Accept(method string) bool
	Close() error
}

// ResultType input option can be used to request a certain type of result.
type ResultType int

const (
	// DidDocumentResult Request a DID Document as output.
	DidDocumentResult ResultType = iota
	// ResolutionResult Request a DID Resolution Result.
	ResolutionResult
)

// ResolveDIDOpts holds the options for did resolve.
type ResolveDIDOpts struct {
	ResultType  ResultType
	VersionID   interface{}
	VersionTime string
	NoCache     bool
}

// ResolveOpts is a did resolve option.
type ResolveOpts func(opts *ResolveDIDOpts)

// WithResultType the result type input option can be used to request a certain type of result.
func WithResultType(resultType ResultType) ResolveOpts {
	return func(opts *ResolveDIDOpts) {
		opts.ResultType = resultType
	}
}

// WithVersionID the version id input option can be used to request a specific version of a DID Document.
func WithVersionID(versionID interface{}) ResolveOpts {
	return func(opts *ResolveDIDOpts) {
		opts.VersionID = versionID
	}
}

// WithVersionTime the version time input option can used to request a specific version of a DID Document.
func WithVersionTime(versionTime time.Time) ResolveOpts {
	return func(opts *ResolveDIDOpts) {
		opts.VersionTime = versionTime.Format(time.RFC3339)
	}
}

// WithNoCache the no-cache input option can be used to turn cache on or off.
func WithNoCache(noCache bool) ResolveOpts {
	return func(opts *ResolveDIDOpts) {
		opts.NoCache = noCache
	}
}

// CreateDIDOpts holds the options for creating DID.
type CreateDIDOpts struct {
	DefaultServiceType     string
	DefaultServiceEndpoint string
	Services               []did.Service
	KeyType                string
	RequestBuilder         func([]byte) (io.Reader, error)
	EncryptionKey          *PubKey
}

// DocOpts is a create DID option.
type DocOpts func(opts *CreateDIDOpts)

// WithDefaultServiceType service type of DID document to be created.
func WithDefaultServiceType(serviceType string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.DefaultServiceType = serviceType
	}
}

// WithDefaultServiceEndpoint service ...
func WithDefaultServiceEndpoint(endpoint string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.DefaultServiceEndpoint = endpoint
	}
}

// WithKeyType allows for setting key type.
func WithKeyType(keyType string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.KeyType = keyType
	}
}

// WithServices allows adding services.
func WithServices(services ...did.Service) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.Services = services
	}
}

// WithEncryptionKey allows for setting encryption key.
func WithEncryptionKey(encryptionKey *PubKey) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.EncryptionKey = encryptionKey
	}
}

// WithRequestBuilder allows to supply request builder
// which can be used to add headers to request stream to be sent to HTTP binding URL.
func WithRequestBuilder(builder func(payload []byte) (io.Reader, error)) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.RequestBuilder = builder
	}
}

// PubKey contains public key type and value.
type PubKey struct {
	ID    string
	Value []byte
	Type  string
}

// ModifiedBy key/signature used to update the DID Document.
type ModifiedBy struct {
	Key string `json:"key,omitempty"`
	Sig string `json:"sig,omitempty"`
}

// RetrieveEncryptionKey retrieves an encryption VerificationMethod in JWK format from key.
func RetrieveEncryptionKey(didKey string, key *PubKey) (*did.VerificationMethod, error) {
	jwk, err := toJWK(key)
	if err != nil {
		return nil, err
	}

	keyID := fmt.Sprintf("%s#%s", didKey, key.ID)

	publicKey, err := did.NewVerificationMethodFromJWK(keyID, key.Type, didKey, jwk)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func toJWK(key *PubKey) (*jose.JWK, error) {
	switch key.Type {
	case JSONWebKey2020:
		return jose.JWKFromPublicKey(key.Value)
	default:
		return nil, fmt.Errorf("not supported public agreement key type: %s", key.Type)
	}
}
