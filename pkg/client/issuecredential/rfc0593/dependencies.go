/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ServiceProvider is used to lookup the issuecredential service.
type ServiceProvider interface {
	Service(name string) (interface{}, error)
}

// IssueCredentialService defines the API required on the issue-credential protocol service implementation.
type IssueCredentialService interface {
	AddMiddleware(...issuecredential.Middleware)
}

// JSONLDDocumentLoaderProvider provides an ld.DocumentLoader.
//
// See also: context.Provider.
type JSONLDDocumentLoaderProvider interface {
	JSONLDDocumentLoader() ld.DocumentLoader
}

// TransientStorage provides transient storage.
type TransientStorage interface {
	ProtocolStateStorageProvider() storage.Provider
}

// Provider provides all dependencies.
//
// See also: context.Provider.
type Provider interface {
	JSONLDDocumentLoaderProvider
	TransientStorage
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
	VDRegistry() vdr.Registry
}

// Signer is used to create signer.SignatureSuite and attach LD proofs.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

// SignatureSuiteSpec specifies how to instantiate a signature suite and its proof.
type SignatureSuiteSpec struct {
	KeyType                 kms.KeyType
	KeyMultiCodec           uint64
	SignatureRepresentation verifiable.SignatureRepresentation
	Suite                   func(...suite.Opt) signer.SignatureSuite
	Signer                  func(Provider, interface{}) Signer
}

// DefaultSignatureSuiteSpecs are the signature suites supported by default.
// TODO make signaturesuite specs configurable.
var DefaultSignatureSuiteSpecs = map[string]SignatureSuiteSpec{ // nolint:gochecknoglobals
	ed25519signature2018.SignatureType: {
		KeyType:       kms.ED25519Type,
		KeyMultiCodec: fingerprint.ED25519PubKeyMultiCodec,
		Suite: func(opts ...suite.Opt) signer.SignatureSuite {
			return ed25519signature2018.New(opts...)
		},
		SignatureRepresentation: verifiable.SignatureJWS,
		Signer: func(p Provider, kh interface{}) Signer {
			return suite.NewCryptoSigner(p.Crypto(), kh)
		},
	},
	bbsblssignature2020.SignatureType: {
		KeyType:       kms.BLS12381G2Type,
		KeyMultiCodec: fingerprint.BLS12381g2PubKeyMultiCodec,
		Suite: func(opts ...suite.Opt) signer.SignatureSuite {
			return bbsblssignature2020.New(opts...)
		},
		SignatureRepresentation: verifiable.SignatureProofValue,
		Signer: func(p Provider, kh interface{}) Signer {
			return newBBSSigner(p.KMS(), p.Crypto(), kh)
		},
	},
}
