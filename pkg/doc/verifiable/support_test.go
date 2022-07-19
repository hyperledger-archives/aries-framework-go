/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

//go:embed testdata/valid_credential.jsonld
var validCredential string //nolint:gochecknoglobals

//go:embed testdata/credential_without_issuancedate.jsonld
var credentialWithoutIssuanceDate string //nolint:gochecknoglobals

func (rc *rawCredential) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(rc)
	require.NoError(t, err)

	return string(bytes)
}

func (vc *Credential) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(vc)
	require.NoError(t, err)

	return string(bytes)
}

func (vc *Credential) byteJSON(t *testing.T) []byte {
	bytes, err := json.Marshal(vc)
	require.NoError(t, err)

	return bytes
}

func (rp *rawPresentation) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(rp)
	require.NoError(t, err)

	return string(bytes)
}

func (vp *Presentation) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(vp)
	require.NoError(t, err)

	return string(bytes)
}

func createVCWithLinkedDataProof(t *testing.T) (*Credential, PublicKeyFetcher) {
	t.Helper()

	vc, err := ParseCredential([]byte(validCredential),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())

	require.NoError(t, err)

	created := time.Now()

	signer, err := newCryptoSigner(kmsapi.ED25519Type)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#any",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	return vc, SingleKey(signer.PublicKeyBytes(), kmsapi.ED25519)
}

func createVCWithTwoLinkedDataProofs(t *testing.T) (*Credential, PublicKeyFetcher) {
	t.Helper()

	vc, err := ParseCredential([]byte(validCredential),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())

	require.NoError(t, err)

	created := time.Now()

	signer1, err := newCryptoSigner(kmsapi.ED25519Type)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer1)),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#key1",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	signer2, err := newCryptoSigner(kmsapi.ED25519Type)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(signer2)),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#key2",
	}, jsonldsig.WithDocumentLoader(createTestDocumentLoader(t)))

	require.NoError(t, err)

	return vc, func(issuerID, keyID string) (*verifier.PublicKey, error) {
		switch keyID {
		case "#key1":
			return &verifier.PublicKey{
				Type:  "Ed25519Signature2018",
				Value: signer1.PublicKeyBytes(),
			}, nil

		case "#key2":
			return &verifier.PublicKey{
				Type:  "Ed25519Signature2018",
				Value: signer2.PublicKeyBytes(),
			}, nil
		}

		panic("invalid keyID")
	}
}

func createKMS() (*localkms.LocalKMS, error) {
	p := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})

	return localkms.New("local-lock://custom/master/key/", p)
}

func newCryptoSigner(keyType kmsapi.KeyType) (signature.Signer, error) {
	localKMS, err := createKMS()
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return signature.NewCryptoSigner(tinkCrypto, localKMS, keyType)
}

func createTestDocumentLoader(t *testing.T, extraContexts ...ldcontext.Document) *ld.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader(extraContexts...)
	require.NoError(t, err)

	return loader
}

func parseTestCredential(t *testing.T, vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	t.Helper()

	return ParseCredential(vcData,
		append([]CredentialOpt{WithJSONLDDocumentLoader(createTestDocumentLoader(t))}, opts...)...)
}

func newTestPresentation(t *testing.T, vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	t.Helper()

	return ParsePresentation(vpData,
		append([]PresentationOpt{WithPresJSONLDDocumentLoader(createTestDocumentLoader(t))}, opts...)...)
}
