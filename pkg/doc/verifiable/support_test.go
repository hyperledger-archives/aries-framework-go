/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

const jsonldContextPrefix = "testdata/context"

//nolint:lll
const validCredential = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
	"https://trustbloc.github.io/context/vc/credentials-v1.jsonld",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University",
    "image": "data:image/png;base64,iVBOR"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "expirationDate": "2020-01-01T19:23:24Z",
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  },
  "evidence": [
    {
      "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
      "type": [
        "DocumentVerification"
      ],
      "verifier": "https://example.edu/issuers/14",
      "evidenceDocument": "DriversLicense",
      "subjectPresence": "Physical",
      "documentPresence": "Physical"
    },
    {
      "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192dxyzab",
      "type": [
        "SupportingActivity"
      ],
      "verifier": "https://example.edu/issuers/14",
      "evidenceDocument": "Fluid Dynamics Focus",
      "subjectPresence": "Digital",
      "documentPresence": "Digital"
    }
  ],
  "termsOfUse": [
    {
      "type": "IssuerPolicy",
      "id": "http://example.com/policies/credential/4",
      "profile": "http://example.com/profiles/credential",
      "prohibition": [
        {
          "assigner": "https://example.edu/issuers/14",
          "assignee": "AllVerifiers",
          "target": "http://example.edu/credentials/3732",
          "action": [
            "Archival"
          ]
        }
      ]
    }
  ],
  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

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

func createVCWithLinkedDataProof() (*Credential, PublicKeyFetcher) {
	vc, err := ParseUnverifiedCredential([]byte(validCredential))
	if err != nil {
		panic(err)
	}

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
	}, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader()))
	if err != nil {
		panic(err)
	}

	return vc, SingleKey(signer.PublicKeyBytes(), kmsapi.ED25519)
}

func createVCWithTwoLinkedDataProofs() (*Credential, PublicKeyFetcher) {
	vc, err := ParseUnverifiedCredential([]byte(validCredential))
	if err != nil {
		panic(err)
	}

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
	}, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader()))
	if err != nil {
		panic(err)
	}

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
	}, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader()))
	if err != nil {
		panic(err)
	}

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

//nolint:gochecknoglobals
var testDocumentLoader = createTestJSONLDDocumentLoader()

func createTestJSONLDDocumentLoader() *ld.CachingDocumentLoader {
	loader := CachingJSONLDLoader()

	addJSONLDCachedContextFromFile(loader,
		"https://www.w3.org/2018/credentials/examples/v1", "vc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/examples-v1.jsonld", "trustbloc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/credentials-v1.jsonld", "trustbloc_jwk2020_example.jsonld")

	addJSONLDCachedContextFromFile(loader, "https://www.w3.org/ns/odrl.jsonld", "odrl.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v1", "security_v1.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v2", "security_v2.jsonld")
	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/presentation-exchange-submission-v1.jsonld",
		"presentation_submission_v1.jsonld")

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join(
		jsonldContextPrefix, contextFile)))
	if err != nil {
		panic(err)
	}

	addJSONLDCachedContext(loader, contextURL, string(contextContent))
}

func addJSONLDCachedContext(loader *ld.CachingDocumentLoader, contextURL, contextContent string) {
	reader, err := ld.DocumentFromReader(strings.NewReader(contextContent))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(contextURL, reader)
}

func parseTestCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	return ParseCredential(vcData, append([]CredentialOpt{WithJSONLDDocumentLoader(testDocumentLoader)}, opts...)...)
}

func newTestPresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	return ParsePresentation(vpData,
		append([]PresentationOpt{WithPresJSONLDDocumentLoader(testDocumentLoader)}, opts...)...)
}
