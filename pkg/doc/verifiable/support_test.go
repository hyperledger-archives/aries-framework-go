/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
)

const certPrefix = "testdata/crypto"

//nolint:lll
const validCredential = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
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

func readPublicKey(keyFilePath string) (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(filepath.Clean(keyFilePath))
	if err != nil {
		return nil, fmt.Errorf("read pem file: %s", keyFilePath)
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return nil, errors.New("failed to decode PEM file")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected type of public key")
	}

	return pubKey, nil
}

func readPrivateKey(keyFilePath string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(filepath.Clean(keyFilePath))
	if err != nil {
		return nil, fmt.Errorf("read pem file: %s", keyFilePath)
	}

	privPem, _ := pem.Decode(priv)
	if privPem == nil {
		return nil, errors.New("failed to decode PEM file")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return privKey, nil
}

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

func (raw *rawPresentation) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(raw)
	require.NoError(t, err)

	return string(bytes)
}

func (vp *Presentation) stringJSON(t *testing.T) string {
	bytes, err := json.Marshal(vp)
	require.NoError(t, err)

	return string(bytes)
}

func getEd25519TestSigner(privKey []byte) *ed25519TestSigner {
	return &ed25519TestSigner{privateKey: privKey}
}

type ed25519TestSigner struct {
	privateKey []byte
}

func (s *ed25519TestSigner) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func getEcdsaP256TestSigner(privKey *ecdsa.PrivateKey) *ecdsaTestSigner {
	return &ecdsaTestSigner{privateKey: privKey, hash: crypto.SHA256}
}

func getEcdsaSecp256k1RS256TestSigner(privKey *ecdsa.PrivateKey) *ecdsaTestSigner {
	return &ecdsaTestSigner{privateKey: privKey, hash: crypto.SHA256}
}

// TODO replace this signer by Crypto signer and get key from LocalKMS
type ecdsaTestSigner struct {
	privateKey *ecdsa.PrivateKey
	hash       crypto.Hash
}

func (es *ecdsaTestSigner) Sign(doc []byte) ([]byte, error) {
	return signEcdsa(doc, es.privateKey, es.hash)
}

func signEcdsa(doc []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()

	_, err := hasher.Write(doc)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		panic(err)
	}

	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func getRS256TestSigner(privKey *rsa.PrivateKey) *rs256TestSigner {
	return &rs256TestSigner{privKey: privKey}
}

type rs256TestSigner struct {
	privKey *rsa.PrivateKey
}

func (s rs256TestSigner) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, hashed)
}

func publicKeyPemToBytes(publicKey *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(publicKey)
}

func createVCWithLinkedDataProof() (*Credential, PublicKeyFetcher) {
	vc, err := NewUnverifiedCredential([]byte(validCredential))
	if err != nil {
		panic(err)
	}

	created := time.Now()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#any",
	})
	if err != nil {
		panic(err)
	}

	return vc, SingleKey(pubKey, kmsapi.ED25519)
}

func createVCWithTwoLinkedDataProofs() (*Credential, PublicKeyFetcher) {
	vc, err := NewUnverifiedCredential([]byte(validCredential))
	if err != nil {
		panic(err)
	}

	created := time.Now()

	pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey1))),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#key1",
	})
	if err != nil {
		panic(err)
	}

	pubKey2, privKey2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey2))),
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:123#key2",
	})
	if err != nil {
		panic(err)
	}

	return vc, func(issuerID, keyID string) (*verifier.PublicKey, error) {
		switch keyID {
		case "#key1":
			return &verifier.PublicKey{
				Type:  "Ed25519Signature2018",
				Value: pubKey1,
			}, nil

		case "#key2":
			return &verifier.PublicKey{
				Type:  "Ed25519Signature2018",
				Value: pubKey2,
			}, nil
		}

		panic("invalid keyID")
	}
}
