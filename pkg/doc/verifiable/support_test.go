/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
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

	"github.com/stretchr/testify/require"
)

const certPrefix = "testdata/crypto"

//nolint:lll
const validCredential = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
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
