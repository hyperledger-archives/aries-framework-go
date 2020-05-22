/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

type UniversityDegree struct {
	Type       string `json:"type,omitempty"`
	University string `json:"university,omitempty"`
}

type UniversityDegreeSubject struct {
	ID     string           `json:"id,omitempty"`
	Name   string           `json:"name,omitempty"`
	Spouse string           `json:"spouse,omitempty"`
	Degree UniversityDegree `json:"degree,omitempty"`
}

type UniversityDegreeCredential struct {
	*verifiable.Credential

	ReferenceNumber int `json:"referenceNumber,omitempty"`
}

func (udc *UniversityDegreeCredential) MarshalJSON() ([]byte, error) {
	// todo too complex! (https://github.com/hyperledger/aries-framework-go/issues/847)
	c := udc.Credential
	cp := *c

	cp.CustomFields = map[string]interface{}{
		"referenceNumber": udc.ReferenceNumber,
	}

	return json.Marshal(&cp)
}

func getEd25519Signer(privKey []byte) *ed25519Signer {
	return &ed25519Signer{privateKey: privKey}
}

type ed25519Signer struct {
	privateKey []byte
}

func (s *ed25519Signer) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func getECDSASecp256k1Signer(privKey *ecdsa.PrivateKey) *ecdsaSecp256k1Signer {
	return &ecdsaSecp256k1Signer{
		privKey: privKey,
	}
}

type ecdsaSecp256k1Signer struct {
	privKey *ecdsa.PrivateKey
}

func (es *ecdsaSecp256k1Signer) Sign(payload []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, es.privKey, hashed)
	if err != nil {
		panic(err)
	}

	curveBits := es.privKey.Curve.Params().BitSize

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

func getJSONLDDocumentLoader() *ld.CachingDocumentLoader {
	loader := verifiable.CachingJSONLDLoader()

	addJSONLDCachedContextFromFile(loader,
		"https://www.w3.org/2018/credentials/examples/v1", "vc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/examples-v1.jsonld", "trustbloc_example.jsonld")

	addJSONLDCachedContextFromFile(loader,
		"https://trustbloc.github.io/context/vc/credentials-v1.jsonld", "trustbloc_jwk2020_example.jsonld")

	addJSONLDCachedContextFromFile(loader, "https://www.w3.org/ns/odrl.jsonld", "odrl.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v1", "security_v1.jsonld")
	addJSONLDCachedContextFromFile(loader, "https://w3id.org/security/v2", "security_v2.jsonld")

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join(
		"testdata/context", contextFile)))
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
