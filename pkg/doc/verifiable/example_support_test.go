/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/bbs/bbs12381g2pub"
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

	addJSONLDCachedContextFromFile(loader,
		"https://w3c-ccg.github.io/ldp-bbs2020/context/v1",
		"bss2020.jsonld")
	addJSONLDCachedContextFromFile(loader,
		"https://w3id.org/citizenship/v1",
		"citizenship.jsonld")

	return loader
}

func addJSONLDCachedContextFromFile(loader *ld.CachingDocumentLoader, contextURL, contextFile string) {
	contextContent, err := ioutil.ReadFile(filepath.Clean(filepath.Join("testdata", "context", contextFile)))
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

type bbsSigner struct {
	privKeyBytes []byte
}

func newBBSSigner(privKey *bbs12381g2pub.PrivateKey) (*bbsSigner, error) { //nolint:interfacer
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privKeyBytes: privKeyBytes}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	msgs := s.textToLines(string(data))

	return bbs12381g2pub.New().Sign(msgs, s.privKeyBytes)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func loadBBSKeyPair(pubKeyB64, privKeyB64 string) (*bbs12381g2pub.PublicKey, *bbs12381g2pub.PrivateKey, error) {
	pubKeyBytes, err := base64.RawStdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := bbs12381g2pub.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := base64.RawStdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privKey, nil
}
