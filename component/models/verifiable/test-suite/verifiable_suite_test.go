//go:build testsuite
// +build testsuite

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

This is not actually a test but rather a stand-alone generator application
that is used by VC Test Suite (https://github.com/w3c/vc-test-suite).
To run VC Test Suite, execute `make vc-test-suite`.
*/

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v3"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/log"
	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ld "github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

var logger = log.New("aries-framework/doc/verifiable/test-suite")
var loader jsonld.DocumentLoader //nolint:gochecknoglobals

// nolint:gochecknoglobals //required for go:embed
var (
	//go:embed contexts/credentials-examples_v1.jsonld
	credentialExamplesVocab []byte
	//go:embed contexts/odrl.jsonld
	odrlVocab []byte
)

func main() {
	inputFile := os.Args[len(os.Args)-1]

	vcBytes, readErr := ioutil.ReadFile(inputFile) // nolint:gosec
	if readErr != nil {
		abort("cannot open input file %s: %v", inputFile, readErr)
	}

	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		abort("create JSON-LD context store: %v", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		abort("create remote JSON-LD context provider store: %v", err)
	}

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err = ld.NewDocumentLoader(p,
		ld.WithExtraContexts(
			ldcontext.Document{
				URL:     "https://www.w3.org/2018/credentials/examples/v1",
				Content: credentialExamplesVocab,
			},
			ldcontext.Document{
				URL:     "https://www.w3.org/ns/odrl.jsonld",
				Content: odrlVocab,
			},
		),
	)
	if err != nil {
		abort("create document loader: %v", err)
	}

	jwt := flag.String("jwt", "", "base64encoded JSON object containing es256kPrivateKeyJwk and rs256PrivateKeyJwk.")
	jwtAud := flag.String("jwt-aud", "", "indication to use aud attribute in all JWTs")
	jwtNoJws := flag.Bool("jwt-no-jws", false, "indication to suppress the JWS although keys are present")
	jwtPresentation := flag.Bool("jwt-presentation", false, "indication to generate a verifiable presentation")
	jwtDecode := flag.Bool("jwt-decode", false, "indication to generate a credential from a JWT verifiable credential. The input file will be a JWT instead of a JSON-LD file.") // nolint: lll
	isPresentation := flag.Bool("presentation", false, "presentation is passed")
	flag.Parse()

	if *jwt == "" {
		if *isPresentation {
			encodeVPToJSON(vcBytes)
		} else {
			encodeVCToJSON(vcBytes, filepath.Base(inputFile))
		}

		return
	}

	privateKey, publicKey := parseRsaKeys(*jwt)

	if *jwtDecode {
		decodeVCJWTToJSON(vcBytes, publicKey)
		return
	}

	if *jwtNoJws {
		encodeVCToJWTUnsecured(vcBytes)
		return
	}

	if *jwtPresentation {
		encodeVPToJWS(vcBytes, *jwtAud, privateKey, publicKey)
	} else {
		encodeVCToJWS(vcBytes, privateKey)
	}
}

func encodeVCToJWS(vcBytes []byte, privateKey *rsa.PrivateKey) {
	credential, err := verifiable.ParseCredential(vcBytes, verifiable.WithNoProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		abort("verifiable credential encoding to JWS failed: %v", err)
	}

	jws, err := jwtClaims.MarshalJWS(verifiable.RS256, getRsaSigner(privateKey), "any")
	if err != nil {
		abort("failed to serialize JWS: %v", err)
	}

	fmt.Println(jws)
}

func encodeVPToJWS(vpBytes []byte, audience string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	vp, err := verifiable.ParsePresentation(vpBytes,
		// do not test the cryptographic proofs (see https://github.com/w3c/vc-test-suite/issues/101)
		verifiable.WithPresNoProofCheck(),
		// the public key is used to decode verifiable credentials passed as JWS to the presentation
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(publicKeyPemToBytes(publicKey), kms.RSARS256)),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		abort("failed to decode presentation: %v", err)
	}

	jwtClaims, err := vp.JWTClaims([]string{audience}, true)
	if err != nil {
		abort("failed to build JWT claims: %v", err)
	}

	jws, err := jwtClaims.MarshalJWS(verifiable.RS256, getRsaSigner(privateKey), "any")
	if err != nil {
		abort("failed to serialize JWS: %v", err)
	}

	fmt.Println(jws)
}

func encodeVCToJWTUnsecured(vcBytes []byte) {
	credential, err := verifiable.ParseCredential(vcBytes, verifiable.WithNoProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		abort("verifiable credential encoding to JWT failed: %v", err)
	}

	jwtUnsecured, err := jwtClaims.MarshalUnsecuredJWT()
	if err != nil {
		abort("failed to serialize unsecured JWT: %v", err)
	}

	fmt.Println(jwtUnsecured)
}

func decodeVCJWTToJSON(vcBytes []byte, publicKey *rsa.PublicKey) {
	// Asked to decode JWT
	credential, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(publicKeyPemToBytes(publicKey), kms.RSARS256)),
		// do not test the cryptographic proofs (see https://github.com/w3c/vc-test-suite/issues/101)
		verifiable.WithNoProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	credential.JWT = ""

	jsonBytes, err := credential.MarshalJSON()
	if err != nil {
		abort("failed to marshall verifiable credential to JSON: %v", err)
	}

	fmt.Println(string(jsonBytes))
}

func parseRsaKeys(packedKeys string) (private *rsa.PrivateKey, public *rsa.PublicKey) {
	// there are several JWKs which are based64
	decodedJwt, err := base64.StdEncoding.DecodeString(packedKeys)
	if err != nil {
		abort("cannot decode base64 of JSON containing JWT keys: %v", err)
	}

	// found the target JWK
	decodedJwtMap := make(map[string]interface{})

	err = json.Unmarshal(decodedJwt, &decodedJwtMap)
	if err != nil {
		abort("failed to decode JSON containing JWT keys: %v", err)
	}

	rs256PrivateKeyJwk, exist := decodedJwtMap["rs256PrivateKeyJwk"]
	if !exist {
		abort("cannot get rs256PrivateKeyJwk key")
	}

	// marshal found key back to bytes
	jwkBytes, err := json.Marshal(rs256PrivateKeyJwk)
	if err != nil {
		abort("JSON marshalling error: %v", err)
	}

	jwk := &jose.JSONWebKey{}

	err = jwk.UnmarshalJSON(jwkBytes)
	if err != nil {
		abort("JWK unmarshalling error: %v", err)
	}

	privateKey, ok := jwk.Key.(*rsa.PrivateKey)
	if !ok {
		abort("expected to get *rsa.PrivateKey, but got smth different")
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func encodeVCToJSON(vcBytes []byte, testFileName string) {
	vcOpts := []verifiable.CredentialOpt{
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithNoProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader),
	}

	// This are special test cases which should be made more precise in VC Test Suite.
	// See https://github.com/w3c/vc-test-suite/issues/96 for more information.
	if testFileName == "example-1-bad-cardinality.jsonld" || testFileName == "example-3-bad-cardinality.jsonld" {
		vcOpts = append(vcOpts, verifiable.WithBaseContextValidation())
	}

	credential, err := verifiable.ParseCredential(vcBytes, vcOpts...)
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	encoded, err := credential.MarshalJSON()
	if err != nil {
		abort("failed to encode credential: %v", err)
	}

	fmt.Println(string(encoded))
}

func encodeVPToJSON(vcBytes []byte) {
	// https://www.w3.org/TR/vc-data-model/#presentations-0 states "If present" under verifiableCredential
	// but the test suite requires the element to be present. Hence, WithPresRequireVC is used in test suite runs.
	vp, err := verifiable.ParsePresentation(vcBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		abort("failed to decode presentation: %v", err)
	}

	encoded, err := vp.MarshalJSON()
	if err != nil {
		abort("failed to encode presentation: %v", err)
	}

	fmt.Println(string(encoded))
}

func getRsaSigner(privKey *rsa.PrivateKey) *rsaSigner {
	return &rsaSigner{privateKey: privKey}
}

type rsaSigner struct {
	privateKey *rsa.PrivateKey
}

func (s *rsaSigner) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed)
}

func (s *rsaSigner) Alg() string {
	return "PS256"
}

func abort(msg string, args ...interface{}) {
	logger.Errorf(msg, args...)
	os.Exit(1)
}

func publicKeyPemToBytes(key *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(key)
}

type provider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}
