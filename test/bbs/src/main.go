// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

//nolint:gci
import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcutil/base58"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

func main() {
	js.Global().Set("signVCAsync", js.FuncOf(signVCJS))
	js.Global().Set("verifyVCAsync", js.FuncOf(verifyVCJS))
	js.Global().Set("deriveVCProofAsync", js.FuncOf(deriveVCProofJS))
	js.Global().Set("verifyProofVCAsync", js.FuncOf(verifyProofVCJS))

	select {}
}

func signVCJS(_ js.Value, args []js.Value) interface{} {
	privKeyObj, vcObj, verificationMethodObj, callback := args[0], args[1], args[2], args[3]

	go func(privKeyB64, vcJSON, verificationMethod string, callback js.Value) {
		vcSigned, err := signVC(privKeyB64, vcJSON, verificationMethod)
		if err != nil {
			callback.Invoke(err.Error(), js.Null())
		} else {
			callback.Invoke(js.Null(), string(vcSigned))
		}
	}(privKeyObj.String(), vcObj.String(), verificationMethodObj.String(), callback)

	return nil
}

func verifyVCJS(_ js.Value, args []js.Value) interface{} {
	pubKeyObj, vcObj, callback := args[0], args[1], args[2]

	go func(pubKeyB64, vcJSON string, callback js.Value) {
		err := verifyVC(pubKeyB64, vcJSON)
		if err != nil {
			callback.Invoke(err.Error())
		} else {
			callback.Invoke(js.Null())
		}
	}(pubKeyObj.String(), vcObj.String(), callback)

	return nil
}

func deriveVCProofJS(_ js.Value, args []js.Value) interface{} {
	pubKeyObj, vcObj, revealJSON, nonce, callback := args[0], args[1], args[2], args[3], args[4]

	go func(pubKeyB64, vcJSON, revealJSON, nonce string, callback js.Value) {
		vcSigned, err := deriveProofVC(pubKeyB64, vcJSON, revealJSON, nonce)
		if err != nil {
			callback.Invoke(err.Error(), js.Null())
		} else {
			callback.Invoke(js.Null(), string(vcSigned))
		}
	}(pubKeyObj.String(), vcObj.String(), revealJSON.String(), nonce.String(), callback)

	return nil
}

func verifyProofVCJS(_ js.Value, args []js.Value) interface{} {
	pubKeyObj, vcObj, callback := args[0], args[1], args[2]

	go func(pubKeyB64, vcJSON string, callback js.Value) {
		err := verifyProofVC(pubKeyB64, vcJSON)
		if err != nil {
			callback.Invoke(err.Error())
		} else {
			callback.Invoke(js.Null())
		}
	}(pubKeyObj.String(), vcObj.String(), callback)

	return nil
}

func signVC(privKeyB64, vcJSON, verificationMethod string) ([]byte, error) {
	privKeyBytes := base58.Decode(privKeyB64)

	privKey, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, errors.New("invalid private key")
	}

	signer, err := newBBSSigner(privKey)
	if err != nil {
		return nil, fmt.Errorf("create BBS signer: %w", err)
	}

	sigSuite := bbsblssignature2020.New(suite.WithSigner(signer))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      verificationMethod,
	}

	jsonldDocLoader, err := createJSONLDDocumentLoader()
	if err != nil {
		return nil, err
	}

	vc, err := verifiable.ParseCredential([]byte(vcJSON), verifiable.WithJSONLDDocumentLoader(jsonldDocLoader),
		verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonldsig.WithDocumentLoader(jsonldDocLoader))
	if err != nil {
		return nil, err
	}

	vcWithProof, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	return vcWithProof, nil
}

func verifyVC(pubKeyB64, vcJSON string) error {
	pubKeyBytes := base58.Decode(pubKeyB64)

	sigSuite := bbsblssignature2020.New(
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	documentLoader, err := createJSONLDDocumentLoader()
	if err != nil {
		return err
	}

	_, err = verifiable.ParseCredential([]byte(vcJSON),
		verifiable.WithJSONLDDocumentLoader(documentLoader),
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)

	return err
}

func verifyProofVC(pubKeyB64, vcJSON string) error {
	pubKeyBytes := base58.Decode(pubKeyB64)

	var vcDoc map[string]interface{}

	err := json.Unmarshal([]byte(vcJSON), &vcDoc)
	if err != nil {
		return fmt.Errorf("parse VC doc: %w", err)
	}

	proof, ok := vcDoc["proof"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected \"proof\" format: %w", err)
	}

	nonce, ok := proof["nonce"].(string)
	if !ok {
		return fmt.Errorf("unexpected \"nonce\" format: %w", err)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("nonce base64 format: %w", err)
	}

	sigSuite := bbsblssignatureproof2020.New(
		suite.WithCompactProof(),
		suite.WithVerifier(bbsblssignatureproof2020.NewG2PublicKeyVerifier(nonceBytes)))

	jsonldDocLoader, err := createJSONLDDocumentLoader()
	if err != nil {
		return err
	}

	_, err = verifiable.ParseCredential([]byte(vcJSON),
		verifiable.WithJSONLDDocumentLoader(jsonldDocLoader),
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)

	return err
}

func deriveProofVC(pubKeyB64, vcJSON, revealJSON, nonce string) ([]byte, error) {
	pubKeyBytes := base58.Decode(pubKeyB64)

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, err
	}

	jsonldLoader, err := createJSONLDDocumentLoader()
	if err != nil {
		return nil, err
	}

	vc, err := verifiable.ParseCredential([]byte(vcJSON), verifiable.WithJSONLDDocumentLoader(jsonldLoader),
		verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	var revealDoc map[string]interface{}

	err = json.Unmarshal([]byte(revealJSON), &revealDoc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal reveal doc: %w", err)
	}

	vcSD, err := vc.GenerateBBSSelectiveDisclosure(revealDoc, nonceBytes,
		verifiable.WithJSONLDDocumentLoader(jsonldLoader),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")))
	if err != nil {
		return nil, fmt.Errorf("create selective disclosure: %w", err)
	}

	vcSDBytes, err := json.Marshal(vcSD)
	if err != nil {
		return nil, err
	}

	return vcSDBytes, nil
}

// nolint:gochecknoglobals // embedded custom context
var (
	//go:embed contexts/citizenship_v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/credentials-examples_v1.jsonld
	credentialExamplesVocab []byte
	//go:embed contexts/odrl.jsonld
	odrlVocab []byte
)

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

func createJSONLDDocumentLoader() (jsonld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := ld.NewDocumentLoader(p,
		ld.WithExtraContexts(
			ldcontext.Document{
				URL:         "https://w3id.org/citizenship/v1",
				DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
				Content:     citizenshipVocab,
			},
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
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
