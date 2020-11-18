// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcutil/base58"

	bbs "github.com/hyperledger/aries-framework-go/pkg/doc/bbs/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func main() {
	js.Global().Set("signVCAsync", js.FuncOf(signVCJS))
	js.Global().Set("verifyVCAsync", js.FuncOf(verifyVCJS))

	select {}
}

func signVCJS(_ js.Value, args []js.Value) interface{} {
	vcObj, privKeyObj, verificationMethodObj, callback := args[0], args[1], args[2], args[3]

	go func(privKeyB64, vcJSON, verificationMethod string, callback js.Value) {
		vcSigned, err := signVC(privKeyB64, vcJSON, verificationMethod)
		if err != nil {
			callback.Invoke(err.Error(), js.Null())
		} else {
			callback.Invoke(js.Null(), string(vcSigned))
		}
	}(vcObj.String(), privKeyObj.String(), verificationMethodObj.String(), callback)

	return nil
}

func verifyVCJS(_ js.Value, args []js.Value) interface{} {
	vcObj, pubKeyObj, callback := args[0], args[1], args[2]

	go func(pubKeyB64, vcJSON string, callback js.Value) {
		err := verifyVC(pubKeyB64, vcJSON)
		if err != nil {
			callback.Invoke(err.Error())
		} else {
			callback.Invoke(js.Null())
		}
	}(vcObj.String(), pubKeyObj.String(), callback)

	return nil
}

func signVC(privKeyB64, vcJSON, verificationMethod string) ([]byte, error) {
	privKeyBytes := base58.Decode(privKeyB64)

	privKey, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, errors.New("invalid private key")
	}

	bbsSigner, err := newBBSSigner(privKey)
	if err != nil {
		return nil, fmt.Errorf("create BBS signer: %w", err)
	}

	sigSuite := bbsblssignature2020.New(suite.WithSigner(bbsSigner))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      verificationMethod,
	}

	jsonldDocLoader := createLDPBBS2020DocumentLoader()

	vc, err := verifiable.ParseUnverifiedCredential([]byte(vcJSON), verifiable.WithJSONLDDocumentLoader(jsonldDocLoader))
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(jsonldDocLoader))
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

	jsonldDocLoader := createLDPBBS2020DocumentLoader()

	_, err := verifiable.ParseCredential([]byte(vcJSON),
		verifiable.WithJSONLDDocumentLoader(jsonldDocLoader),
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)

	return err
}
