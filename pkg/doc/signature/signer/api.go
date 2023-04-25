/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
)

// SignatureSuite encapsulates signature suite methods required for signing documents.
type SignatureSuite = signer.SignatureSuite

// DocumentSigner implements signing of JSONLD documents.
type DocumentSigner = signer.DocumentSigner

// Context holds signing options and private key.
type Context = signer.Context

// New returns new instance of document verifier.
func New(signatureSuites ...SignatureSuite) *DocumentSigner {
	return signer.New(signatureSuites...)
}
