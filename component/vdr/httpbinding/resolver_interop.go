//go:build ACAPyInterop
// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"strings"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
)

// interopPreprocess in a ACAPyInterop build, this converts public sov did docs into a usable format.
func interopPreprocess(doc *diddoc.Doc) *diddoc.Doc {
	// skip non-sov docs
	if strings.HasPrefix(doc.ID, "did:") {
		if !strings.HasPrefix(doc.ID, "did:sov:") {
			return doc
		}
	}

	interopSovService(doc)

	return doc
}

func interopSovService(doc *diddoc.Doc) {
	s, found := diddoc.LookupService(doc, "endpoint")
	if !found {
		return
	}

	s.Type = "did-communication"

	if len(s.RecipientKeys) == 0 {
		for _, vm := range doc.VerificationMethod {
			didKey, _ := fingerprint.CreateDIDKey(vm.Value)

			s.RecipientKeys = append(s.RecipientKeys, didKey)
		}
	}
}
