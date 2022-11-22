//go:build ACAPyInterop
// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/didcommutil"
)

const (
	doACAPyInterop = true
)

// Interop: convert a peer did doc to a "sov-like" did doc, to accommodate current behaviour in aca-py,
//
//	where sovrin dids are used as peer dids.
//
// TODO interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
func convertPeerToSov(doc *did.Doc) (*did.Doc, error) {
	if doc == nil {
		return doc, nil
	}

	didParts := strings.Split(doc.ID, ":")
	if len(didParts) != 3 {
		return nil, fmt.Errorf("peer did not in 3 parts")
	}

	if didParts[1] != "peer" {
		return doc, nil
	}

	id := base58.Encode(base58.Decode(didParts[2])[:16])

	newDID := fmt.Sprintf("did:sov:%s", id)

	docBytes, err := doc.MarshalJSON()
	if err != nil {
		return nil, err
	}

	docBytes = bytes.Replace(docBytes, []byte(doc.ID), []byte(newDID), -1)
	err = doc.UnmarshalJSON(docBytes)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func interopRecipientKey(doc *did.Doc) (string, error) {
	serviceType := didcommutil.GetServiceType(doc.Service[0].Type)

	if serviceType == "IndyAgent" {
		return recipientKey(doc)
	}

	return "", fmt.Errorf("recipientKeyAsDIDKey: invalid DID Doc service type: '%v'", doc.Service[0].Type)
}
