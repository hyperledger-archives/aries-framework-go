/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	defaultPath  = "/.well-known/doc.json"
	documentPath = "/doc.json"
)

// parseDIDWeb consumes a did:web identifier and returns the URL location of the did Doc.
func parseDIDWeb(id string) (string, string, error) {
	var address, host string

	parsedDID, err := did.Parse(id)
	if err != nil {
		return address, host, fmt.Errorf("invalid did, does not conform to generic did standard --> %w", err)
	}

	pathComponents := strings.Split(parsedDID.MethodSpecificID, ":")

	pathComponents[0], err = url.QueryUnescape(pathComponents[0])
	if err != nil {
		return address, host, fmt.Errorf("error parsing did:web did")
	}

	host = strings.Split(pathComponents[0], ":")[0]

	switch len(pathComponents) {
	case 1:
		address = "https://" + pathComponents[0] + defaultPath
	default:
		address = "https://" + strings.Join(pathComponents, "/") + documentPath
	}

	return address, host, nil
}
