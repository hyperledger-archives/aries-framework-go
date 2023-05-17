/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/models/did"
)

const (
	defaultPath  = "/.well-known/did.json"
	documentPath = "/did.json"
)

// parseDIDWeb consumes a did:web identifier and returns the URL location of the did Doc.
func parseDIDWeb(id string, useHTTP bool) (string, string, error) {
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

	protocol := "https://"
	if useHTTP {
		protocol = "http://"
	}

	switch len(pathComponents) {
	case 1:
		address = protocol + pathComponents[0] + defaultPath
	default:
		address = protocol + strings.Join(pathComponents, "/") + documentPath
	}

	return address, host, nil
}
