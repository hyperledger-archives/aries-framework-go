/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const (
	// HTTPClientOpt http client opt.
	HTTPClientOpt = "httpClient"
)

var logger = log.New("aries-framework/pkg/vdr/web")

// Read resolves a did:web did.
func (v *VDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	httpClient := &http.Client{}

	didOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(didOpts)
	}

	k, ok := didOpts.Values[HTTPClientOpt]
	if ok {
		httpClient, ok = k.(*http.Client)

		if !ok {
			return nil, fmt.Errorf("failed to cast http client opt to http client struct")
		}
	}

	address, _, err := parseDIDWeb(didID)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> could not parse did:web did --> %w", err)
	}

	resp, err := httpClient.Get(address)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> http request unsuccessful --> %w", err)
	}

	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http server returned status code [%d]", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error reading http response body: %s --> %w", body, err)
	}

	doc, err := did.ParseDocument(body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error parsing did doc --> %w", err)
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
