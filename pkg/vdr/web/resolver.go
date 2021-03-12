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

var logger = log.New("aries-framework/pkg/vdr/web")

// Read resolves a did:web did.
func (v *VDR) Read(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error) {
	// apply resolve opts
	docOpts := &vdrapi.ResolveOpts{
		HTTPClient: &http.Client{},
	}

	for _, opt := range opts {
		opt(docOpts)
	}

	address, _, err := parseDIDWeb(didID)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> could not parse did:web did --> %w", err)
	}

	resp, err := docOpts.HTTPClient.Get(address)
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
