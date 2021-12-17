/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const (
	didLDJson = "application/did+ld+json"
)

// resolveDID makes DID resolution via HTTP.
func (v *VDR) resolveDID(uri string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("HTTP create get request failed: %w", err)
	}

	req.Header.Add("Accept", didLDJson)

	if v.resolveAuthToken != "" {
		req.Header.Add("Authorization", v.resolveAuthToken)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP Get request failed: %w", err)
	}

	defer closeResponseBody(resp.Body)

	var gotBody []byte

	gotBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-type"), didLDJson) {
		return gotBody, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return nil, vdrapi.ErrNotFound
	}

	return nil, fmt.Errorf("unsupported response from DID resolver [%v] header [%s] body [%s]",
		resp.StatusCode, resp.Header.Get("Content-type"), gotBody)
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDR) Read(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	reqURL, err := url.ParseRequestURI(v.endpointURL)
	if err != nil {
		return nil, fmt.Errorf("url parse request uri failed: %w", err)
	}

	reqURL.Path = path.Join(reqURL.Path, didID)

	data, err := v.resolveDID(reqURL.String())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, vdrapi.ErrNotFound
	}

	documentResolution, err := did.ParseDocumentResolution(data)
	if err != nil {
		if !errors.Is(err, did.ErrDIDDocumentNotExist) {
			return nil, err
		}

		logger.Warnf("parse document resolution failed %w", err)
	} else {
		return documentResolution, nil
	}

	didDoc, err := did.ParseDocument(data)
	if err != nil {
		return nil, err
	}

	didDoc = interopPreprocess(didDoc)

	return &did.DocResolution{DIDDocument: didDoc}, nil
}
