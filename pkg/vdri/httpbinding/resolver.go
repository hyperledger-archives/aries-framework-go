/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

const (
	didLDJson = "application/did+ld+json"
)

type didResolution struct {
	Context          interface{}            `json:"@context"`
	DIDDocument      map[string]interface{} `json:"didDocument"`
	ResolverMetadata map[string]interface{} `json:"resolverMetadata"`
	MethodMetadata   map[string]interface{} `json:"methodMetadata"`
}

// resolveDID makes DID resolution via HTTP
func (v *VDRI) resolveDID(uri string) ([]byte, error) {
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
		return nil, fmt.Errorf("DID does not exist for request: %s", uri)
	}

	return nil, fmt.Errorf("unsupported response from DID resolver [%v] header [%s] body [%s]",
		resp.StatusCode, resp.Header.Get("Content-type"), gotBody)
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDRI) Read(didID string, _ ...vdriapi.ResolveOpts) (*did.Doc, error) {
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
		return nil, vdriapi.ErrNotFound
	}

	var r didResolution
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal data return from http binding resolver %w", err)
	}

	didDocBytes := data
	// check if data is did resolution
	if len(r.DIDDocument) != 0 {
		var err error

		didDocBytes, err = json.Marshal(r.DIDDocument)
		if err != nil {
			return nil, fmt.Errorf("marshal data from did resolution did doc %w", err)
		}
	}

	return did.ParseDocument(didDocBytes)
}
