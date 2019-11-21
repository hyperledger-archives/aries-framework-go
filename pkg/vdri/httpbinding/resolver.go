/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// resolveDID makes DID resolution via HTTP
func (v *VDRI) resolveDID(uri string) ([]byte, error) {
	resp, err := v.client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("HTTP Get request failed: %w", err)
	}

	defer closeResponseBody(resp.Body)

	if containsDIDDocument(resp) {
		var gotBody []byte

		gotBody, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body failed: %w", err)
		}

		return gotBody, nil
	} else if notExistentDID(resp) {
		return nil, fmt.Errorf("DID does not exist for request: %s", uri)
	}

	return nil, fmt.Errorf("unsupported response from DID resolver [%v] header [%s]",
		resp.StatusCode, resp.Header.Get("Content-type"))
}

// notExistentDID checks if requested DID is not found on remote DID resolver
func notExistentDID(resp *http.Response) bool {
	return resp.StatusCode == http.StatusNotFound
}

// containsDIDDocument checks weather reply from remote DID resolver contains DID document
func containsDIDDocument(resp *http.Response) bool {
	return resp.StatusCode == http.StatusOK && resp.Header.Get("Content-type") == "application/did+ld+json"
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

	return did.ParseDocument(data)
}
