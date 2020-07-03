/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-agent-mobile/wrappers/rest")

type httpClient interface {
	Do(r *http.Request) (*http.Response, error)
}

func makeHTTPRequest(httpClient httpClient, method, url, token string) (string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create a new http request for [%s]: %w", url, err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while making request to [%s]: %w", url, err)
	}

	defer func() {
		e := response.Body.Close()
		if e != nil {
			// TODO use `/pkg/common/log` package instead
			logger.Warnf("failed to close response body: %w", e)
		}
	}()

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body for [%s]: %w", url, err)
	}

	return string(b), nil
}
