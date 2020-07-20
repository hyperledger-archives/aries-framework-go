/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-agent-mobile/wrappers/rest")

type httpClient interface {
	Do(r *http.Request) (*http.Response, error)
}

type restOperation struct {
	url   string
	token string

	httpClient httpClient
	endpoint   *endpoint
	request    *models.RequestEnvelope
}

func exec(operation *restOperation) *models.ResponseEnvelope {
	parsedURL, err := url.Parse(operation.url)
	if err != nil {
		return &models.ResponseEnvelope{
			Error: &models.CommandError{Message: fmt.Sprintf("failed to parse url [%s]: %v", operation.url, err)},
		}
	}

	parsedURL.Path = path.Join(parsedURL.Path, operation.endpoint.Path)

	parsedURL.Path, err = embedParams(parsedURL.Path, operation.request.Payload)
	if err != nil {
		return &models.ResponseEnvelope{
			Error: &models.CommandError{Message: fmt.Sprintf("failed to embed params in request path: %v", err)},
		}
	}

	resp, err := makeHTTPRequest(operation.httpClient, operation.endpoint.Method,
		parsedURL.String(), operation.token, operation.request.Payload)
	if err != nil {
		return &models.ResponseEnvelope{
			Error: &models.CommandError{
				Message: fmt.Sprintf("failed to make http request to [%s]: %v", parsedURL.String(), err),
			},
		}
	}

	return &models.ResponseEnvelope{Payload: resp}
}

func makeHTTPRequest(httpClient httpClient, method, agentURL, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, agentURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new http request for [%s]: %w", agentURL, err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while making request to [%s]: %w", agentURL, err)
	}

	defer func() {
		e := response.Body.Close()
		if e != nil {
			logger.Warnf("failed to close response body: %w", e)
		}
	}()

	return ioutil.ReadAll(response.Body)
}

func embedParams(reqPath string, body []byte) (newURL string, err error) {
	params := []string{"piid", "id", "name"}
	newURL = reqPath

	for _, param := range params {
		newURL, err = embedParam(newURL, param, body)
		if err != nil {
			return
		}
	}

	return newURL, nil
}

func embedParam(reqPath, paramKey string, body []byte) (string, error) {
	toReplace := fmt.Sprintf("{%s}", paramKey)

	if body == nil || !strings.Contains(reqPath, toReplace) {
		return reqPath, nil
	}

	model := make(map[string]interface{})
	if err := json.Unmarshal(body, &model); err != nil {
		return reqPath, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	val, ok := model[paramKey]
	if !ok {
		return reqPath, fmt.Errorf("no %s found in request path", paramKey)
	}

	newURL := strings.ReplaceAll(reqPath, toReplace, fmt.Sprintf("%s", val))

	return newURL, nil
}
