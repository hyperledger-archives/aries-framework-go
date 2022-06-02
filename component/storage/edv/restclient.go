/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("EDV-Provider")

const (
	contentTypeApplicationJSON = "application/json"
	locationHeaderName         = "Location"

	failResponseFromEDVServer = "status code %d was returned along with the following message: %s"
	failSendPOSTRequest       = "failed to send POST request: %w"
	failCreateRequest         = "failed to create request: %w"
)

// addHeaders function supports adding custom HTTP headers.
type addHeaders func(req *http.Request) (*http.Header, error)

type restClient struct {
	edvServerURL string
	httpClient   *http.Client
	headersFunc  addHeaders
}

func (c *restClient) createDocument(vaultID string, docBytes []byte) (string, error) {
	logger.Debugf(`Sending request to vault with ID "%s" to create the following document: %s`, docBytes)

	endpoint := fmt.Sprintf("%s/%s/documents", c.edvServerURL, vaultID)

	statusCode, hdr, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, docBytes, c.headersFunc)
	if err != nil {
		return "", fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusCreated {
		return hdr.Get(locationHeaderName), nil
	}

	return "", fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) updateDocument(vaultID, docID string, docBytes []byte) error {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	logger.Debugf(`Sending request to vault with ID "%s" to update a document with ID "%s". `+
		`Document contents: %s`, vaultID, docID, docBytes)

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, docBytes, c.headersFunc)
	if err != nil {
		return fmt.Errorf(failSendPOSTRequest, err)
	}

	// TODO (#2331): StatusNoContent added for now since Transmute's EDV implementation uses it
	if statusCode == http.StatusOK || statusCode == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) readDocument(vaultID, docID string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodGet, endpoint, nil, c.headersFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to send GET request: %w", err)
	}

	switch statusCode {
	case http.StatusOK:
		return respBytes, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("error: %w, status code %d was returned along with the following message: %s",
			spi.ErrDataNotFound, statusCode, respBytes)
	default:
		return nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
	}
}

// Queries the given vault and returns all documents that contain all the given tags. If a tag value is blank,
// then it acts as a wildcard, where any tag value for the associated tag name will match.
// If query.ReturnFullDocuments is false, then only the document locations will be returned via the first return value.
// If query.ReturnFullDocuments is true, then the full documents will be returned via the second return value.
func (c *restClient) query(vaultID string, edvQuery query) ([]string, []encryptedDocument, error) {
	jsonToSend, err := json.Marshal(edvQuery)
	if err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/query", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return nil, nil, fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusOK {
		if edvQuery.ReturnFullDocuments {
			var documents []encryptedDocument

			err = json.Unmarshal(respBytes, &documents)
			if err != nil {
				return nil, nil, err
			}

			return nil, documents, nil
		}

		var docURLs []string

		err = json.Unmarshal(respBytes, &docURLs)
		if err != nil {
			return nil, nil, err
		}

		return docURLs, nil, nil
	}

	return nil, nil, fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) batch(vaultID string, vaultOperations []vaultOperation) error {
	jsonToSend, err := json.Marshal(vaultOperations)
	if err != nil {
		return fmt.Errorf("failed to marshal vault operations: %w", err)
	}

	endpoint := fmt.Sprintf("%s/%s/batch", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.headersFunc)
	if err != nil {
		return fmt.Errorf(failSendPOSTRequest, err)
	}

	if statusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) deleteDocument(vaultID, docID string) error {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodDelete, endpoint, nil, c.headersFunc)
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK {
		return nil
	} else if statusCode == http.StatusNotFound {
		return fmt.Errorf("error: %w, status code %d was returned along with the following message: %s",
			spi.ErrDataNotFound, statusCode, respBytes)
	}

	return fmt.Errorf(failResponseFromEDVServer, statusCode, respBytes)
}

func (c *restClient) sendHTTPRequest(method, endpoint string, body []byte,
	addHeadersFunc addHeaders) (int, http.Header, []byte, error) {
	var req *http.Request

	var err error

	if len(body) == 0 {
		req, err = http.NewRequest(method, endpoint, nil)
		if err != nil {
			return -1, nil, nil, fmt.Errorf(failCreateRequest, err)
		}
	} else {
		req, err = http.NewRequest(method, endpoint, bytes.NewBuffer(body))
		if err != nil {
			return -1, nil, nil, fmt.Errorf(failCreateRequest, err)
		}
	}

	if addHeadersFunc != nil {
		httpHeaders, errAddHdr := addHeadersFunc(req)
		if errAddHdr != nil {
			return -1, nil, nil, fmt.Errorf("add optional request headers error: %w", errAddHdr)
		}

		if httpHeaders != nil {
			req.Header = httpHeaders.Clone()
		}
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", contentTypeApplicationJSON)
	}

	resp, err := c.httpClient.Do(req) //nolint: bodyclose
	if err != nil {
		return -1, nil, nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logger.Debugf(`Sent %s request to %s. Response status code: %d Response body: %s`, method, endpoint,
		resp.StatusCode, respBytes)

	return resp.StatusCode, resp.Header, respBytes, nil
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err)
	}
}
