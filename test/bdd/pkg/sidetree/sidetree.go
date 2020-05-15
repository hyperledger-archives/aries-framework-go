/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidetree

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const docTemplate = `{
  "publicKey": [
   {
     "id": "%s",
     "type": "JwsVerificationKey2020",
     "usage": ["auth", "general","ops"],
     "jwk": %s
   }
  ],
  "service": [
	{
	   "id": "hub",
	   "type": "did-communication",
	   "serviceEndpoint": "%s",
       "recipientKeys" : [ "%s" ]
	}
  ]
}`

const (
	sha2_256            = 18
	recoveryRevealValue = "recoveryOTP"
	updateRevealValue   = "updateOTP"
)

type didResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument"`
	ResolverMetadata json.RawMessage `json:"resolverMetadata"`
	MethodMetadata   json.RawMessage `json:"methodMetadata"`
}

// CreateDID in sidetree
func CreateDID(url, keyID, ed25519PubKey, serviceEndpoint string) (*diddoc.Doc, error) {
	key, err := base64.RawURLEncoding.DecodeString(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	opaqueDoc, err := getOpaqueDocument(keyID, key, serviceEndpoint)
	if err != nil {
		return nil, err
	}

	req, err := getCreateRequest(opaqueDoc, key)
	if err != nil {
		return nil, err
	}

	var result didResolution

	err = sendHTTP(http.MethodPost, url, req, &result)
	if err != nil {
		return nil, err
	}

	doc, err := diddoc.ParseDocument(result.DIDDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public DID document: %s", err)
	}

	return doc, nil
}

func getOpaqueDocument(keyID string, key []byte, serviceEndpoint string) ([]byte, error) {
	opsPubKey, err := getPubKey(ed25519.PublicKey(key))
	if err != nil {
		return nil, err
	}

	data := fmt.Sprintf(docTemplate, keyID, opsPubKey, serviceEndpoint, base58.Encode(key))

	doc, err := document.FromBytes([]byte(data))
	if err != nil {
		return nil, err
	}

	return doc.Bytes()
}

func getPubKey(pubKey interface{}) (string, error) {
	publicKey, err := pubkey.GetPublicKeyJWK(pubKey)
	if err != nil {
		return "", err
	}

	opsPubKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return "", err
	}

	return string(opsPubKeyBytes), nil
}

func getCreateRequest(doc, key []byte) ([]byte, error) {
	recoveryPublicKey, err := pubkey.GetPublicKeyJWK(ed25519.PublicKey(key))
	if err != nil {
		return nil, err
	}

	return helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:          string(doc),
		RecoveryKey:             recoveryPublicKey,
		NextRecoveryRevealValue: []byte(recoveryRevealValue),
		NextUpdateRevealValue:   []byte(updateRevealValue),
		MultihashCode:           sha2_256,
	})
}

func sendHTTP(method, destination string, message []byte, result interface{}) error {
	// create request
	req, err := http.NewRequest(method, destination, bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http '%s' request for '%s', cause: %s", method, destination, err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	// send http request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get response from '%s', cause :%s", destination, err)
	}

	defer closeResponse(resp.Body)

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(data, result)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		fmt.Printf("Failed to close response body : %s\n", err)
	}
}
