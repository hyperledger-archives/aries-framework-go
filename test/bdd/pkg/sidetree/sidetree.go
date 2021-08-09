/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidetree

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const docTemplate = `{
  "publicKey": [
   {
     "id": "%s",
     "type": "%s",
     "purposes": ["authentication"],
     "publicKeyJwk": %s
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
	sha2_256 = 18 // multihash

	defaultKeyType = "JwsVerificationKey2020"
)

type didResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument"`
	ResolverMetadata json.RawMessage `json:"resolverMetadata"`
	MethodMetadata   json.RawMessage `json:"methodMetadata"`
}

// CreateDIDParams defines parameters for CreateDID().
type CreateDIDParams struct {
	URL             string
	KeyID           string
	JWK             *jwk.JWK
	UpdateJWK       *jwk.JWK
	RecoveryJWK     *jwk.JWK
	KeyType         string
	ServiceEndpoint string
}

// CreateDID in sidetree.
func CreateDID(params *CreateDIDParams) (*diddoc.Doc, error) {
	opaqueDoc, err := getOpaqueDocument(params)
	if err != nil {
		return nil, err
	}

	req, err := getCreateRequest(opaqueDoc, params.UpdateJWK, params.RecoveryJWK)
	if err != nil {
		return nil, err
	}

	var result didResolution

	err = util.SendHTTP(http.MethodPost, params.URL, req, &result)
	if err != nil {
		return nil, err
	}

	doc, err := diddoc.ParseDocument(result.DIDDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public DID document: %w", err)
	}

	return doc, nil
}

func getOpaqueDocument(params *CreateDIDParams) ([]byte, error) {
	opsPubKey, err := getPubKey(params.JWK)
	if err != nil {
		return nil, err
	}

	keyBytes, err := params.JWK.PublicKeyBytes()
	if err != nil {
		return nil, err
	}

	didKey, _ := fingerprint.CreateDIDKey(keyBytes)

	keyType := params.KeyType
	if keyType == "" {
		keyType = defaultKeyType
	}

	data := fmt.Sprintf(docTemplate, params.KeyID, keyType, opsPubKey, params.ServiceEndpoint, didKey)

	doc, err := document.FromBytes([]byte(data))
	if err != nil {
		return nil, err
	}

	return doc.Bytes()
}

func getPubKey(j *jwk.JWK) (string, error) {
	publicKey, err := pubkey.GetPublicKeyJWK(j.Key)
	if err != nil {
		return "", err
	}

	opsPubKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return "", err
	}

	return string(opsPubKeyBytes), nil
}

func getCreateRequest(doc []byte, updateJWK, recoveryJWK *jwk.JWK) ([]byte, error) {
	pubKeyUpdate, err := pubkey.GetPublicKeyJWK(updateJWK.Key)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.GetCommitment(pubKeyUpdate, sha2_256)
	if err != nil {
		return nil, err
	}

	pubKeyRecovery, err := pubkey.GetPublicKeyJWK(recoveryJWK.Key)
	if err != nil {
		return nil, err
	}

	recoveryCommitment, err := commitment.GetCommitment(pubKeyRecovery, sha2_256)
	if err != nil {
		return nil, err
	}

	// for testing purposes we are going to use same commitment key for update and recovery
	return client.NewCreateRequest(&client.CreateRequestInfo{
		OpaqueDocument:     string(doc),
		UpdateCommitment:   updateCommitment,
		RecoveryCommitment: recoveryCommitment,
		MultihashCode:      sha2_256,
	})
}
