/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdvdri "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
)

// VDRI contains necessary fields to support its operations.
type VDRI struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// ResolveDID resolve did.
func (v *VDRI) ResolveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdri.ResolveDIDCommandMethod)
}

// SaveDID saves the did doc to the store.
func (v *VDRI) SaveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdri.SaveDIDCommandMethod)
}

// GetDID retrieves the did from the store.
func (v *VDRI) GetDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdri.GetDIDCommandMethod)
}

// GetDIDRecords retrieves the did doc containing name and didID.
func (v *VDRI) GetDIDRecords(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdri.GetDIDsCommandMethod)
}

func (v *VDRI) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        v.URL,
		token:      v.Token,
		httpClient: v.httpClient,
		endpoint:   v.endpoints[endpoint],
		request:    request,
	})
}
