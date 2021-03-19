/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdvdr "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
)

// VDR contains necessary fields to support its operations.
type VDR struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// ResolveDID resolve did.
func (v *VDR) ResolveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdr.ResolveDIDCommandMethod)
}

// SaveDID saves the did doc to the store.
func (v *VDR) SaveDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdr.SaveDIDCommandMethod)
}

// CreateDID create the did doc.
func (v *VDR) CreateDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdr.CreateDIDCommandMethod)
}

// GetDID retrieves the did from the store.
func (v *VDR) GetDID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdr.GetDIDCommandMethod)
}

// GetDIDRecords retrieves the did doc containing name and didID.
func (v *VDR) GetDIDRecords(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return v.createRespEnvelope(request, cmdvdr.GetDIDsCommandMethod)
}

func (v *VDR) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        v.URL,
		token:      v.Token,
		httpClient: v.httpClient,
		endpoint:   v.endpoints[endpoint],
		request:    request,
	})
}
