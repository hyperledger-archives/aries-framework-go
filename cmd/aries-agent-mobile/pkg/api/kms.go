/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// KMSController defines methods for the KMS controller.
type KMSController interface {

	// CreateKeySet create a new public/private encryption and signature key pairs set.
	CreateKeySet(request *models.RequestEnvelope) *models.ResponseEnvelope

	// ImportKey imports a key.
	ImportKey(request *models.RequestEnvelope) *models.ResponseEnvelope
}
