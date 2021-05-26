/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// JSONLDContextController defines methods for the JSON-LD context controller.
type JSONLDContextController interface {
	// AddContext adds JSON-LD contexts to the underlying storage.
	AddContext(request *models.RequestEnvelope) *models.ResponseEnvelope
}
