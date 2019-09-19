/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import "github.com/hyperledger/aries-framework-go/pkg/common/metadata"

const (
	// Introduce protocol name
	Introduce = "introduce"
	// Spec defines the introduce spec
	Spec = metadata.AriesCommunityDID + ";spec/introduce/1.0/"
	// ConnectionProposal defines the introduce proposal message type.
	ConnectionProposal = Spec + "proposal"
	// ConnectionResponse defines the introduce response message type.
	ConnectionResponse = Spec + "response"
	// ConnectionInvitation defines the introduce invitation message type.
	ConnectionInvitation = Spec + "invitation"
	// ConnectionConfirm defines the introduce confirm message type.
	ConnectionConfirm = Spec + "confirm"
)
