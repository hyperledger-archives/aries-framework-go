/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package presexch implements Presentation Exchange: https://identity.foundation/presentation-exchange.
package presexch

import (
	"github.com/hyperledger/aries-framework-go/component/models/presexch"
)

const (
	// PresentationSubmissionJSONLDContextIRI is the JSONLD context of presentation submissions.
	PresentationSubmissionJSONLDContextIRI = presexch.PresentationSubmissionJSONLDContextIRI
	// CredentialApplicationJSONLDContextIRI is the JSONLD context of credential application
	// which also contains presentation submission details.
	CredentialApplicationJSONLDContextIRI = presexch.CredentialApplicationJSONLDContextIRI
	// PresentationSubmissionJSONLDType is the JSONLD type of presentation submissions.
	PresentationSubmissionJSONLDType = presexch.PresentationSubmissionJSONLDType
	// CredentialApplicationJSONLDType is the JSONLD type of credential application.
	CredentialApplicationJSONLDType = presexch.CredentialApplicationJSONLDType
)

// ErrNoCredentials when any credentials do not satisfy requirements.
var ErrNoCredentials = presexch.ErrNoCredentials

// DefinitionJSONSchemaV1 is the JSONSchema definition for PresentationDefinition.
// nolint:lll
// https://github.com/decentralized-identity/presentation-exchange/blob/9a6abc6d2b0f08b6339c9116132fa94c4c834418/test/presentation-definition/schema.json
const DefinitionJSONSchemaV1 = presexch.DefinitionJSONSchemaV1

// DefinitionJSONSchemaV2 is the JSONSchema definition for PresentationDefinition.
// nolint:lll
const DefinitionJSONSchemaV2 = presexch.DefinitionJSONSchemaV2
