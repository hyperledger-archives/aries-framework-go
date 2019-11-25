/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// Request defines a2a issue-credential request
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential
type Request struct {
	Type               string              `json:"@type,omitempty"`
	ID                 string              `json:"@id,omitempty"`
	Comment            string              `json:"comment,omitempty"`
	RequestAttach      []*model.Attachment `json:"requests~attach,omitempty"`
	CredDefID          string              `json:"cred_def_id,omitempty"`
	SchemaID           string              `json:"schema_id,omitempty"`
	CredentialProposal *CredentialPreview  `json:"credential_proposal,omitempty"`
	Thread             *decorator.Thread   `json:"~thread,omitempty"`
}

// Issue defines a2a issue-credential
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential
type Issue struct {
	Type              string              `json:"@type,omitempty"`
	ID                string              `json:"@id,omitempty"`
	Comment           string              `json:"comment,omitempty"`
	CredentialsAttach []*model.Attachment `json:"credentials~attach,omitempty"`
	Thread            *decorator.Thread   `json:"~thread,omitempty"`
}

// CredentialPreview defines a2a credential-preview for a issue-credential protocol
type CredentialPreview struct {
	Type       string        `json:"@type,omitempty"`
	Attributes []*Attributes `json:"attributes,omitempty"`
}

//Attributes defines the structure for the attachment
type Attributes struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value,omitempty"`
}
