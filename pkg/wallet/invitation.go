/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	oobsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
)

// rawInvitation can unmarshal either a DIDComm V1 or V2 invitation.
type rawInvitation struct {
	IDv1       string                   `json:"@id"`
	TypeV1     string                   `json:"@type"`
	From       string                   `json:"from,omitempty"`
	Label      string                   `json:"label,omitempty"`
	GoalV1     string                   `json:"goal,omitempty"`
	GoalCodeV1 string                   `json:"goal_code,omitempty"`
	ServicesV1 []interface{}            `json:"services"`
	AcceptV1   []string                 `json:"accept,omitempty"`
	Protocols  []string                 `json:"handshake_protocols,omitempty"`
	RequestsV1 []decorator.Attachment   `json:"request~attach,omitempty"`
	IDv2       string                   `json:"id"`
	TypeV2     string                   `json:"type"`
	Body       oobv2.InvitationBody     `json:"body"`
	RequestsV2 []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// GenericInvitation holds either a DIDComm V1 or V2 invitation.
type GenericInvitation struct {
	ID        string                        `json:"id"`
	Type      string                        `json:"type"`
	From      string                        `json:"from,omitempty"`
	Label     string                        `json:"label,omitempty"`
	Goal      string                        `json:"goal,omitempty"`
	GoalCode  string                        `json:"goal-code,omitempty"`
	Services  []interface{}                 `json:"services"`
	Accept    []string                      `json:"accept,omitempty"`
	Protocols []string                      `json:"handshake_protocols,omitempty"`
	Requests  []decorator.GenericAttachment `json:"attachments,omitempty"`
	version   service.Version
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (gi *GenericInvitation) UnmarshalJSON(data []byte) error {
	raw := rawInvitation{}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	switch raw.version() {
	case service.V1:
		gi.ID = raw.IDv1
		gi.Type = raw.TypeV1
		gi.Label = raw.Label
		gi.Goal = raw.GoalV1
		gi.GoalCode = raw.GoalCodeV1
		gi.Services = raw.ServicesV1
		gi.Accept = raw.AcceptV1
		gi.Protocols = raw.Protocols
		gi.Requests = decorator.V1AttachmentsToGeneric(raw.RequestsV1)
		gi.version = service.V1
	case service.V2:
		gi.ID = raw.IDv2
		gi.Type = raw.TypeV2
		gi.From = raw.From
		gi.Label = raw.Label
		gi.Goal = raw.Body.Goal
		gi.GoalCode = raw.Body.GoalCode
		gi.Services = nil
		gi.Accept = raw.Body.Accept
		gi.Protocols = nil
		gi.Requests = decorator.V2AttachmentsToGeneric(raw.RequestsV2)
		gi.version = service.V2
	}

	return nil
}

// Version returns the DIDComm version of this OOB invitation.
func (gi *GenericInvitation) Version() service.Version {
	if gi.version == "" {
		return service.V1
	}

	return gi.version
}

// AsV1 returns this invitation as an OOB V1 invitation.
func (gi *GenericInvitation) AsV1() *oobsvc.Invitation {
	attachments := decorator.GenericAttachmentsToV1(gi.Requests)

	reqs := make([]*decorator.Attachment, len(attachments))

	for i := 0; i < len(attachments); i++ {
		reqs[i] = &attachments[i]
	}

	return &oobsvc.Invitation{
		ID:        gi.ID,
		Type:      gi.Type,
		Label:     gi.Label,
		Goal:      gi.Goal,
		GoalCode:  gi.GoalCode,
		Services:  gi.Services,
		Accept:    gi.Accept,
		Protocols: gi.Protocols,
		Requests:  reqs,
	}
}

// AsV2 returns this invitation as an OOB V2 invitation.
func (gi *GenericInvitation) AsV2() *oobv2.Invitation {
	attachments := decorator.GenericAttachmentsToV2(gi.Requests)

	reqs := make([]*decorator.AttachmentV2, len(attachments))

	for i := 0; i < len(attachments); i++ {
		reqs[i] = &attachments[i]
	}

	return &oobv2.Invitation{
		ID:    gi.ID,
		Type:  gi.Type,
		From:  gi.From,
		Label: gi.Label,
		Body: &oobv2.InvitationBody{
			Goal:     gi.Goal,
			GoalCode: gi.GoalCode,
			Accept:   gi.Accept,
		},
		Requests: reqs,
	}
}

func (r *rawInvitation) version() service.Version {
	if r.IDv1 != "" && r.TypeV1 != "" {
		return service.V1
	}

	if r.IDv2 != "" && r.TypeV2 != "" {
		return service.V2
	}

	return service.V1
}
