/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exchange

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// Invitation defines DID exchange invitation message
type Invitation struct {
	Type  string `json:"@type,omitempty"`
	ID    string `json:"@id,omitempty"`
	Label string `json:"label,omitempty"`
	DID   string `json:"did,omitempty"`
}

// GenerateInviteWithPublicDID generates the DID exchange invitation string with public DID
func GenerateInviteWithPublicDID(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.DID == "" {
		return "", errors.New("ID and DID are mandatory")
	}

	return encodedExchangeInvitation(invite)
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Wrapf(err, "JSON Marshal Error")
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}
