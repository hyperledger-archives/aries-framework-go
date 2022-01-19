/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

type rawPropose struct {
	IDV2      string                    `json:"@id,omitempty"`
	TypeV2    string                    `json:"@type,omitempty"`
	CommentV2 string                    `json:"comment,omitempty"`
	FormatsV2 []Format                  `json:"formats,omitempty"`
	AttachV2  []decorator.Attachment    `json:"proposals~attach,omitempty"`
	IDV3      string                    `json:"id,omitempty"`
	TypeV3    string                    `json:"type,omitempty"`
	BodyV3    ProposePresentationV3Body `json:"body,omitempty"`
	AttachV3  []decorator.AttachmentV2  `json:"attachments,omitempty"`
}

func (r *rawPropose) version() version { // nolint: gocyclo
	if r.IDV2 != "" ||
		r.TypeV2 != "" ||
		r.CommentV2 != "" ||
		len(r.FormatsV2) != 0 ||
		len(r.AttachV2) != 0 {
		return version2
	}

	if r.IDV3 != "" ||
		r.TypeV3 != "" ||
		len(r.AttachV3) != 0 ||
		r.BodyV3.GoalCode != "" ||
		r.BodyV3.Comment != "" {
		return version3
	}

	return version2
}

// ProposePresentationParams holds the parameters for proposing a presentation.
type ProposePresentationParams struct {
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string
	// Formats contains an entry for each proposal~attach array entry, including an optional value of the
	// attachment @id (if attachments are present) and the verifiable presentation format and version of the attachment.
	Formats  []Format
	GoalCode string
	// Attachments is an array of attachments that further define the presentation request being proposed.
	// This might be used to clarify which formats or format versions are wanted.
	Attachments []decorator.GenericAttachment
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *ProposePresentationParams) UnmarshalJSON(b []byte) error {
	raw := rawPropose{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *ProposePresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	raw := rawPropose{}

	err := msgMap.Decode(&raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

func (p *ProposePresentationParams) fromRaw(raw *rawPropose) {
	switch raw.version() {
	default:
		fallthrough
	case version2:
		p.Comment = raw.CommentV2
		p.Formats = raw.FormatsV2
		p.GoalCode = ""
		p.Attachments = decorator.V1AttachmentsToGeneric(raw.AttachV2)
	case version3:
		p.Comment = raw.BodyV3.Comment
		p.Formats = nil
		p.GoalCode = raw.BodyV3.GoalCode
		p.Attachments = decorator.V2AttachmentsToGeneric(raw.AttachV3)
	}
}

type rawRequest struct {
	IDV2          string                    `json:"@id,omitempty"`
	TypeV2        string                    `json:"@type,omitempty"`
	CommentV2     string                    `json:"comment,omitempty"`
	WillConfirmV2 bool                      `json:"will_confirm,omitempty"`
	FormatsV2     []Format                  `json:"formats,omitempty"`
	AttachV2      []decorator.Attachment    `json:"request_presentations~attach,omitempty"`
	IDV3          string                    `json:"id,omitempty"`
	TypeV3        string                    `json:"type,omitempty"`
	BodyV3        RequestPresentationV3Body `json:"body,omitempty"`
	AttachV3      []decorator.AttachmentV2  `json:"attachments,omitempty"`
}

func (r *rawRequest) version() version { // nolint: gocyclo
	if r.IDV2 != "" ||
		r.TypeV2 != "" ||
		r.CommentV2 != "" ||
		len(r.FormatsV2) != 0 ||
		len(r.AttachV2) != 0 {
		return version2
	}

	if r.IDV3 != "" ||
		r.TypeV3 != "" ||
		len(r.AttachV3) != 0 ||
		r.BodyV3.GoalCode != "" ||
		r.BodyV3.Comment != "" {
		return version3
	}

	return version2
}

// RequestPresentationParams holds the parameters for requesting a presentation.
type RequestPresentationParams struct {
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string
	// WillConfirm is a field that defaults to "false" to indicate that the verifier will or will not
	// send a post-presentation confirmation ack message.
	WillConfirm bool
	// Formats contains an entry for each request_presentations~attach array entry, providing the the value of the
	// attachment @id and the verifiable presentation request format and version of the attachment.
	Formats []Format
	// Attachments is an array of attachments containing the acceptable verifiable presentation requests.
	Attachments []decorator.GenericAttachment
	// GoalCode is an optional goal code to indicate the desired use of the requested presentation.
	GoalCode string
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *RequestPresentationParams) UnmarshalJSON(b []byte) error {
	raw := rawRequest{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *RequestPresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	raw := rawRequest{}

	err := msgMap.Decode(&raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

func (p *RequestPresentationParams) fromRaw(raw *rawRequest) {
	switch raw.version() {
	default:
		fallthrough
	case version2:
		p.Comment = raw.CommentV2
		p.WillConfirm = raw.WillConfirmV2
		p.Formats = raw.FormatsV2
		p.Attachments = decorator.V1AttachmentsToGeneric(raw.AttachV2)
		p.GoalCode = ""
	case version3:
		p.Comment = raw.BodyV3.Comment
		p.WillConfirm = raw.BodyV3.WillConfirm
		p.Formats = nil
		p.Attachments = decorator.V2AttachmentsToGeneric(raw.AttachV3)
		p.GoalCode = raw.BodyV3.GoalCode
	}
}

type rawPresentation struct {
	IDV2      string                   `json:"@id,omitempty"`
	TypeV2    string                   `json:"@type,omitempty"`
	CommentV2 string                   `json:"comment,omitempty"`
	FormatsV2 []Format                 `json:"formats,omitempty"`
	AttachV2  []decorator.Attachment   `json:"presentations~attach,omitempty"`
	TypeV3    string                   `json:"type,omitempty"`
	BodyV3    PresentationV3Body       `json:"body,omitempty"`
	AttachV3  []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

func (r *rawPresentation) version() version {
	if r.IDV2 != "" ||
		r.TypeV2 != "" ||
		r.CommentV2 != "" ||
		len(r.FormatsV2) != 0 ||
		len(r.AttachV2) != 0 {
		return version2
	}

	if r.TypeV3 != "" ||
		len(r.AttachV3) != 0 ||
		r.BodyV3.GoalCode != "" ||
		r.BodyV3.Comment != "" {
		return version3
	}

	return version2
}

// PresentationParams holds the parameters for providing a presentation.
type PresentationParams struct {
	// Comment is a field that provides some human readable information about the provided presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300].
	Comment string
	// Formats contains an entry for each presentations~attach array entry, providing the the value of the attachment
	// @id and the verifiable presentation format and version of the attachment.
	Formats []Format
	// Attachments is an array of attachments containing verifiable presentations.
	Attachments []decorator.GenericAttachment
	// GoalCode is an optional goal code to indicate the intended use of the provided presentation(s).
	GoalCode string
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PresentationParams) UnmarshalJSON(b []byte) error {
	raw := rawPresentation{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *PresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	raw := rawPresentation{}

	err := msgMap.Decode(&raw)
	if err != nil {
		return err
	}

	p.fromRaw(&raw)

	return nil
}

func (p *PresentationParams) fromRaw(raw *rawPresentation) {
	switch raw.version() {
	default:
		fallthrough
	case version2:
		p.Comment = raw.CommentV2
		p.Formats = raw.FormatsV2
		p.Attachments = decorator.V1AttachmentsToGeneric(raw.AttachV2)
		p.GoalCode = ""
	case version3:
		p.Comment = raw.BodyV3.Comment
		p.Formats = nil
		p.Attachments = decorator.V2AttachmentsToGeneric(raw.AttachV3)
		p.GoalCode = raw.BodyV3.GoalCode
	}
}
