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
	ProposePresentationV2
	ProposePresentationV3
}

func (r *rawPropose) isV3() bool {
	if r.ProposePresentationV2.notEmpty() {
		return false
	}

	if r.ProposePresentationV3.notEmpty() {
		return true
	}

	return false
}

func (p *ProposePresentationV2) notEmpty() bool {
	return p.ID != "" || p.Type != "" || p.Comment != "" || len(p.Formats) != 0 || len(p.ProposalsAttach) != 0
}

func (p *ProposePresentationV3) notEmpty() bool {
	return p.ID != "" || p.Type != "" || p.Body.Comment != "" || p.Body.GoalCode != "" || len(p.Attachments) != 0
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

	if raw.isV3() {
		p.FromV3(&raw.ProposePresentationV3)
	} else {
		p.FromV2(&raw.ProposePresentationV2)
	}

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *ProposePresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	isV2, _ := service.IsDIDCommV2(&msgMap) // nolint:errcheck
	if isV2 {
		msgV3 := &ProposePresentationV3{}

		err := msgMap.Decode(msgV3)
		if err != nil {
			return err
		}

		p.FromV3(msgV3)
	} else {
		msgV2 := &ProposePresentationV2{}

		err := msgMap.Decode(msgV2)
		if err != nil {
			return err
		}

		p.FromV2(msgV2)
	}

	return nil
}

// AsV2 translates this presentation proposal into a present-proof 2.0 proposal message.
func (p *ProposePresentationParams) AsV2() *ProposePresentationV2 {
	return &ProposePresentationV2{
		Type:            ProposePresentationMsgTypeV2,
		Comment:         p.Comment,
		Formats:         p.Formats,
		ProposalsAttach: decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this presentation proposal into a present-proof 3.0 proposal message.
func (p *ProposePresentationParams) AsV3() *ProposePresentationV3 {
	return &ProposePresentationV3{
		Type: ProposePresentationMsgTypeV3,
		Body: ProposePresentationV3Body{
			GoalCode: p.GoalCode,
			Comment:  p.Comment,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this presentation proposal from a present-proof 2.0 proposal message.
func (p *ProposePresentationParams) FromV2(v2 *ProposePresentationV2) {
	p.Comment = v2.Comment
	p.Formats = v2.Formats
	p.GoalCode = ""
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.ProposalsAttach)
}

// FromV3 initializes this presentation proposal from a present-proof 3.0 proposal message.
func (p *ProposePresentationParams) FromV3(v3 *ProposePresentationV3) {
	p.Comment = v3.Body.Comment
	p.Formats = nil
	p.GoalCode = v3.Body.GoalCode
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
}

type rawRequest struct {
	RequestPresentationV2
	RequestPresentationV3
}

func (r *RequestPresentationV2) notEmpty() bool {
	return r.ID != "" ||
		r.Type != "" ||
		r.Comment != "" ||
		len(r.Formats) != 0 ||
		len(r.RequestPresentationsAttach) != 0
}

func (r *RequestPresentationV3) notEmpty() bool {
	return r.ID != "" ||
		r.Type != "" ||
		len(r.Attachments) != 0 ||
		r.Body.GoalCode != "" ||
		r.Body.Comment != ""
}

func (r *rawRequest) isV3() bool {
	if r.RequestPresentationV2.notEmpty() {
		return false
	}

	if r.RequestPresentationV3.notEmpty() {
		return true
	}

	return false
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

	if raw.isV3() {
		p.FromV3(&raw.RequestPresentationV3)
	} else {
		p.FromV2(&raw.RequestPresentationV2)
	}

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *RequestPresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	isV2, _ := service.IsDIDCommV2(&msgMap) // nolint:errcheck
	if isV2 {
		msgV3 := &RequestPresentationV3{}

		err := msgMap.Decode(msgV3)
		if err != nil {
			return err
		}

		p.FromV3(msgV3)
	} else {
		msgV2 := &RequestPresentationV2{}

		err := msgMap.Decode(msgV2)
		if err != nil {
			return err
		}

		p.FromV2(msgV2)
	}

	return nil
}

// AsV2 translates this presentation request into a present-proof 2.0 request message.
func (p *RequestPresentationParams) AsV2() *RequestPresentationV2 {
	return &RequestPresentationV2{
		Type:                       RequestPresentationMsgTypeV2,
		Comment:                    p.Comment,
		WillConfirm:                p.WillConfirm,
		Formats:                    p.Formats,
		RequestPresentationsAttach: decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this presentation request into a present-proof 3.0 request message.
func (p *RequestPresentationParams) AsV3() *RequestPresentationV3 {
	return &RequestPresentationV3{
		Type: RequestPresentationMsgTypeV3,
		Body: RequestPresentationV3Body{
			GoalCode:    p.GoalCode,
			Comment:     p.Comment,
			WillConfirm: p.WillConfirm,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this presentation request from a present-proof 2.0 request message.
func (p *RequestPresentationParams) FromV2(v2 *RequestPresentationV2) {
	p.Comment = v2.Comment
	p.WillConfirm = v2.WillConfirm
	p.Formats = v2.Formats
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.RequestPresentationsAttach)
	p.GoalCode = ""
}

// FromV3 initializes this presentation request from a present-proof 3.0 request message.
func (p *RequestPresentationParams) FromV3(v3 *RequestPresentationV3) {
	p.Comment = v3.Body.Comment
	p.WillConfirm = v3.Body.WillConfirm
	p.Formats = nil
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
	p.GoalCode = v3.Body.GoalCode
}

type rawPresentation struct {
	PresentationV2
	PresentationV3
}

func (p *PresentationV2) notEmpty() bool {
	return p.ID != "" ||
		p.Type != "" ||
		p.Comment != "" ||
		len(p.Formats) != 0 ||
		len(p.PresentationsAttach) != 0
}

func (p *PresentationV3) notEmpty() bool {
	return p.Type != "" ||
		len(p.Attachments) != 0 ||
		p.Body.GoalCode != "" ||
		p.Body.Comment != ""
}

func (r *rawPresentation) isV3() bool {
	if r.PresentationV2.notEmpty() {
		return false
	}

	if r.PresentationV3.notEmpty() {
		return true
	}

	return false
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

	if raw.isV3() {
		p.FromV3(&raw.PresentationV3)
	} else {
		p.FromV2(&raw.PresentationV2)
	}

	return nil
}

// FromDIDCommMsgMap implements service.MsgMapDecoder.
func (p *PresentationParams) FromDIDCommMsgMap(msgMap service.DIDCommMsgMap) error {
	isV2, _ := service.IsDIDCommV2(&msgMap) // nolint:errcheck
	if isV2 {
		msgV3 := &PresentationV3{}

		err := msgMap.Decode(msgV3)
		if err != nil {
			return err
		}

		p.FromV3(msgV3)
	} else {
		msgV2 := &PresentationV2{}

		err := msgMap.Decode(msgV2)
		if err != nil {
			return err
		}

		p.FromV2(msgV2)
	}

	return nil
}

// AsV2 translates this presentation message into a present-proof 2.0 presentation message.
func (p *PresentationParams) AsV2() *PresentationV2 {
	return &PresentationV2{
		Type:                PresentationMsgTypeV2,
		Comment:             p.Comment,
		Formats:             p.Formats,
		PresentationsAttach: decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this presentation message into a present-proof 3.0 presentation message.
func (p *PresentationParams) AsV3() *PresentationV3 {
	return &PresentationV3{
		Type: PresentationMsgTypeV3,
		Body: PresentationV3Body{
			GoalCode: p.GoalCode,
			Comment:  p.Comment,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this presentation message from a present-proof 2.0 presentation message.
func (p *PresentationParams) FromV2(v2 *PresentationV2) {
	p.Comment = v2.Comment
	p.Formats = v2.Formats
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.PresentationsAttach)
	p.GoalCode = ""
}

// FromV3 initializes this presentation message from a present-proof 3.0 presentation message.
func (p *PresentationParams) FromV3(v3 *PresentationV3) {
	p.Comment = v3.Body.Comment
	p.Formats = nil
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
	p.GoalCode = v3.Body.GoalCode
}
