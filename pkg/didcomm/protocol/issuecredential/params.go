/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// ProposeCredentialParams holds parameters for a credential proposal message.
type ProposeCredentialParams struct {
	Type               string
	ID                 string
	Comment            string
	Attachments        []decorator.GenericAttachment
	CredentialProposal PreviewCredential
	Formats            []Format
	GoalCode           string
	CredentialPreview  interface{}
}

// AsV2 translates this credential proposal into an issue credential 2.0 proposal message.
func (p *ProposeCredentialParams) AsV2() *ProposeCredentialV2 {
	return &ProposeCredentialV2{
		Type:               p.Type,
		Comment:            p.Comment,
		CredentialProposal: p.CredentialProposal,
		Formats:            p.Formats,
		FiltersAttach:      decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this credential proposal into an issue credential 3.0 proposal message.
func (p *ProposeCredentialParams) AsV3() *ProposeCredentialV3 {
	return &ProposeCredentialV3{
		Type: p.Type,
		ID:   p.ID,
		Body: ProposeCredentialV3Body{
			GoalCode:          p.GoalCode,
			Comment:           p.Comment,
			CredentialPreview: p.CredentialPreview,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this credential proposal from an issue credential 2.0 proposal.
func (p *ProposeCredentialParams) FromV2(v2 *ProposeCredentialV2) {
	p.Type = v2.Type
	p.ID = ""
	p.Comment = v2.Comment
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.FiltersAttach)

	p.CredentialProposal = v2.CredentialProposal
	p.Formats = v2.Formats

	p.GoalCode = ""
	p.CredentialPreview = ""
}

// FromV3 initializes this credential proposal from an issue credential 3.0 proposal.
func (p *ProposeCredentialParams) FromV3(v3 *ProposeCredentialV3) {
	p.Type = v3.Type
	p.ID = v3.ID
	p.Comment = v3.Body.Comment
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)

	p.CredentialProposal = PreviewCredential{}
	p.Formats = nil

	p.GoalCode = v3.Body.GoalCode
	p.CredentialPreview = v3.Body.CredentialPreview
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *ProposeCredentialParams) UnmarshalJSON(b []byte) error {
	raw := rawPropose{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	if raw.isV3() {
		p.FromV3(&raw.ProposeCredentialV3)
	} else {
		p.FromV2(&raw.ProposeCredentialV2)
	}

	return nil
}

type rawPropose struct {
	ProposeCredentialV2
	ProposeCredentialV3
}

func (p *ProposeCredentialV2) notEmpty() bool {
	return p.Type != "" ||
		p.Comment != "" ||
		p.CredentialProposal.Type != "" ||
		len(p.CredentialProposal.Attributes) != 0 ||
		len(p.Formats) != 0 ||
		len(p.FiltersAttach) != 0
}

func (p *ProposeCredentialV3) notEmpty() bool {
	return p.ID != "" ||
		p.Type != "" ||
		p.Body.GoalCode != "" ||
		p.Body.Comment != "" ||
		p.Body.CredentialPreview != nil ||
		len(p.Attachments) != 0
}

func (r *rawPropose) isV3() bool {
	if r.ProposeCredentialV2.notEmpty() {
		return false
	}

	if r.ProposeCredentialV3.notEmpty() {
		return true
	}

	return false
}

// OfferCredentialParams holds parameters for a credential offer message.
type OfferCredentialParams struct {
	Type              string
	ID                string
	Comment           string
	Attachments       []decorator.GenericAttachment
	Formats           []Format
	GoalCode          string
	ReplacementID     string
	CredentialPreview interface{}
}

// AsV2 translates this credential offer into an issue credential 2.0 offer message.
func (p *OfferCredentialParams) AsV2() *OfferCredentialV2 {
	preview, ok := p.CredentialPreview.(PreviewCredential)
	if !ok {
		preview = PreviewCredential{}
	}

	return &OfferCredentialV2{
		Type:              p.Type,
		Comment:           p.Comment,
		CredentialPreview: preview,
		Formats:           p.Formats,
		OffersAttach:      decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this credential offer into an issue credential 3.0 offer message.
func (p *OfferCredentialParams) AsV3() *OfferCredentialV3 {
	return &OfferCredentialV3{
		Type: p.Type,
		ID:   p.ID,
		Body: OfferCredentialV3Body{
			GoalCode:          p.GoalCode,
			Comment:           p.Comment,
			ReplacementID:     p.ReplacementID,
			CredentialPreview: p.CredentialPreview,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this credential offer from an issue credential 2.0 offer message.
func (p *OfferCredentialParams) FromV2(v2 *OfferCredentialV2) {
	p.Type = v2.Type
	p.ID = ""
	p.Comment = v2.Comment

	p.Attachments = decorator.V1AttachmentsToGeneric(v2.OffersAttach)
	p.CredentialPreview = v2.CredentialPreview
	p.Formats = v2.Formats

	p.GoalCode = ""
	p.ReplacementID = ""
}

// FromV3 initializes this credential offer from an issue credential 3.0 offer message.
func (p *OfferCredentialParams) FromV3(v3 *OfferCredentialV3) {
	p.Type = v3.Type
	p.ID = v3.ID
	p.Comment = v3.Body.Comment

	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
	p.CredentialPreview = v3.Body.CredentialPreview
	p.Formats = nil

	p.GoalCode = v3.Body.GoalCode
	p.ReplacementID = v3.Body.ReplacementID
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *OfferCredentialParams) UnmarshalJSON(b []byte) error {
	raw := rawOffer{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	if raw.isV3() {
		p.FromV3(&raw.OfferCredentialV3)
	} else {
		p.FromV2(&raw.OfferCredentialV2)
	}

	return nil
}

type rawOffer struct {
	OfferCredentialV2
	OfferCredentialV3
}

func (o *OfferCredentialV2) notEmpty() bool {
	return o.Type != "" ||
		o.Comment != "" ||
		o.CredentialPreview.Type != "" ||
		len(o.Formats) != 0 ||
		len(o.OffersAttach) != 0 ||
		len(o.CredentialPreview.Attributes) != 0
}

func (o *OfferCredentialV3) notEmpty() bool {
	return o.ID != "" ||
		o.Type != "" ||
		o.Body.Comment != "" ||
		o.Body.GoalCode != "" ||
		o.Body.ReplacementID != "" ||
		o.Body.CredentialPreview != nil ||
		len(o.Attachments) != 0
}

func (r *rawOffer) isV3() bool {
	if r.OfferCredentialV2.notEmpty() {
		return false
	}

	if r.OfferCredentialV3.notEmpty() {
		return true
	}

	return false
}

// RequestCredentialParams holds parameters for a credential request message.
type RequestCredentialParams struct {
	ID          string
	Type        string
	Comment     string
	Formats     []Format
	GoalCode    string
	Attachments []decorator.GenericAttachment
}

// AsV2 translates this credential request into an issue credential 2.0 request message.
func (p *RequestCredentialParams) AsV2() *RequestCredentialV2 {
	return &RequestCredentialV2{
		Type:           p.Type,
		Comment:        p.Comment,
		Formats:        p.Formats,
		RequestsAttach: decorator.GenericAttachmentsToV1(p.Attachments),
	}
}

// AsV3 translates this credential request into an issue credential 3.0 request message.
func (p *RequestCredentialParams) AsV3() *RequestCredentialV3 {
	return &RequestCredentialV3{
		ID:   p.ID,
		Type: p.Type,
		Body: RequestCredentialV3Body{
			Comment:  p.Comment,
			GoalCode: p.GoalCode,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
	}
}

// FromV2 initializes this credential request from an issue credential 2.0 request message.
func (p *RequestCredentialParams) FromV2(v2 *RequestCredentialV2) {
	p.ID = ""
	p.Type = v2.Type
	p.Comment = v2.Comment
	p.Formats = v2.Formats
	p.GoalCode = ""
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.RequestsAttach)
}

// FromV3 initialized this credential request from an issue credential 3.0 request message.
func (p *RequestCredentialParams) FromV3(v3 *RequestCredentialV3) {
	p.ID = v3.ID
	p.Type = v3.Type
	p.Comment = v3.Body.Comment
	p.Formats = nil
	p.GoalCode = v3.Body.GoalCode
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
}

type rawRequest struct {
	RequestCredentialV2
	RequestCredentialV3
}

func (r *RequestCredentialV2) notEmpty() bool {
	return r.Type != "" ||
		r.Comment != "" ||
		len(r.Formats) != 0 ||
		len(r.RequestsAttach) != 0
}

func (r *RequestCredentialV3) notEmpty() bool {
	return r.ID != "" ||
		r.Type != "" ||
		r.Body.GoalCode != "" ||
		r.Body.Comment != "" ||
		len(r.Attachments) != 0
}

func (r *rawRequest) isV3() bool {
	if r.RequestCredentialV2.notEmpty() {
		return false
	}

	if r.RequestCredentialV3.notEmpty() {
		return true
	}

	return false
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *RequestCredentialParams) UnmarshalJSON(b []byte) error {
	raw := rawRequest{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	if raw.isV3() {
		p.FromV3(&raw.RequestCredentialV3)
	} else {
		p.FromV2(&raw.RequestCredentialV2)
	}

	return nil
}

// IssueCredentialParams holds parameters for a credential issuance message.
type IssueCredentialParams struct { // nolint: golint
	Type          string
	ID            string
	Comment       string
	Formats       []Format
	Attachments   []decorator.GenericAttachment
	GoalCode      string
	ReplacementID string
	WebRedirect   *decorator.WebRedirect
}

// AsV2 translates this credential issuance into an issue credential 2.0 issuance message.
func (p *IssueCredentialParams) AsV2() *IssueCredentialV2 {
	return &IssueCredentialV2{
		Type:              p.Type,
		Comment:           p.Comment,
		Formats:           p.Formats,
		CredentialsAttach: decorator.GenericAttachmentsToV1(p.Attachments),
		WebRedirect:       p.WebRedirect,
	}
}

// AsV3 translates this credential issuance into an issue credential 3.0 issuance message.
func (p *IssueCredentialParams) AsV3() *IssueCredentialV3 {
	return &IssueCredentialV3{
		ID:   p.ID,
		Type: p.Type,
		Body: IssueCredentialV3Body{
			GoalCode:      p.GoalCode,
			ReplacementID: p.ReplacementID,
			Comment:       p.Comment,
		},
		Attachments: decorator.GenericAttachmentsToV2(p.Attachments),
		WebRedirect: p.WebRedirect,
	}
}

// FromV2 initializes this credential issuance from an issue credential 2.0 issuance message.
func (p *IssueCredentialParams) FromV2(v2 *IssueCredentialV2) {
	p.ID = ""
	p.Type = v2.Type
	p.Comment = v2.Comment
	p.Formats = v2.Formats
	p.GoalCode = ""
	p.ReplacementID = ""
	p.Attachments = decorator.V1AttachmentsToGeneric(v2.CredentialsAttach)
	p.WebRedirect = v2.WebRedirect
}

// FromV3 initialized this credential issuance from an issue credential 3.0 issuance message.
func (p *IssueCredentialParams) FromV3(v3 *IssueCredentialV3) {
	p.ID = v3.ID
	p.Type = v3.Type
	p.Comment = v3.Body.Comment
	p.Formats = nil
	p.GoalCode = v3.Body.GoalCode
	p.ReplacementID = v3.Body.ReplacementID
	p.Attachments = decorator.V2AttachmentsToGeneric(v3.Attachments)
	p.WebRedirect = v3.WebRedirect
}

type rawIssuance struct {
	IssueCredentialV2
	IssueCredentialV3
}

func (o *IssueCredentialV2) notEmpty() bool {
	return o.Type != "" ||
		o.Comment != "" ||
		len(o.Formats) != 0 ||
		len(o.CredentialsAttach) != 0
}

func (o *IssueCredentialV3) notEmpty() bool {
	return o.ID != "" ||
		o.Type != "" ||
		o.Body.Comment != "" ||
		o.Body.GoalCode != "" ||
		o.Body.ReplacementID != "" ||
		len(o.Attachments) != 0
}

func (r *rawIssuance) isV3() bool {
	if r.IssueCredentialV2.notEmpty() {
		return false
	}

	if r.IssueCredentialV3.notEmpty() {
		return true
	}

	return false
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *IssueCredentialParams) UnmarshalJSON(b []byte) error {
	raw := rawIssuance{}

	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	if raw.isV3() {
		p.FromV3(&raw.IssueCredentialV3)
	} else {
		p.FromV2(&raw.IssueCredentialV2)
	}

	return nil
}
