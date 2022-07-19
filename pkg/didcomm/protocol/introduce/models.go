/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Proposal defines proposal request.
type Proposal struct {
	Type     string            `json:"@type,omitempty"`
	ID       string            `json:"@id,omitempty"`
	To       *To               `json:"to,omitempty"`
	NWise    bool              `json:"nwise,omitempty"`
	Thread   *decorator.Thread `json:"~thread,omitempty"`
	Timing   *decorator.Timing `json:"~timing,omitempty"`
	Goal     string            `json:"goal,omitempty"`
	GoalCode string            `json:"goal_code,omitempty"`
}

// To introducee descriptor keeps information about the introduction
// e.g introducer wants to introduce Bot to introducee { "name": "Bob" }.
type To struct {
	Name            string          `json:"name,omitempty"`
	Description     string          `json:"description,omitempty"`
	DescriptionL10N DescriptionL10N `json:"description~l10n,omitempty"`
	Where           string          `json:"where,omitempty"`
	ImgAttach       ImgAttach       `json:"img~attach,omitempty"`
	Proposed        bool            `json:"proposed,omitempty"`
}

// DescriptionL10N may contain locale field and key->val pair for translation
// e.g { "locale": "en", "es": "Donde se toma el MRI; no en el centro"},
// where locale field tells that field Description form To struct has en translation.
type DescriptionL10N map[string]string

// Locale returns locale for the specified description (To.Description).
func (d DescriptionL10N) Locale() string {
	if d == nil {
		return ""
	}
	// TODO: clarify whether it should be default locale e.g "en" or empty string
	return d["locale"]
}

// ImgAttach represent information about the image.
type ImgAttach struct {
	Description string  `json:"description,omitempty"`
	MimeType    string  `json:"mime-type,omitempty"`
	Filename    string  `json:"filename,omitempty"`
	Content     Content `json:"content,omitempty"`
}

// Content keeps image data.
type Content struct {
	Link      string `json:"link,omitempty"`
	ByteCount int    `json:"byte_count,omitempty"`
	Sha256    string `json:"sha256,omitempty"`
}

// PleaseIntroduceTo includes all field from To structure
// also it has Discovered the field which should be provided by help-me-discover protocol.
type PleaseIntroduceTo struct {
	// nolint: staticcheck
	To `json:",squash"`
	// Discovered    Discovered `json:"discovered,omitempty"`
}

// Request is not part of any state machine, it can be sent at any time,
// and when it is received, the recipient can choose whether or not to honor it in their own way
// TODO: need to clarify about decorator ~please_ack and problem_report
// 		 should Request contain those fields? What type it should be for each field?
type Request struct {
	Type              string             `json:"@type,omitempty"`
	ID                string             `json:"@id,omitempty"`
	PleaseIntroduceTo *PleaseIntroduceTo `json:"please_introduce_to,omitempty"`
	NWise             bool               `json:"nwise,omitempty"`
	Timing            *decorator.Timing  `json:"~timing,omitempty"`
}

// Response message that introducee usually sends in response to an introduction proposal.
type Response struct {
	Type        string                  `json:"@type,omitempty"`
	ID          string                  `json:"@id,omitempty"`
	Thread      *decorator.Thread       `json:"~thread,omitempty"`
	Approve     bool                    `json:"approve,omitempty"`
	OOBMessage  map[string]interface{}  `json:"oob-message,omitempty"`
	Attachments []*decorator.Attachment `json:"~attach,omitempty"`
}
