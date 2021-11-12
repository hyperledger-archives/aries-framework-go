/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// ProblemReport problem report definition
// TODO: need to provide full ProblemReport structure https://github.com/hyperledger/aries-framework-go/issues/912
type ProblemReport struct {
	Type        string      `json:"@type"`
	ID          string      `json:"@id"`
	Description Code        `json:"description"`
	WebRedirect interface{} `json:"~web-redirect,omitempty"`
}

// Code represents a problem report code.
type Code struct {
	Code string `json:"code"`
}

// ProblemReportV2 problem report definition.
type ProblemReportV2 struct {
	Type string              `json:"type,omitempty"`
	ID   string              `json:"id,omitempty"`
	Body ProblemReportV2Body `json:"body,omitempty"`
}

// ProblemReportV2Body represents body for ProblemReportV2.
type ProblemReportV2Body struct {
	Code        string      `json:"code,omitempty"`
	Comment     string      `json:"comment,omitempty"`
	Args        []string    `json:"args,omitempty"`
	EscalateTo  string      `json:"escalate_to,omitempty"`
	WebRedirect interface{} `json:"~web-redirect,omitempty"`
}
