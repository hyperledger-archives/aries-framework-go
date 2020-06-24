/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrappers

// CommandError contains a basic command Error.
type CommandError struct {
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
	Type    int    `json:"type,omitempty"`
}

// IntroduceActionsRequest contains the fields on an actions request
type IntroduceActionsRequest struct {
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
}

// IntroduceActionsResponse contains an action response and an error
type IntroduceActionsResponse struct {
	ActionsResponse string        `json:"actions_response"`
	Error           *CommandError `json:"error,omitempty"`
}
