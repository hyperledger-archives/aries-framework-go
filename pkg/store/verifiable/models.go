/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// Record model containing name, ID and other fields of interest.
type Record struct {
	Name      string   `json:"name,omitempty"`
	ID        string   `json:"id,omitempty"`
	Context   []string `json:"context,omitempty"`
	Type      []string `json:"type,omitempty"`
	SubjectID string   `json:"subjectId,omitempty"`
}
