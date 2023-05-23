/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"github.com/hyperledger/aries-framework-go/component/models/presexch"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
)

// MatchOptions is a holder of options that can set when matching a submission against definitions.
type MatchOptions = presexch.MatchOptions

// MatchOption is an option that sets an option for when matching.
type MatchOption = presexch.MatchOption

// WithCredentialOptions used when parsing the embedded credentials.
func WithCredentialOptions(options ...verifiable.CredentialOpt) MatchOption {
	return func(m *MatchOptions) {
		m.CredentialOptions = options
	}
}

// WithDisableSchemaValidation used to disable schema validation.
func WithDisableSchemaValidation() MatchOption {
	return func(m *MatchOptions) {
		m.DisableSchemaValidation = true
	}
}

// WithMergedSubmission provides a presentation submission that's external to the Presentations being matched,
// which contains the descriptor mapping for each Presentation.
//
// If there are multiple Presentations, this merged submission should use the Presentation array as the JSON Path root
// when referencing the contained Presentations and the Credentials within.
func WithMergedSubmission(submission *PresentationSubmission) MatchOption {
	return func(m *MatchOptions) {
		m.MergedSubmission = submission
	}
}

// WithMergedSubmissionMap provides a presentation submission that's external to the Presentations being matched,
// which contains the descriptor mapping for each Presentation. This submission is expected to be in the
// map[string]interface{} format used by json.Unmarshal.
//
// If there are multiple Presentations, this merged submission should use the Presentation array as the JSON Path root
// when referencing the contained Presentations and the Credentials within.
func WithMergedSubmissionMap(submissionMap map[string]interface{}) MatchOption {
	return func(m *MatchOptions) {
		m.MergedSubmissionMap = submissionMap
	}
}

// MatchRequirementsOpt is the MatchSubmissionRequirement option.
type MatchRequirementsOpt = presexch.MatchRequirementsOpt

// WithSelectiveDisclosureApply enables selective disclosure apply on resulting VC.
func WithSelectiveDisclosureApply() MatchRequirementsOpt {
	return presexch.WithSelectiveDisclosureApply()
}

// WithSDCredentialOptions used when applying selective disclosure.
func WithSDCredentialOptions(options ...verifiable.CredentialOpt) MatchRequirementsOpt {
	return presexch.WithSDCredentialOptions(options...)
}
