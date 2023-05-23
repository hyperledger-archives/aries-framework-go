/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"github.com/hyperledger/aries-framework-go/component/models/presexch"
)

// PresentationSubmission is the container for the descriptor_map:
// https://identity.foundation/presentation-exchange/#presentation-submission.
type PresentationSubmission = presexch.PresentationSubmission

// InputDescriptorMapping maps an InputDescriptor to a verifiable credential pointed to by the JSONPath in `Path`.
type InputDescriptorMapping = presexch.InputDescriptorMapping

// PresentationDefinition presentation definitions (https://identity.foundation/presentation-exchange/).
type PresentationDefinition = presexch.PresentationDefinition

// SubmissionRequirement describes input that must be submitted via a Presentation Submission
// to satisfy Verifier demands.
type SubmissionRequirement = presexch.SubmissionRequirement

// InputDescriptor input descriptors.
type InputDescriptor = presexch.InputDescriptor

// Schema input descriptor schema.
type Schema = presexch.Schema

// Constraints describes InputDescriptor`s Constraints field.
type Constraints = presexch.Constraints

// Holder describes Constraints`s  holder object.
type Holder = presexch.Holder

// Field describes Constraints`s Fields field.
type Field = presexch.Field

// Filter describes filter.
type Filter = presexch.Filter

// Selection can be "all" or "pick".
type Selection = presexch.Selection

const (
	// All rule`s value.
	All = presexch.All
	// Pick rule`s value.
	Pick = presexch.Pick
)

// Preference can be "required" or "preferred".
type Preference = presexch.Preference

const (
	// Required predicate`s value.
	Required = presexch.Required
	// Preferred predicate`s value.
	Preferred = presexch.Preferred
)

// StrOrInt type that defines string or integer.
type StrOrInt = presexch.StrOrInt

// Format describes PresentationDefinition`s Format field.
type Format = presexch.Format

// JwtType contains alg.
type JwtType = presexch.JwtType

// LdpType contains proof_type.
type LdpType = presexch.LdpType

const (
	// FormatJWT presentation exchange format.
	FormatJWT = presexch.FormatJWT
	// FormatJWTVC presentation exchange format.
	FormatJWTVC = presexch.FormatJWTVC
	// FormatJWTVP presentation exchange format.
	FormatJWTVP = presexch.FormatJWTVP
	// FormatLDP presentation exchange format.
	FormatLDP = presexch.FormatLDP
	// FormatLDPVC presentation exchange format.
	FormatLDPVC = presexch.FormatLDPVC
	// FormatLDPVP presentation exchange format.
	FormatLDPVP = presexch.FormatLDPVP
)

// MatchedSubmissionRequirement contains information about VCs that matched a presentation definition.
type MatchedSubmissionRequirement = presexch.MatchedSubmissionRequirement

// MatchedInputDescriptor contains information about VCs that matched an input descriptor of presentation definition.
type MatchedInputDescriptor = presexch.MatchedInputDescriptor

// MatchValue holds a matched credential from PresentationDefinition.Match, along with the ID of the
// presentation that held the matched credential.
type MatchValue = presexch.MatchValue
