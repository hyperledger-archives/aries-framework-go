/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

const (
	// ContextURI is the required JSON-LD context for VCs and VPs.
	ContextURI = "https://www.w3.org/2018/credentials/v1"
	// ContextID is the non-fragment part of the JSON-LD schema ID for VCs and VPs.
	ContextID = "https://www.w3.org/2018/credentials"
	// VCType is the required Type for Verifiable Credentials.
	VCType = "VerifiableCredential"
	// VPType is the required Type for Verifiable Credentials.
	VPType = "VerifiablePresentation"
)
