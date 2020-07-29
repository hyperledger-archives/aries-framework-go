/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// AriesController provides Aries agent protocols tailored to mobile platforms.
type AriesController interface {

	// GetIntroduceController returns an implementation of IntroduceController
	GetIntroduceController() (IntroduceController, error)

	// GetVerifiableController returns an implementation of VerifiableController
	GetVerifiableController() (VerifiableController, error)

	// GetIssueCredentialController returns an implementation of IssueCredentialController
	GetIssueCredentialController() (IssueCredentialController, error)
	
	// GetDIDExchangeController returns an implementation of DIDExchangeController
	GetDIDExchangeController() (DIDExchangeController, error)
}
