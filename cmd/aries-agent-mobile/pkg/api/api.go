/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"

// AriesController provides Aries agent protocols tailored to mobile platforms
type AriesController interface {

	// GetIntroduceController returns an implementation of IntroduceController
	GetIntroduceController() (IntroduceController, error)
}

// IntroduceController defines methods for the introduce protocol
type IntroduceController interface {

	// Actions returns unfinished actions for the async usage.
	Actions(request *wrappers.IntroduceActionsRequest) *wrappers.IntroduceActionsResponse
}
