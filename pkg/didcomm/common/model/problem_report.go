/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// ProblemReport problem report definition
// TODO: need to provide full ProblemReport structure https://github.com/hyperledger/aries-framework-go/issues/912
type ProblemReport struct {
	service.Header
	Description struct {
		Code string `json:"code"`
	} `json:"description"`
}
