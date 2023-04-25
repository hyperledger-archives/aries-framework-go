// +build !ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
)

func wrapTime(t time.Time) *util.TimeWrapper {
	return &util.TimeWrapper{Time: t}
}
