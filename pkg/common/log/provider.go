/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"github.com/hyperledger/aries-framework-go/component/log"
	spilog "github.com/hyperledger/aries-framework-go/spi/log"
)

// Initialize sets new custom logging provider which takes over logging operations.
// It is required to call this function before making any loggings for using custom loggers.
func Initialize(l spilog.LoggerProvider) {
	log.Initialize(l)
}
