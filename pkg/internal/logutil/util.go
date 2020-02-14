/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logutil

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

// LogError is a utility function to log error messages.
func LogError(logger *log.Log, command, action, errMsg string, data ...string) {
	logger.Errorf("command=[%s] action=[%s] %s errMsg=[%s]", command, action, data, errMsg)
}

// LogDebug is a utility function to log debug messages.
func LogDebug(logger *log.Log, command, action, msg string, data ...string) {
	logger.Debugf("command=[%s] action=[%s] %s msg=[%s]", command, action, data, msg)
}

// LogInfo is a utility function to log info messages.
func LogInfo(logger *log.Log, command, action, msg string, data ...string) {
	logger.Infof("command=[%s] action=[%s] %s msg=[%s]", command, action, data, msg)
}

// CreateKeyValueString creates a concatenated string.
func CreateKeyValueString(key, val string) string {
	return fmt.Sprintf("%s=[%s]", key, val)
}
