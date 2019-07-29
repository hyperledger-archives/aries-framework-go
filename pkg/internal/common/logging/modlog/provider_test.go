/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

func TestDefLoggerProvider(t *testing.T) {
	const module = "sample-module"
	deflogger := NewModLogProvider().GetLogger(module)

	//Change output function to bytes.Buffer for testing
	deflogger.(*modLog).logger.(*defLog).SetOutput(&buf)

	VerifyDefaultLogging(t, deflogger, module, metadata.SetLevel)
}

func TestDefLoggerProviderNoCallerInfo(t *testing.T) {
	const module = "sample-module-no-caller-info"
	deflogger := NewModLogProvider().GetLogger(module)

	//Change output function to bytes.Buffer for testing
	deflogger.(*modLog).logger.(*defLog).SetOutput(&buf)

	metadata.HideCallerInfo(module, log.INFO)
	metadata.SetLevel(module, log.DEBUG)

	deflogger.Infof(msgFormat, msgArg1, msgArg2)
	matchDefLogOutput(t, module, log.INFO, log.DEBUG, false)
}

func TestCustomLoggerProvider(t *testing.T) {
	const module = "sample-module"
	provider := NewModLogProvider(WithCustomProvider(NewCustomLoggingProvider()))
	customLogger := provider.GetLogger(module)

	VerifyCustomLogger(t, customLogger, module)
}
