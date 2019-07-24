/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

func TestDefLoggerProvider(t *testing.T) {
	const module = "sample-module"
	defProvider := ModuledLoggerProvider()
	deflogger := defProvider.GetLogger(module)

	//Change output function to bytes.Buffer for testing
	deflogger.(*defLog).ChangeOutput(&buf)

	VerifyDefaultLogging(t, deflogger, module, SetLevel)
}

func TestDefLoggerProviderNoCallerInfo(t *testing.T) {
	const module = "sample-module-no-caller-info"
	defProvider := ModuledLoggerProvider()
	deflogger := defProvider.GetLogger(module)

	//Change output function to bytes.Buffer for testing
	deflogger.(*defLog).ChangeOutput(&buf)

	HideCallerInfo(module, api.INFO)
	SetLevel(module, api.DEBUG)

	deflogger.Infof(msgFormat, msgArg1, msgArg2)
	matchDefLogOutput(t, module, api.INFO, api.DEBUG, false)
}

func TestCustomLoggerProvider(t *testing.T) {
	const module = "sample-module"
	defProvider := ModuledLoggerProvider(WithCustomProvider(NewCustomLoggingProvider()))
	customLogger := defProvider.GetLogger(module)

	VerifyCustomLogger(t, customLogger, module)
}
