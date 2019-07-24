/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
	"github.com/stretchr/testify/require"
)

const (
	defLoggerOutputRegex           = "\\[%s\\] .* UTC - modlog.VerifyDefaultLogging -> %s %s"
	defLoggerNoCallerInfoRegex     = "\\[%s\\] .* UTC -> %s %s"
	msgFormat                      = "brown %s jumps over the lazy %s"
	msgArg1                        = "fox"
	msgArg2                        = "dog"
	customOutput                   = "CUSTOM LOG OUTPUT"
	customLevelOutputExpectedRegex = "\\[%s\\] .* CUSTOM LOG OUTPUT"
)

var buf bytes.Buffer

//VerifyDefaultLogging verifies default logging behaviour.
//Should only be used for tests
func VerifyDefaultLogging(t *testing.T, logger api.Logger, module string, setLevel func(module string, level api.Level)) {
	allTestLevels := []api.Level{api.ERROR, api.DEBUG, api.INFO, api.WARNING, api.CRITICAL}

	for _, levelEnabled := range allTestLevels {

		//change log level
		setLevel(module, levelEnabled)

		logger.Infof(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, api.INFO, levelEnabled, true)

		logger.Errorf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, api.ERROR, levelEnabled, true)

		logger.Debugf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, api.DEBUG, levelEnabled, true)

		logger.Warnf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, api.WARNING, levelEnabled, true)
	}

	//testing critical logging by handling panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("supposed to panic")
		}
		matchDefLogOutput(t, module, api.CRITICAL, api.WARNING, true)
	}()

	logger.Panicf(msgFormat, msgArg1, msgArg2)
}

func matchDefLogOutput(t *testing.T, module string, currentLevel, levelEnabled api.Level, infoEnabled bool) {
	if currentLevel > levelEnabled {
		require.Empty(t, buf.String())
		return
	}
	defer buf.Reset()

	var regex string

	if infoEnabled {
		regex = fmt.Sprintf(defLoggerOutputRegex, module, metadata.ParseString(currentLevel), fmt.Sprintf(msgFormat, msgArg1, msgArg2))
	} else {
		regex = fmt.Sprintf(defLoggerNoCallerInfoRegex, module, metadata.ParseString(currentLevel), fmt.Sprintf(msgFormat, msgArg1, msgArg2))
	}

	match, err := regexp.MatchString(regex, buf.String())

	//TODO delete below log line
	t.Log(buf.String())

	require.Empty(t, err, "error while matching regex with logoutput wasnt expected")
	require.True(t, match, "logger isn't producing output as expected,\n\tLevel Enabled:[%s]\n\tlogoutput:%s\n\tregex:%s", metadata.ParseString(currentLevel), buf.String(), regex)
}

//VerifyCustomLogger verifies custom logging behaviour.
//Should only be used for tests
func VerifyCustomLogger(t *testing.T, logger api.Logger, module string) {
	regex := fmt.Sprintf(customLevelOutputExpectedRegex, module)
	allTestLevels := []api.Level{api.ERROR, api.DEBUG, api.INFO, api.WARNING, api.CRITICAL}

	for _, levelEnabled := range allTestLevels {

		//change log level
		SetLevel(module, levelEnabled)

		//print in all levels and verify
		logger.Infof("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.INFO, levelEnabled)

		logger.Debugf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.DEBUG, levelEnabled)

		logger.Warnf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.WARNING, levelEnabled)

		logger.Errorf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.ERROR, levelEnabled)

		logger.Panicf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.CRITICAL, levelEnabled)

		logger.Fatalf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, api.CRITICAL, levelEnabled)
	}
}

func matchCustomLogOutput(t *testing.T, regex string, level, levelEnabled api.Level) {
	if level > levelEnabled {
		require.Empty(t, buf.String())
		return
	}
	defer buf.Reset()
	//TODO : delete
	t.Log(buf.String())
	match, err := regexp.MatchString(regex, buf.String())
	require.Empty(t, err, "error while matching regex with logoutput wasnt expected")
	require.True(t, match, "logger isn't producing output as expected,\n\tLevel Enabled:[%s]\n\tlogoutput:%s\n\tregex:%s", metadata.ParseString(level), buf.String(), regex)
}

//SwitchLogOutputToBuffer switches log output to test buffer,
//Should only be used for testing
func SwitchLogOutputToBuffer(logger api.Logger) {
	defLog, ok := logger.(*defLog)
	if ok {
		defLog.ChangeOutput(&buf)
	}
}

//GetSampleCustomLogger returns custom logger which can only be used for testing purposes.
func GetSampleCustomLogger(output *bytes.Buffer, module string) api.Logger {
	logger := log.New(output, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC)
	return &sampleLog{logger}
}

//NewCustomLoggingProvider returns new custom logging provider which can only be used for testing purposes.
func NewCustomLoggingProvider() api.LoggerProvider {
	return &sampleProvider{}
}

// sampleProvider is a custom logging provider
type sampleProvider struct {
}

//GetLogger returns custom logger implementation
func (p *sampleProvider) GetLogger(module string) api.Logger {
	return GetSampleCustomLogger(&buf, module)
}

//modLog is a moduled wrapper for api.Logger implementation
type sampleLog struct {
	logger *log.Logger
}

// Fatal calls underlying logger.Fatal
func (m *sampleLog) Fatalf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Panic calls underlying logger.Panic
func (m *sampleLog) Panicf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Debug calls error log function if DEBUG level enabled
func (m *sampleLog) Debugf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Info calls error log function if INFO level enabled
func (m *sampleLog) Infof(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Warn calls error log function if WARNING level enabled
func (m *sampleLog) Warnf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Error calls error log function if ERROR level enabled
func (m *sampleLog) Errorf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}
