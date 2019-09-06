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

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
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

// TODO Review this variable
//nolint:gochecknoglobals
var buf bytes.Buffer

// VerifyDefaultLogging verifies default logging behaviour.
// Should only be used for tests.
func VerifyDefaultLogging(t *testing.T, logger Logger, module string, setLevel func(module string, level metadata.Level)) { //nolint:lll
	allTestLevels := []metadata.Level{metadata.ERROR, metadata.DEBUG, metadata.INFO, metadata.WARNING, metadata.CRITICAL}

	for _, levelEnabled := range allTestLevels {

		// change log level
		setLevel(module, levelEnabled)

		logger.Infof(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, metadata.INFO, levelEnabled, true)

		logger.Errorf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, metadata.ERROR, levelEnabled, true)

		logger.Debugf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, metadata.DEBUG, levelEnabled, true)

		logger.Warnf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, metadata.WARNING, levelEnabled, true)
	}

	// testing critical logging by handling panic
	defer func() {
		r := recover()
		require.NotNil(t, r, "supposed to panic")
		matchDefLogOutput(t, module, metadata.CRITICAL, metadata.WARNING, true)
	}()

	logger.Panicf(msgFormat, msgArg1, msgArg2)
}

func matchDefLogOutput(t *testing.T, module string, currentLevel, levelEnabled metadata.Level, infoEnabled bool) {
	if currentLevel > levelEnabled {
		require.Empty(t, buf.String())
		return
	}
	defer buf.Reset()

	var regex string

	levelStr := metadata.ParseString(currentLevel)
	if infoEnabled {
		regex = fmt.Sprintf(defLoggerOutputRegex, module, levelStr, fmt.Sprintf(msgFormat, msgArg1, msgArg2))
	} else {
		regex = fmt.Sprintf(defLoggerNoCallerInfoRegex, module, levelStr, fmt.Sprintf(msgFormat, msgArg1, msgArg2))
	}

	match, err := regexp.MatchString(regex, buf.String())

	require.Empty(t, err, "error while matching regex with logoutput wasnt expected")
	require.True(t, match, "logger output incorrect,\n\tLevel Enabled:[%s]\n\tlogoutput:%s\n\tregex:%s",
		metadata.ParseString(currentLevel), buf.String(), regex)
}

// VerifyCustomLogger verifies custom logging behaviour.
// Should only be used for tests.
func VerifyCustomLogger(t *testing.T, logger Logger, module string) {
	regex := fmt.Sprintf(customLevelOutputExpectedRegex, module)
	allTestLevels := []metadata.Level{metadata.ERROR, metadata.DEBUG, metadata.INFO, metadata.WARNING, metadata.CRITICAL}

	for _, levelEnabled := range allTestLevels {

		// change log level
		metadata.SetLevel(module, levelEnabled)

		// print in all levels and verify
		logger.Infof("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.INFO, levelEnabled)

		logger.Debugf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.DEBUG, levelEnabled)

		logger.Warnf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.WARNING, levelEnabled)

		logger.Errorf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.ERROR, levelEnabled)

		logger.Panicf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.CRITICAL, levelEnabled)

		logger.Fatalf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, metadata.CRITICAL, levelEnabled)
	}
}

func matchCustomLogOutput(t *testing.T, regex string, level, levelEnabled metadata.Level) {
	if level > levelEnabled {
		require.Empty(t, buf.String())
		return
	}
	defer buf.Reset()
	match, err := regexp.MatchString(regex, buf.String())
	require.Empty(t, err, "error while matching regex with logoutput wasnt expected")
	require.True(t, match, "logger output incorrect,\n\tLevel Enabled:[%s]\n\tlogoutput:%s\n\tregex:%s",
		metadata.ParseString(level), buf.String(), regex)
}

// SwitchLogOutputToBuffer switches log output to test buffer.
// Should only be used for testing.
func SwitchLogOutputToBuffer(logger Logger) {
	defLog, ok := logger.(*ModLog).logger.(*DefLog)
	if ok {
		defLog.SetOutput(&buf)
	}
}

// GetSampleCustomLogger returns custom logger which can only be used for testing purposes.
func GetSampleCustomLogger(module string) *SampleLog {
	logger := log.New(&buf, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC)
	return &SampleLog{logger}
}

// SampleLog is a sample logger implementation for testing purposes.
// note: this implementation should be strictly used for testing only.
type SampleLog struct {
	logger *log.Logger
}

// Fatalf calls underlying logger.Fatalf
func (m *SampleLog) Fatalf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Panicf calls underlying logger.Panicf
func (m *SampleLog) Panicf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Debugf calls error log function if DEBUG level enabled
func (m *SampleLog) Debugf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Infof calls error log function if INFO level enabled
func (m *SampleLog) Infof(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Warnf calls error log function if WARNING level enabled
func (m *SampleLog) Warnf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Errorf calls error log function if ERROR level enabled
func (m *SampleLog) Errorf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}
