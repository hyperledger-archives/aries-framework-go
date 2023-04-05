/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"bytes"
	"fmt"
	builtinlog "log"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/log/internal/metadata"

	"github.com/hyperledger/aries-framework-go/spi/log"
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

// TODO https://github.com/hyperledger/aries-framework-go/issues/751 remove global var buff.
//
//nolint:gochecknoglobals
var buf bytes.Buffer

// VerifyDefaultLogging verifies default logging behaviour.
// Should only be used for tests.
func VerifyDefaultLogging(t *testing.T, logger log.Logger, module string, setLevel func(module string, level log.Level)) { //nolint:lll
	allTestLevels := []log.Level{log.ERROR, log.DEBUG, log.INFO, log.WARNING, log.CRITICAL}

	for _, levelEnabled := range allTestLevels {
		// change log level
		setLevel(module, levelEnabled)

		logger.Infof(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, log.INFO, levelEnabled, true)

		logger.Errorf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, log.ERROR, levelEnabled, true)

		logger.Debugf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, log.DEBUG, levelEnabled, true)

		logger.Warnf(msgFormat, msgArg1, msgArg2)
		matchDefLogOutput(t, module, log.WARNING, levelEnabled, true)
	}

	// testing critical logging by handling panic
	defer func() {
		r := recover()
		require.NotNil(t, r, "supposed to panic")
		matchDefLogOutput(t, module, log.CRITICAL, log.WARNING, true)
	}()

	logger.Panicf(msgFormat, msgArg1, msgArg2)
}

func matchDefLogOutput(t *testing.T, module string, currentLevel, levelEnabled log.Level, infoEnabled bool) {
	if currentLevel > levelEnabled {
		require.Empty(t, buf.String())
		return
	}

	defer buf.Reset()

	levelStr := metadata.ParseString(currentLevel)

	var regex string
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
func VerifyCustomLogger(t *testing.T, logger log.Logger, module string) {
	regex := fmt.Sprintf(customLevelOutputExpectedRegex, module)
	allTestLevels := []log.Level{log.ERROR, log.DEBUG, log.INFO, log.WARNING, log.CRITICAL}

	for _, levelEnabled := range allTestLevels {
		// change log level
		metadata.SetLevel(module, levelEnabled)

		// print in all levels and verify
		logger.Infof("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.INFO, levelEnabled)

		logger.Debugf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.DEBUG, levelEnabled)

		logger.Warnf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.WARNING, levelEnabled)

		logger.Errorf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.ERROR, levelEnabled)

		logger.Panicf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.CRITICAL, levelEnabled)

		logger.Fatalf("brown fox jumps over the lazy dog")
		matchCustomLogOutput(t, regex, log.CRITICAL, levelEnabled)
	}
}

func matchCustomLogOutput(t *testing.T, regex string, level, levelEnabled log.Level) {
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
func SwitchLogOutputToBuffer(logger log.Logger) {
	defLog, ok := logger.(*ModLog).logger.(*DefLog)
	if ok {
		defLog.SetOutput(&buf)
	}
}

// GetSampleCustomLogger returns custom logger which can only be used for testing purposes.
func GetSampleCustomLogger(module string) *SampleLog {
	logger := builtinlog.New(&buf, fmt.Sprintf(logPrefixFormatter, module),
		builtinlog.Ldate|builtinlog.Ltime|builtinlog.LUTC)
	return &SampleLog{logger}
}

// SampleLog is a sample logger implementation for testing purposes.
// note: this implementation should be strictly used for testing only.
type SampleLog struct {
	logger *builtinlog.Logger
}

// Fatalf calls underlying logger.Fatalf.
func (m *SampleLog) Fatalf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Panicf calls underlying logger.Panicf.
func (m *SampleLog) Panicf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Debugf calls error log function if DEBUG level enabled.
func (m *SampleLog) Debugf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Infof calls error log function if INFO level enabled.
func (m *SampleLog) Infof(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Warnf calls error log function if WARNING level enabled.
func (m *SampleLog) Warnf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}

// Errorf calls error log function if ERROR level enabled.
func (m *SampleLog) Errorf(format string, args ...interface{}) {
	m.logger.Print(customOutput)
}
