/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocklogger

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/log"
)

// MockLogger is a mocked logger that can be used for testing.
type MockLogger struct {
	AllLogContents   string
	FatalLogContents string
	PanicLogContents string
	DebugLogContents string
	InfoLogContents  string
	WarnLogContents  string
	ErrorLogContents string
}

// Fatalf writes to the mock logger.
func (t *MockLogger) Fatalf(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.FatalLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Panicf writes to the mock logger.
func (t *MockLogger) Panicf(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.PanicLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Debugf writes to the mock logger.
func (t *MockLogger) Debugf(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.DebugLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Infof writes to the mock logger.
func (t *MockLogger) Infof(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.InfoLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Warnf writes to the mock logger.
func (t *MockLogger) Warnf(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.WarnLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Errorf writes to the mock logger.
func (t *MockLogger) Errorf(msg string, args ...interface{}) {
	t.AllLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))

	t.ErrorLogContents += fmt.Sprintln(fmt.Sprintf(msg, args...))
}

// Provider is a mock logger provider that can be used for testing.
type Provider struct {
	MockLogger *MockLogger
}

// GetLogger returns the underlying mock logger.
func (p *Provider) GetLogger(string) log.Logger {
	return p.MockLogger
}
