/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package modlog provides a moduled wrapper for any underlying log.Logger implementation.
package modlog

import (
	"github.com/hyperledger/aries-framework-go/component/log/internal/metadata"
	"github.com/hyperledger/aries-framework-go/spi/log"
)

// NewModLog returns new moduled logger instance based on given logger implementation and module.
func NewModLog(logger log.Logger, module string) *ModLog {
	return &ModLog{logger: logger, module: module}
}

// ModLog is a moduled wrapper for any underlying 'log.Logger' implementation.
// Since this is a moduled wrapper each module can have different logging levels (default is INFO).
type ModLog struct {
	logger log.Logger
	module string
}

// Fatalf calls underlying logger.Fatal.
func (m *ModLog) Fatalf(format string, args ...interface{}) {
	m.logger.Fatalf(format, args...)
}

// Panicf calls underlying logger.Panic.
func (m *ModLog) Panicf(format string, args ...interface{}) {
	m.logger.Panicf(format, args...)
}

// Debugf calls error log function if DEBUG level enabled.
func (m *ModLog) Debugf(format string, args ...interface{}) {
	if !metadata.IsEnabledFor(m.module, log.DEBUG) {
		return
	}

	m.logger.Debugf(format, args...)
}

// Infof calls error log function if INFO level enabled.
func (m *ModLog) Infof(format string, args ...interface{}) {
	if !metadata.IsEnabledFor(m.module, log.INFO) {
		return
	}

	m.logger.Infof(format, args...)
}

// Warnf calls error log function if WARNING level enabled.
func (m *ModLog) Warnf(format string, args ...interface{}) {
	if !metadata.IsEnabledFor(m.module, log.WARNING) {
		return
	}

	m.logger.Warnf(format, args...)
}

// Errorf calls error log function if ERROR level enabled.
func (m *ModLog) Errorf(format string, args ...interface{}) {
	if !metadata.IsEnabledFor(m.module, log.ERROR) {
		return
	}

	m.logger.Errorf(format, args...)
}
