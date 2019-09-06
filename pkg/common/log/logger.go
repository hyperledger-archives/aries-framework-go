/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
)

//nolint:lll
const (
	// loggerNotInitializedMsg is used when a logger is not initialized before logging
	loggerNotInitializedMsg = "Default logger initialized (please call log.Initialize() if you wish to use a custom logger)"
	loggerModule            = "aries-framework/common"
)

// Log is an implementation of Logger interface.
// It encapsulates default or custom logger to provide module and level based logging.
type Log struct {
	instance Logger
	module   string
	once     sync.Once
}

// New creates and returns a Logger implementation based on given module name.
// note: the underlying logger instance is lazy initialized on first use.
// To use your own logger implementation provide logger provider in 'Initialize()' before logging any line.
// If 'Initialize()' is not called before logging any line then default logging implementation will be used.
func New(module string) *Log {
	return &Log{module: module}
}

// Fatalf calls Fatalf function of underlying logger
// should possibly cause system shutdown based on implementation
func (l *Log) Fatalf(msg string, args ...interface{}) {
	l.logger().Fatalf(msg, args...)
}

// Panicf calls Panic function of underlying logger
// should possibly cause panic based on implementation
func (l *Log) Panicf(msg string, args ...interface{}) {
	l.logger().Panicf(msg, args...)
}

// Debugf calls Debugf function of underlying logger
func (l *Log) Debugf(msg string, args ...interface{}) {
	l.logger().Debugf(msg, args...)
}

// Infof calls Infof function of underlying logger
func (l *Log) Infof(msg string, args ...interface{}) {
	l.logger().Infof(msg, args...)
}

// Warnf calls Warnf function of underlying logger
func (l *Log) Warnf(msg string, args ...interface{}) {
	l.logger().Warnf(msg, args...)
}

// Errorf calls Errorf function of underlying logger
func (l *Log) Errorf(msg string, args ...interface{}) {
	l.logger().Errorf(msg, args...)
}

func (l *Log) logger() Logger {
	l.once.Do(func() {
		l.instance = loggerProvider().GetLogger(l.module)
	})
	return l.instance
}

// SetLevel - setting log level for given module
//  Parameters:
//  module is module name
//  level is logging level
//
// If not set default logging level is info
func SetLevel(module string, level Level) {
	metadata.SetLevel(module, metadata.Level(level))
}

// GetLevel - getting log level for given module
//  Parameters:
//  module is module name
//
//  Returns:
//  logging level
//
// If not set default logging level is info
func GetLevel(module string) Level {
	return Level(metadata.GetLevel(module))
}

// IsEnabledFor - Check if given log level is enabled for given module
//  Parameters:
//  module is module name
//  level is logging level
//
//  Returns:
//  is logging enabled for this module and level
//
// If not set default logging level is info
func IsEnabledFor(module string, level Level) bool {
	return metadata.IsEnabledFor(module, metadata.Level(level))
}

// ParseLevel returns the log level from a string representation.
//  Parameters:
//  level is logging level in string representation
//
//  Returns:
//  logging level
func ParseLevel(level string) (Level, error) {
	l, err := metadata.ParseLevel(level)
	return Level(l), err
}

// ShowCallerInfo - Show caller info in log lines for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func ShowCallerInfo(module string, level Level) {
	metadata.ShowCallerInfo(module, metadata.Level(level))
}

// HideCallerInfo - Do not show caller info in log lines for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func HideCallerInfo(module string, level Level) {
	metadata.HideCallerInfo(module, metadata.Level(level))
}

// IsCallerInfoEnabled - returns if caller info enabled for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
//  Returns:
//  is caller info enabled for this module and level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func IsCallerInfoEnabled(module string, level Level) bool {
	return metadata.IsCallerInfoEnabled(module, metadata.Level(level))
}
