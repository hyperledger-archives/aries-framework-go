/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"github.com/hyperledger/aries-framework-go/component/log"
	spilog "github.com/hyperledger/aries-framework-go/spi/log"
)

// Log is an implementation of Logger interface.
// It encapsulates default or custom logger to provide module and level based logging.
type Log = log.Log

// New creates and returns a Logger implementation based on given module name.
// note: the underlying logger instance is lazy initialized on first use.
// To use your own logger implementation provide logger provider in 'Initialize()' before logging any line.
// If 'Initialize()' is not called before logging any line then default logging implementation will be used.
func New(module string) *Log {
	return log.New(module)
}

// SetLevel - setting log level for given module
//
//	Parameters:
//	module is module name
//	level is logging level
//
// If not set default logging level is info.
func SetLevel(module string, level spilog.Level) {
	log.SetLevel(module, level)
}

// GetLevel - getting log level for given module
//
//	Parameters:
//	module is module name
//
//	Returns:
//	logging level
//
// If not set default logging level is info.
func GetLevel(module string) spilog.Level {
	return log.GetLevel(module)
}

// IsEnabledFor - Check if given log level is enabled for given module
//
//	Parameters:
//	module is module name
//	level is logging level
//
//	Returns:
//	is logging enabled for this module and level
//
// If not set default logging level is info.
func IsEnabledFor(module string, level spilog.Level) bool {
	return log.IsEnabledFor(module, level)
}

// ParseLevel returns the log level from a string representation.
//
//	Parameters:
//	level is logging level in string representation
//
//	Returns:
//	logging level
func ParseLevel(level string) (spilog.Level, error) {
	l, err := log.ParseLevel(level)

	return l, err
}

// ShowCallerInfo - Show caller info in log lines for given log level and module
//
//	Parameters:
//	module is module name
//	level is logging level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func ShowCallerInfo(module string, level spilog.Level) {
	log.ShowCallerInfo(module, level)
}

// HideCallerInfo - Do not show caller info in log lines for given log level and module
//
//	Parameters:
//	module is module name
//	level is logging level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func HideCallerInfo(module string, level spilog.Level) {
	log.HideCallerInfo(module, level)
}

// IsCallerInfoEnabled - returns if caller info enabled for given log level and module
//
//	Parameters:
//	module is module name
//	level is logging level
//
//	Returns:
//	is caller info enabled for this module and level
//
// note: based on implementation of custom logger, callerinfo info may not be available for custom logging provider
func IsCallerInfoEnabled(module string, level spilog.Level) bool {
	return log.IsCallerInfoEnabled(module, level)
}
