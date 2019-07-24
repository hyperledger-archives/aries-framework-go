/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logging

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/modlog"
)

const (
	//loggerNotInitializedMsg is used when a logger is not initialized before logging
	loggerNotInitializedMsg = "Default logger initialized (please call logging.InitLogger if you wish to use a custom logger)"
	loggerModule            = "aries-framework/common"
)

//Logger is a basic implementation of api.Logger interface.
//It encapsulates default or custom logger to provide module and level based logging.
type Logger struct {
	instance api.Logger
	module   string
	once     sync.Once
}

// NewLogger creates and returns a Logger object based on the given module name.
// note: the underlying logger instance is lazy initialized on first use
func NewLogger(module string) *Logger {
	return &Logger{module: module}
}

// loggerProviderInstance is logger factory singleton - access only via loggerProvider()
var loggerProviderInstance api.LoggerProvider
var loggerProviderOnce sync.Once

//Initialize sets new custom logging provider which takes over logging operations.
//It is required to call this function before making any loggings for using custom loggers.
func Initialize(l api.LoggerProvider) {
	loggerProviderOnce.Do(func() {
		loggerProviderInstance = modlog.ModuledLoggerProvider(modlog.WithCustomProvider(l))
		logger := loggerProviderInstance.GetLogger(loggerModule)
		logger.Debugf("Logger provider initialized")
	})
}

func loggerProvider() api.LoggerProvider {
	loggerProviderOnce.Do(func() {
		// A custom logger must be initialized prior to the first log output
		// Otherwise the built-in logger is used
		loggerProviderInstance = modlog.ModuledLoggerProvider()
		logger := loggerProviderInstance.GetLogger(loggerModule)
		logger.Debugf(loggerNotInitializedMsg)
	})
	return loggerProviderInstance
}

//Fatalf calls Fatalf function of underlying logger
//should possibly cause system shutdown based on implementation
func (l *Logger) Fatalf(msg string, args ...interface{}) {
	l.logger().Fatalf(msg, args...)
}

//Panicf calls Panic function of underlying logger
//should possibly cause panic based on implementation
func (l *Logger) Panicf(msg string, args ...interface{}) {
	l.logger().Panicf(msg, args...)
}

//Debugf calls Debugf function of underlying logger
func (l *Logger) Debugf(msg string, args ...interface{}) {
	l.logger().Debugf(msg, args...)
}

//Infof calls Infof function of underlying logger
func (l *Logger) Infof(msg string, args ...interface{}) {
	l.logger().Infof(msg, args...)
}

//Warnf calls Warnf function of underlying logger
func (l *Logger) Warnf(msg string, args ...interface{}) {
	l.logger().Warnf(msg, args...)
}

//Errorf calls Errorf function of underlying logger
func (l *Logger) Errorf(msg string, args ...interface{}) {
	l.logger().Errorf(msg, args...)
}

func (l *Logger) logger() api.Logger {
	l.once.Do(func() {
		l.instance = loggerProvider().GetLogger(l.module)
	})
	return l.instance
}

//SetLevel - setting log level for given module
//  Parameters:
//  module is module name
//  level is logging level
//If not set default logging level is info
func SetLevel(module string, level api.Level) {
	modlog.SetLevel(module, level)
}

//GetLevel - getting log level for given module
//  Parameters:
//  module is module name
//
//  Returns:
//  logging level
//If not set default logging level is info
func GetLevel(module string) api.Level {
	return modlog.GetLevel(module)
}

//IsEnabledFor - Check if given log level is enabled for given module
//  Parameters:
//  module is module name
//  level is logging level
//
//  Returns:
//  is logging enabled for this module and level
//If not set default logging level is info
func IsEnabledFor(module string, level api.Level) bool {
	return modlog.IsEnabledFor(module, level)
}

// LogLevel returns the log level from a string representation.
//  Parameters:
//  level is logging level in string representation
//
//  Returns:
//  logging level
func LogLevel(level string) (api.Level, error) {
	return metadata.ParseLevel(level)
}

//ShowCallerInfo - Show caller info in log lines for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
//note: based on implementation of custom logger, callerinfo information may not be available for custom logging provider
func ShowCallerInfo(module string, level api.Level) {
	modlog.ShowCallerInfo(module, level)
}

//HideCallerInfo - Do not show caller info in log lines for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
//note: based on implementation of custom logger, callerinfo information may not be available for custom logging provider
func HideCallerInfo(module string, level api.Level) {
	modlog.HideCallerInfo(module, level)
}

//IsCallerInfoEnabled - returns if caller info enabled for given log level and module
//  Parameters:
//  module is module name
//  level is logging level
//
//  Returns:
//  is caller info enabled for this module and level
func IsCallerInfoEnabled(module string, level api.Level) bool {
	return modlog.IsCallerInfoEnabled(module, level)
}
