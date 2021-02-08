/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package logger is not expected to be used by the mobile app.
package logger

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/spi/log"
)

// New returns new Logger.
func New(l api.LoggerProvider) *Logger {
	return &Logger{l: l}
}

// Logger describes logger structure.
type Logger struct {
	l api.LoggerProvider
}

// GetLogger returns logger implementation.
func (l *Logger) GetLogger(module string) log.Logger {
	return loggerWrapper{l.l.GetLogger(module)}
}

type loggerWrapper struct {
	api.Logger
}

func (w loggerWrapper) Fatalf(msg string, args ...interface{}) {
	w.Fatal(fmt.Sprintf(msg, args...))
}

func (w loggerWrapper) Panicf(msg string, args ...interface{}) {
	w.Panic(fmt.Sprintf(msg, args...))
}

func (w loggerWrapper) Debugf(msg string, args ...interface{}) {
	w.Debug(fmt.Sprintf(msg, args...))
}

func (w loggerWrapper) Infof(msg string, args ...interface{}) {
	w.Info(fmt.Sprintf(msg, args...))
}

func (w loggerWrapper) Warnf(msg string, args ...interface{}) {
	w.Warn(fmt.Sprintf(msg, args...))
}

func (w loggerWrapper) Errorf(msg string, args ...interface{}) {
	w.Error(fmt.Sprintf(msg, args...))
}
