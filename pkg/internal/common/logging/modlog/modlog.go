/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

//modLog is a moduled wrapper for api.Logger implementation
//This adds functionality of module based levels on top of provider logger implementation
type modLog struct {
	logger api.Logger
	module string
}

//Fatalf calls underlying logger.Fatal
func (m *modLog) Fatalf(format string, args ...interface{}) {
	m.logger.Fatalf(format, args...)
}

//Panicf calls underlying logger.Panic
func (m *modLog) Panicf(format string, args ...interface{}) {
	m.logger.Panicf(format, args...)
}

//Debugf calls error log function if DEBUG level enabled
func (m *modLog) Debugf(format string, args ...interface{}) {
	opts := getLoggerOpts(m.module, api.DEBUG)
	if !opts.levelEnabled {
		return
	}
	m.logger.Debugf(format, args...)
}

//Infof calls error log function if INFO level enabled
func (m *modLog) Infof(format string, args ...interface{}) {
	opts := getLoggerOpts(m.module, api.INFO)
	if !opts.levelEnabled {
		return
	}
	m.logger.Infof(format, args...)
}

//Warnf calls error log function if WARNING level enabled
func (m *modLog) Warnf(format string, args ...interface{}) {
	opts := getLoggerOpts(m.module, api.WARNING)
	if !opts.levelEnabled {
		return
	}
	m.logger.Warnf(format, args...)
}

//Errorf calls error log function if ERROR level enabled
func (m *modLog) Errorf(format string, args ...interface{}) {
	opts := getLoggerOpts(m.module, api.ERROR)
	if !opts.levelEnabled {
		return
	}
	m.logger.Errorf(format, args...)
}
