/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

type callerInfoKey struct {
	module string
	level  api.Level
}

//CallerInfo maintains module-level based information to show or hide caller info
type CallerInfo struct {
	showcaller map[callerInfoKey]bool
}

//ShowCallerInfo enables caller info for given module and level
func (l *CallerInfo) ShowCallerInfo(module string, level api.Level) {
	if l.showcaller == nil {
		l.showcaller = l.getDefaultCallerInfoSetting()
	}
	l.showcaller[callerInfoKey{module, level}] = true
}

//HideCallerInfo disables caller info for given module and level
func (l *CallerInfo) HideCallerInfo(module string, level api.Level) {
	if l.showcaller == nil {
		l.showcaller = l.getDefaultCallerInfoSetting()
	}
	l.showcaller[callerInfoKey{module, level}] = false
}

//IsCallerInfoEnabled returns if caller info enabled for given module and level
func (l *CallerInfo) IsCallerInfoEnabled(module string, level api.Level) bool {

	if l.showcaller == nil {
		//If no callerinfo setting exists, then look for default
		l.showcaller = l.getDefaultCallerInfoSetting()
		return l.showcaller[callerInfoKey{"", level}]
	}

	showcaller, exists := l.showcaller[callerInfoKey{module, level}]
	if !exists {
		//If no callerinfo setting exists for given module, then look for default
		return l.showcaller[callerInfoKey{"", level}]
	}
	return showcaller
}

//getDefaultCallerInfoSetting returns default setting for caller info
func (l *CallerInfo) getDefaultCallerInfoSetting() map[callerInfoKey]bool {
	return map[callerInfoKey]bool{
		{"", api.CRITICAL}: true,
		{"", api.ERROR}:    true,
		{"", api.WARNING}:  true,
		{"", api.INFO}:     true,
		{"", api.DEBUG}:    true,
	}
}
