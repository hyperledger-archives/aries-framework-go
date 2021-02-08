/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"github.com/hyperledger/aries-framework-go/spi/log"
)

func newCallerInfo() *callerInfo {
	return &callerInfo{
		info: map[callerInfoKey]bool{
			{"", log.CRITICAL}: true,
			{"", log.ERROR}:    true,
			{"", log.WARNING}:  true,
			{"", log.INFO}:     true,
			{"", log.DEBUG}:    true,
		},
	}
}

type callerInfoKey struct {
	module string
	level  log.Level
}

// callerInfo maintains module-level based information to show or hide caller info.
type callerInfo struct {
	info map[callerInfoKey]bool
}

// ShowCallerInfo enables caller info for given module and level.
func (l *callerInfo) ShowCallerInfo(module string, level log.Level) {
	l.info[callerInfoKey{module, level}] = true
}

// HideCallerInfo disables caller info for given module and level.
func (l *callerInfo) HideCallerInfo(module string, level log.Level) {
	l.info[callerInfoKey{module, level}] = false
}

// IsCallerInfoEnabled returns if caller info enabled for given module and level.
func (l *callerInfo) IsCallerInfoEnabled(module string, level log.Level) bool {
	show, exists := l.info[callerInfoKey{module, level}]
	if !exists {
		// If no callerinfo setting exists for given module, then look for default
		return l.info[callerInfoKey{"", level}]
	}

	return show
}
