/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

func newCallerInfo() *callerInfo {
	return &callerInfo{
		info: map[callerInfoKey]bool{
			{"", CRITICAL}: true,
			{"", ERROR}:    true,
			{"", WARNING}:  true,
			{"", INFO}:     true,
			{"", DEBUG}:    true,
		},
	}
}

type callerInfoKey struct {
	module string
	level  Level
}

// callerInfo maintains module-level based information to show or hide caller info
type callerInfo struct {
	info map[callerInfoKey]bool
}

// ShowCallerInfo enables caller info for given module and level
func (l *callerInfo) ShowCallerInfo(module string, level Level) {
	l.info[callerInfoKey{module, level}] = true
}

// HideCallerInfo disables caller info for given module and level
func (l *callerInfo) HideCallerInfo(module string, level Level) {
	l.info[callerInfoKey{module, level}] = false
}

// IsCallerInfoEnabled returns if caller info enabled for given module and level
func (l *callerInfo) IsCallerInfoEnabled(module string, level Level) bool {
	show, exists := l.info[callerInfoKey{module, level}]
	if !exists {
		// If no callerinfo setting exists for given module, then look for default
		return l.info[callerInfoKey{"", level}]
	}

	return show
}
