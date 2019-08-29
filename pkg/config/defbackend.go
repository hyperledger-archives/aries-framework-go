/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/spf13/viper"
)

// defConfigBackend represents the default config backend
type defConfigBackend struct {
	configViper *viper.Viper
	opts        options
}

// Lookup gets the config item value by Key
func (c *defConfigBackend) Lookup(key string) (interface{}, bool) {
	value := c.configViper.Get(key)
	if value == nil {
		return nil, false
	}
	return value, true
}
