/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lookup

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/spf13/cast"
)

//ConfigProvider provides config backend for aries
type ConfigProvider func() (ConfigBackend, error)

//ConfigBackend backend for all config types in aries
type ConfigBackend interface {
	Lookup(key string) (interface{}, bool)
}

//New providers lookup wrapper around given backend
func New(backends api.ConfigBackend) *ConfigLookup {
	return &ConfigLookup{backend: backends}
}

//ConfigLookup is wrapper for ConfigBackend which performs key lookup and unmarshalling
type ConfigLookup struct {
	backend api.ConfigBackend
}

//Lookup returns value for given key
func (c *ConfigLookup) Lookup(key string) (interface{}, bool) {
	val, ok := c.backend.Lookup(key)
	if ok {
		return val, true
	}
	return nil, false
}

//GetBool returns bool value for given key
func (c *ConfigLookup) GetBool(key string) bool {
	value, ok := c.Lookup(key)
	if !ok {
		return false
	}
	return cast.ToBool(value)
}

//GetString returns string value for given key
func (c *ConfigLookup) GetString(key string) string {
	value, ok := c.Lookup(key)
	if !ok {
		return ""
	}
	return cast.ToString(value)
}

//GetInt returns int value for given key
func (c *ConfigLookup) GetInt(key string) int {
	value, ok := c.Lookup(key)
	if !ok {
		return 0
	}
	return cast.ToInt(value)
}

//GetDuration returns time.Duration value for given key
func (c *ConfigLookup) GetDuration(key string) time.Duration {
	value, ok := c.Lookup(key)
	if !ok {
		return 0
	}
	return cast.ToDuration(value)
}
