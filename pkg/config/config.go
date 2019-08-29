/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/spf13/viper"
	errors "golang.org/x/xerrors"
)

type options struct {
	envPrefix string
}

const (
	cmdRoot = "ARIES"
)

// Option configures the package.
type Option func(opts *options)

// FromReader loads configuration from in.
// configType can be "json" or "yaml".
func FromReader(in io.Reader, configType string, opts ...Option) api.ConfigProvider {
	return func() (api.ConfigBackend, error) {
		return initFromReader(in, configType, opts...)
	}
}

// FromFile reads from named config file
func FromFile(name string, opts ...Option) api.ConfigProvider {
	return func() (api.ConfigBackend, error) {
		backend := newBackend(opts...)

		if name == "" {
			return nil, errors.New("filename is required")
		}

		// create new viper
		backend.configViper.SetConfigFile(name)

		// If a config file is found, read it in.
		err := backend.configViper.MergeInConfig()
		if err != nil {
			return nil, errors.Errorf("loading config file failed: %w", err)
		}

		return backend, nil
	}
}

func initFromReader(in io.Reader, configType string, opts ...Option) (api.ConfigBackend, error) {
	backend := newBackend(opts...)

	if configType == "" {
		return nil, errors.New("empty config type")
	}

	// read config from bytes array, but must set ConfigType
	// for viper to properly unmarshal the bytes array
	backend.configViper.SetConfigType(configType)
	err := backend.configViper.MergeConfig(in)
	if err != nil {
		return nil, errors.Errorf("viper MergeConfig failed : %w", err)
	}

	return backend, nil
}

// WithEnvPrefix defines the prefix for environment variable overrides.
func WithEnvPrefix(prefix string) Option {
	return func(opts *options) {
		opts.envPrefix = prefix
	}
}

func newBackend(opts ...Option) *defConfigBackend {
	o := options{
		envPrefix: cmdRoot,
	}

	for _, option := range opts {
		option(&o)
	}

	v := newViper(o.envPrefix)

	//default backend for config
	backend := &defConfigBackend{
		configViper: v,
		opts:        o,
	}

	return backend
}

func newViper(cmdRootPrefix string) *viper.Viper {
	myViper := viper.New()
	myViper.SetEnvPrefix(cmdRootPrefix)
	myViper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	myViper.SetEnvKeyReplacer(replacer)
	return myViper
}
