/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package msghandler

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
)

func TestRegistrar_Register(t *testing.T) {
	tests := []struct {
		testName string
		svcs     []dispatcher.MessageService
		err      string
	}{
		{
			testName: "empty msg services",
		},
		{
			testName: "add multiple msg services on empty list- test success",
			svcs: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test1", "sample-name-01"),
				generic.NewCustomMockMessageSvc("test2", "sample-name-02"),
				generic.NewCustomMockMessageSvc("test3", "sample-name-03"),
			},
		},
		{
			testName: "add multiple msg services on non empty list- test success",
			svcs: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test1", "sample-name-11"),
				generic.NewCustomMockMessageSvc("test2", "sample-name-12"),
				generic.NewCustomMockMessageSvc("test3", "sample-name-13"),
			},
		},
		{
			testName: "add multiple msg services - test duplicate scenario-1",
			svcs: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test1", "sample-name-21"),
				generic.NewCustomMockMessageSvc("test2", "sample-name-11"),
				generic.NewCustomMockMessageSvc("test3", "sample-name-23"),
			},
			err: fmt.Sprintf(errAlreadyRegistered, "sample-name-11"),
		},
		{
			testName: "add multiple msg services - test duplicate scenario-2",
			svcs: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test1", "sample-name-21"),
				generic.NewCustomMockMessageSvc("test2", "sample-name-22"),
				generic.NewCustomMockMessageSvc("test3", "sample-name-23"),
			},
		},
		{
			testName: "add multiple msg services of same type - test success",
			svcs: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test", "sample-name-31"),
				generic.NewCustomMockMessageSvc("test", "sample-name-32"),
				generic.NewCustomMockMessageSvc("test", "sample-name-33"),
			},
		},
	}

	handler := NewRegistrar()
	require.NotNil(t, handler)

	for _, test := range tests {
		tc := test

		t.Run(tc.testName, func(t *testing.T) {
			b4Count := len(handler.services)
			err := handler.Register(tc.svcs...)

			if tc.err != "" {
				require.Error(t, err, "expected error: %s", tc.err)
				require.Contains(t, err.Error(), tc.err)
				require.Len(t, handler.Services(), b4Count)
				return
			}

			require.NoError(t, err)
			require.Len(t, handler.Services(), b4Count+len(tc.svcs))
		})
	}
}

func TestRegistrar_Unregister(t *testing.T) {
	tests := []struct {
		testName      string
		register      []dispatcher.MessageService
		unregister    []string
		err           string
		expectedCount int
	}{
		{
			testName:   "unregister on empty msg services",
			unregister: []string{"sample-name-01"},
			err:        fmt.Sprintf(errNeverRegistered, "sample-name-01"),
		},
		{
			testName: "add multiple msg services on empty list- test success",
			register: []dispatcher.MessageService{
				generic.NewCustomMockMessageSvc("test1", "sample-name-01"),
				generic.NewCustomMockMessageSvc("test2", "sample-name-02"),
				generic.NewCustomMockMessageSvc("test3", "sample-name-03"),
			},
			unregister:    []string{"sample-name-01", "sample-name-02"},
			expectedCount: 1,
		},
		{
			testName:   "unregister on empty msg services",
			unregister: []string{"sample-name-01"},
			err:        fmt.Sprintf(errNeverRegistered, "sample-name-01"),
		},
	}

	handler := NewRegistrar()
	require.NotNil(t, handler)

	for _, test := range tests {
		tc := test

		t.Run(tc.testName, func(t *testing.T) {
			err := handler.Register(tc.register...)
			require.NoError(t, err)

			for _, name := range tc.unregister {
				b4Count := len(handler.services)
				err = handler.Unregister(name)

				if tc.err != "" {
					require.Error(t, err, "expected error: %s", tc.err)
					require.Contains(t, err.Error(), tc.err)
					require.Len(t, handler.Services(), b4Count)
					return
				}

				require.NoError(t, err)
			}

			require.Len(t, handler.Services(), tc.expectedCount)
		})
	}
}
