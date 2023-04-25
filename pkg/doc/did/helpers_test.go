/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go/component/models/did"

	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
)

func TestContextCleanup(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var c0 Context = "stringval"
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, c0, c1)
	})

	t.Run("[]string", func(t *testing.T) {
		var c0 Context = []string{"stringval"}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, c0, c1)
	})

	t.Run("[]string empty", func(t *testing.T) {
		var c0 Context = []string{""}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, c0, c1)
	})

	t.Run("[]string nil", func(t *testing.T) {
		var c0 Context = []string{}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, []string{""}, c1)
	})

	t.Run("[]interface{} nil value", func(t *testing.T) {
		var c0 Context = []interface{}{}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, "", c1)
	})

	t.Run("[]interface{} all strings", func(t *testing.T) {
		var c0 Context = []interface{}{"alpha", "beta"}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, []string{"alpha", "beta"}, c1)
	})

	t.Run("[]interface{} with map", func(t *testing.T) {
		var c0 Context = []interface{}{map[string]interface{}{"@key": "value"}}
		var c1 Context = ContextCleanup(c0)
		require.Equal(t, c0, c1)
	})
}

func TestContextCopy(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var c0 Context = "stringval"
		var c1 Context = ContextCopy(c0)
		require.Equal(t, c0, c1)
	})

	t.Run("[]string", func(t *testing.T) {
		var c0 Context = []string{"stringval"}
		var c1 Context = ContextCopy(c0)
		require.Equal(t, c0, c1)

		p0, p1 := reflect.ValueOf(c0).Pointer(), reflect.ValueOf(c1).Pointer()
		require.NotEqual(t, p0, p1, "slices should not share pointers")
	})

	t.Run("[]interface{}", func(t *testing.T) {
		var c0 Context = []interface{}{map[string]interface{}{"@key": "value"}}
		var c1 Context = ContextCopy(c0)
		require.Equal(t, c0, c1)

		p0, p1 := reflect.ValueOf(c0).Pointer(), reflect.ValueOf(c1).Pointer()
		require.NotEqual(t, p0, p1, "slices should not share pointers")

		a0, ok := c0.([]interface{})
		require.True(t, ok)

		a1, ok := c1.([]interface{})
		require.True(t, ok)

		p0, p1 = reflect.ValueOf(a0[0]).Pointer(), reflect.ValueOf(a1[0]).Pointer()
		require.NotEqual(t, p0, p1, "maps should not share pointers")
	})
}

func TestContextPeekString(t *testing.T) {
	const (
		DoNotWant = "ContextDoNotWant"
		Want      = "ContextWant"
	)

	tests := map[string]struct {
		schema string
		ok     bool
		input  Context
	}{
		"present in 'string'":                   {schema: Want, ok: true, input: Want},
		"present in '[]string' (single)":        {schema: Want, ok: true, input: []string{Want}},
		"present in '[]string' (multiple)":      {schema: Want, ok: true, input: []string{Want, DoNotWant}},
		"present in '[]interface{}' (single)":   {schema: Want, ok: true, input: []interface{}{Want}},
		"present in '[]interface{}' (multiple)": {schema: Want, ok: true, input: []interface{}{Want, DoNotWant}},
		"not present in 'string'":               {schema: "", ok: false, input: ""},
		"not present in '[]string'":             {schema: "", ok: false, input: []string{}},
		"not present in '[]interface{}'":        {schema: "", ok: false, input: []interface{}{}},
		"context is nil":                        {schema: "", ok: false, input: nil},
		"context is invalid":                    {schema: "", ok: false, input: 42},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			schema, ok := ContextPeekString(tc.input)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.schema, schema)
		})
	}
}

func TestContextContainsString(t *testing.T) {
	const (
		DoNotWant = "ContextDoNotWant"
		Want      = "ContextWant"
	)

	tests := map[string]struct {
		ok    bool
		input Context
	}{
		"present in 'string'":                    {ok: true, input: Want},
		"present in '[]string' (first)":          {ok: true, input: []string{Want}},
		"present in '[]string' (not first)":      {ok: true, input: []string{DoNotWant, Want}},
		"present in '[]interface{}' (first)":     {ok: true, input: []interface{}{Want}},
		"present in '[]interface{}' (not first)": {ok: true, input: []interface{}{DoNotWant, Want}},
		"present in '[]interface{}' (map)":       {ok: false, input: []interface{}{map[string]interface{}{"k": Want}}},
		"not present in 'string'":                {ok: false, input: DoNotWant},
		"not present in '[]string'":              {ok: false, input: []string{DoNotWant}},
		"not present in '[]interface{}'":         {ok: false, input: []interface{}{DoNotWant}},
		"context is nil":                         {ok: false, input: nil},
		"context is invalid":                     {ok: false, input: 42},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ok := ContextContainsString(tc.input, Want)
			require.Equal(t, tc.ok, ok)
		})
	}
}

func TestGetRecipientKeys(t *testing.T) {
	t.Run("successfully getting recipient keys", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.True(t, ok)
		require.Equal(t, 1, len(recipientKeys))
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service = nil

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})

	t.Run("error due to missing recipient keys in did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})
}

func TestGetDidCommService(t *testing.T) {
	didCommServiceType := "did-communication"

	t.Run("successfully getting did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, 0, s.Priority)
	})

	t.Run("successfully getting did-communication service - switch order", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		service := didDoc.Service[0]
		didDoc.Service[0] = didDoc.Service[1]
		didDoc.Service[1] = service

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, 0, s.Priority)
	})

	t.Run("successfully getting did-communication service - first priority nil", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[0].Priority = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, 1, s.Priority)
	})

	t.Run("successfully getting did-communication service - second priority nil", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[1].Priority = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, 0, s.Priority)
	})

	t.Run("successfully getting did-communication service - both nil", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[0].Priority = nil
		didDoc.Service[1].Priority = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, nil, s.Priority)

		uri, err := s.ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, "https://localhost:8090", uri)
	})

	t.Run("error due to missing service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[0].Type = "some-type"
		didDoc.Service[1].Type = "other-type"

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})
}
