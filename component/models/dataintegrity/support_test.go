/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import (
	"errors"

	"github.com/tidwall/gjson"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
)

var errExpected = errors.New("expected error")

const mockSuiteType = "mock-suite-2023"

type mockSuite struct {
	ReqCreatedVal  bool
	CreateProofVal *models.Proof
	CreateProofErr error
	VerifyProofErr error
}

var _ suite.Suite = &mockSuite{}

type mockSuiteInitializer struct {
	mockSuite *mockSuite
	initErr   error
	typeStr   string
}

var _ suite.VerifierInitializer = &mockSuiteInitializer{}
var _ suite.SignerInitializer = &mockSuiteInitializer{}

func jsonEquals(doc1, doc2 []byte) bool {
	if !gjson.ValidBytes(doc1) || !gjson.ValidBytes(doc2) {
		return false
	}

	val1 := gjson.ParseBytes(doc1)
	val2 := gjson.ParseBytes(doc2)

	return deepEqual(val1, val2)
}

func deepEqual(doc1, doc2 gjson.Result) bool {
	if doc1.Type != doc2.Type {
		return false
	}

	switch doc1.Type {
	case gjson.Null, gjson.False, gjson.True:
		return true
	case gjson.String:
		return doc1.Str == doc2.Str
	case gjson.Number:
		return doc1.Num == doc2.Num
	}

	if doc1.IsArray() && doc2.IsArray() {
		arr1 := doc1.Array()
		arr2 := doc2.Array()

		return deepEqArray(arr1, arr2)
	}

	if doc1.IsObject() && doc2.IsObject() {
		obj1 := doc1.Map()
		obj2 := doc2.Map()

		return deepEqObj(obj1, obj2)
	}

	return false
}

func deepEqArray(arr1, arr2 []gjson.Result) bool {
	if len(arr1) != len(arr2) {
		return false
	}

	for i := 0; i < len(arr1); i++ {
		if !deepEqual(arr1[i], arr2[i]) {
			return false
		}
	}

	return true
}

func deepEqObj(obj1, obj2 map[string]gjson.Result) bool {
	if len(obj1) != len(obj2) {
		return false
	}

	for key, val1 := range obj1 {
		val2, ok := obj2[key]
		if !ok {
			return false
		}

		if !deepEqual(val1, val2) {
			return false
		}
	}

	return true
}

func (m *mockSuite) CreateProof([]byte, *models.ProofOptions) (*models.Proof, error) {
	return m.CreateProofVal, m.CreateProofErr
}

func (m *mockSuite) RequiresCreated() bool {
	return m.ReqCreatedVal
}

func (m *mockSuite) VerifyProof([]byte, *models.Proof, *models.ProofOptions) error {
	return m.VerifyProofErr
}

func (m *mockSuiteInitializer) Signer() (suite.Signer, error) {
	return m.mockSuite, m.initErr
}

func (m *mockSuiteInitializer) Verifier() (suite.Verifier, error) {
	return m.mockSuite, m.initErr
}

func (m *mockSuiteInitializer) Type() string {
	return m.typeStr
}
