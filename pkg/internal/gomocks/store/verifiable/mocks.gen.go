// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/hyperledger/aries-framework-go/pkg/store/verifiable (interfaces: Store)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	verifiable "github.com/hyperledger/aries-framework-go/component/models/verifiable"
	verifiable0 "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// GetCredential mocks base method.
func (m *MockStore) GetCredential(arg0 string) (*verifiable.Credential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredential", arg0)
	ret0, _ := ret[0].(*verifiable.Credential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockStoreMockRecorder) GetCredential(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockStore)(nil).GetCredential), arg0)
}

// GetCredentialIDByName mocks base method.
func (m *MockStore) GetCredentialIDByName(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredentialIDByName", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredentialIDByName indicates an expected call of GetCredentialIDByName.
func (mr *MockStoreMockRecorder) GetCredentialIDByName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredentialIDByName", reflect.TypeOf((*MockStore)(nil).GetCredentialIDByName), arg0)
}

// GetCredentials mocks base method.
func (m *MockStore) GetCredentials() ([]*verifiable0.Record, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredentials")
	ret0, _ := ret[0].([]*verifiable0.Record)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredentials indicates an expected call of GetCredentials.
func (mr *MockStoreMockRecorder) GetCredentials() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredentials", reflect.TypeOf((*MockStore)(nil).GetCredentials))
}

// GetPresentation mocks base method.
func (m *MockStore) GetPresentation(arg0 string) (*verifiable.Presentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPresentation", arg0)
	ret0, _ := ret[0].(*verifiable.Presentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPresentation indicates an expected call of GetPresentation.
func (mr *MockStoreMockRecorder) GetPresentation(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPresentation", reflect.TypeOf((*MockStore)(nil).GetPresentation), arg0)
}

// GetPresentationIDByName mocks base method.
func (m *MockStore) GetPresentationIDByName(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPresentationIDByName", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPresentationIDByName indicates an expected call of GetPresentationIDByName.
func (mr *MockStoreMockRecorder) GetPresentationIDByName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPresentationIDByName", reflect.TypeOf((*MockStore)(nil).GetPresentationIDByName), arg0)
}

// GetPresentations mocks base method.
func (m *MockStore) GetPresentations() ([]*verifiable0.Record, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPresentations")
	ret0, _ := ret[0].([]*verifiable0.Record)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPresentations indicates an expected call of GetPresentations.
func (mr *MockStoreMockRecorder) GetPresentations() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPresentations", reflect.TypeOf((*MockStore)(nil).GetPresentations))
}

// RemoveCredentialByName mocks base method.
func (m *MockStore) RemoveCredentialByName(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveCredentialByName", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveCredentialByName indicates an expected call of RemoveCredentialByName.
func (mr *MockStoreMockRecorder) RemoveCredentialByName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveCredentialByName", reflect.TypeOf((*MockStore)(nil).RemoveCredentialByName), arg0)
}

// RemovePresentationByName mocks base method.
func (m *MockStore) RemovePresentationByName(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemovePresentationByName", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemovePresentationByName indicates an expected call of RemovePresentationByName.
func (mr *MockStoreMockRecorder) RemovePresentationByName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemovePresentationByName", reflect.TypeOf((*MockStore)(nil).RemovePresentationByName), arg0)
}

// SaveCredential mocks base method.
func (m *MockStore) SaveCredential(arg0 string, arg1 *verifiable.Credential, arg2 ...verifiable0.Opt) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SaveCredential", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveCredential indicates an expected call of SaveCredential.
func (mr *MockStoreMockRecorder) SaveCredential(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveCredential", reflect.TypeOf((*MockStore)(nil).SaveCredential), varargs...)
}

// SavePresentation mocks base method.
func (m *MockStore) SavePresentation(arg0 string, arg1 *verifiable.Presentation, arg2 ...verifiable0.Opt) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SavePresentation", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// SavePresentation indicates an expected call of SavePresentation.
func (mr *MockStoreMockRecorder) SavePresentation(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SavePresentation", reflect.TypeOf((*MockStore)(nil).SavePresentation), varargs...)
}
