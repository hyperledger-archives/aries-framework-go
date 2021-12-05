/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didrotate

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	defaultKID = "#key-1"
	oldDID     = "did:test:old"
	newDID     = "did:test:new"
	myDID      = "did:test:mine"
	theirDID   = "did:test:theirs"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		_ = createBlankDIDRotator(t)
	})

	t.Run("failure", func(t *testing.T) {
		_, err := New(&mockProvider{
			storeProvider: &mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf("open store error")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "open store error")
	})
}

func TestDIDRotator_HandleInboundMessage(t *testing.T) {
	t.Run("not didcomm v2", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		// didcomm v1 message
		msg := service.DIDCommMsgMap{
			"@id":   "12345",
			"@type": "abc",
		}

		err := dr.HandleInboundMessage(msg, "", "")
		require.NoError(t, err)

		// invalid didcomm message
		msg = service.DIDCommMsgMap{
			"foo": "12345",
			"bar": "abc",
		}

		err = dr.HandleInboundMessage(msg, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a valid didcomm v1 or v2 message")
	})

	t.Run("bad from_prior", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		// from_prior not a string
		msg := service.DIDCommMsgMap{
			"id":         "12345",
			"type":       "abc",
			"body":       map[string]interface{}{},
			"from_prior": []string{"abc", "def"},
		}

		err := dr.HandleInboundMessage(msg, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "field should be a string")

		// from_prior not a JWS
		msg = service.DIDCommMsgMap{
			"id":         "12345",
			"type":       "abc",
			"body":       map[string]interface{}{},
			"from_prior": "#$&@(*#^@(*#^",
		}

		err = dr.HandleInboundMessage(msg, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing DID rotation JWS")
	})

	sender := createBlankDIDRotator(t)
	senderDoc := createMockDoc(t, sender, myDID)
	senderConnID := uuid.New().String()

	e := sender.connStore.SaveConnectionRecord(&connection.Record{
		ConnectionID: senderConnID,
		State:        connection.StateNameCompleted,
		TheirDID:     theirDID,
		MyDID:        myDID,
		Namespace:    connection.MyNSPrefix,
	})
	require.NoError(t, e)

	setResolveDocs(sender, []*did.Doc{senderDoc})

	e = sender.RotateConnectionDID(senderConnID, defaultKID, newDID)
	require.NoError(t, e)

	senderConnRec, e := sender.connStore.GetConnectionRecord(senderConnID)
	require.NoError(t, e)

	blankMessage := service.DIDCommMsgMap{
		"id":   "12345",
		"type": "abc",
	}

	rotateMessage, e := sender.HandleOutboundMessage(blankMessage.Clone(), senderConnRec)
	require.NoError(t, e)

	t.Run("fail: can't rotate without prior connection", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		err := recip.HandleInboundMessage(rotateMessage, newDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound message cannot rotate without an existing prior connection")
	})

	t.Run("fail: error reading connection record", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		connStore, err := connection.NewRecorder(&mockProvider{
			storeProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				ErrQuery: fmt.Errorf("store error"),
				ErrGet:   fmt.Errorf("store error"),
			}),
		})
		require.NoError(t, err)

		recip.connStore = connStore

		err = recip.HandleInboundMessage(rotateMessage, newDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "looking up did rotation connection record")
	})

	t.Run("fail: from_prior JWS validation error", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		err := recip.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: senderConnID,
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
		})
		require.NoError(t, err)

		err = recip.HandleInboundMessage(rotateMessage, newDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "'from_prior' validation")
	})

	t.Run("fail: recipient rotated, but received message addressed to wrong DID", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		err := recip.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: uuid.New().String(),
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
			MyDIDRotation: &connection.DIDRotationRecord{
				OldDID:    "did:test:recipient-old",
				NewDID:    theirDID,
				FromPrior: "",
			},
		})
		require.NoError(t, err)

		err = recip.HandleInboundMessage(blankMessage, myDID, "did:oops:wrong")
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound message sent to unexpected DID")
	})

	t.Run("fail: error saving connection record", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		connID := uuid.New().String()

		connRec := &connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
			MyDIDRotation: &connection.DIDRotationRecord{
				OldDID:    "did:test:recipient-old",
				NewDID:    theirDID,
				FromPrior: "",
			},
		}

		var err error

		mockStore := mockstorage.MockStore{Store: map[string]mockstorage.DBEntry{}}

		recip.connStore, err = connection.NewRecorder(&mockProvider{
			storeProvider: mockstorage.NewCustomMockStoreProvider(&mockStore),
		})
		require.NoError(t, err)

		err = recip.connStore.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		mockStore.ErrPut = fmt.Errorf("store error")

		err = recip.HandleInboundMessage(blankMessage, myDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "updating connection with DID rotation")
	})

	t.Run("success: pass-through, no rotation on either end", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		err := recip.HandleInboundMessage(blankMessage, myDID, theirDID)
		require.NoError(t, err)
	})
}

func TestDIDRotator_HandleOutboundMessage(t *testing.T) {
	t.Run("not didcomm v2 message", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		// didcomm v1 message
		msg := service.DIDCommMsgMap{
			"@id":   "12345",
			"@type": "abc",
		}

		_, err := dr.HandleOutboundMessage(msg, &connection.Record{})
		require.NoError(t, err)

		// invalid didcomm message
		msg = service.DIDCommMsgMap{
			"foo": "12345",
			"bar": "abc",
		}

		_, err = dr.HandleOutboundMessage(msg, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a valid didcomm v1 or v2 message")
	})
}

func TestDIDRotator_RotateConnectionDID(t *testing.T) {
	t.Run("fail: get connection record", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		err := dr.RotateConnectionDID("not an ID", "foo", "did:some:thing")
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting connection record")
	})

	t.Run("fail: resolve signing did doc", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		connID := uuid.New().String()

		err := dr.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
			TheirDID:     "did:test:them",
			MyDID:        "did:test:me",
			Namespace:    connection.MyNSPrefix,
		})
		require.NoError(t, err)

		err = dr.RotateConnectionDID(connID, "foo", "did:some:thing")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolving my DID")
	})

	t.Run("fail: creating did rotation JWS", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		connID := uuid.New().String()

		drDID := "did:test:me"

		err := dr.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
			TheirDID:     "did:test:them",
			MyDID:        drDID,
			Namespace:    connection.MyNSPrefix,
		})
		require.NoError(t, err)

		doc := createMockDoc(t, dr, drDID)
		setResolveDocs(dr, []*did.Doc{doc})

		err = dr.RotateConnectionDID(connID, "foo", "did:some:thing")
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating did rotation from_prior")
	})

	t.Run("fail: saving updated connection record", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		connID := uuid.New().String()

		drDID := "did:test:me"

		var err error

		mockStore := mockstorage.MockStore{Store: map[string]mockstorage.DBEntry{}}

		dr.connStore, err = connection.NewRecorder(&mockProvider{
			storeProvider: mockstorage.NewCustomMockStoreProvider(&mockStore),
		})
		require.NoError(t, err)

		err = dr.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
			TheirDID:     "did:test:them",
			MyDID:        drDID,
			Namespace:    connection.MyNSPrefix,
		})
		require.NoError(t, err)

		mockStore.ErrPut = fmt.Errorf("store error")

		doc := createMockDoc(t, dr, drDID)
		setResolveDocs(dr, []*did.Doc{doc})

		err = dr.RotateConnectionDID(connID, defaultKID, "did:some:thing")
		require.Error(t, err)
		require.Contains(t, err.Error(), "saving connection record")
	})
}

func TestDIDRotator_Create(t *testing.T) {
	t.Run("fail: KID not in doc", func(t *testing.T) {
		dr := createBlankDIDRotator(t)
		doc := createMockDoc(t, dr, oldDID)

		_, err := dr.Create(doc, "#oops", newDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "KID not found in doc")
	})

	t.Run("fail: unsupported VM type", func(t *testing.T) {
		dr := createBlankDIDRotator(t)
		doc2 := &did.Doc{
			ID: oldDID,
			VerificationMethod: []did.VerificationMethod{
				{
					ID:         defaultKID,
					Type:       "oops",
					Controller: oldDID,
					Value:      nil,
				},
			},
		}

		_, err := dr.Create(doc2, defaultKID, newDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vm.Type 'oops' not supported")
	})

	t.Run("fail: kms get key handle error", func(t *testing.T) {
		dr := createBlankDIDRotator(t)
		doc := createMockDoc(t, dr, oldDID)

		dr.kms = &mockkms.KeyManager{
			GetKeyErr: fmt.Errorf("kms error"),
		}

		_, err := dr.Create(doc, defaultKID, newDID)

		require.Error(t, err)
		require.Contains(t, err.Error(), "get signing key handle")
	})

	t.Run("fail: signing error", func(t *testing.T) {
		dr := createBlankDIDRotator(t)
		doc := createMockDoc(t, dr, oldDID)

		cr := mockcrypto.Crypto{
			SignErr: fmt.Errorf("sign error"),
		}

		dr.crypto = &cr

		_, err := dr.Create(doc, defaultKID, newDID)

		require.Error(t, err)
		require.Contains(t, err.Error(), "creating DID rotation JWS")
	})
}

func TestDIDRotator_CreateVerify(t *testing.T) {
	dr := createBlankDIDRotator(t)

	doc := createMockDoc(t, dr, oldDID)

	setResolveDocs(dr, []*did.Doc{doc})

	t.Run("success", func(t *testing.T) {
		sig, err := dr.Create(doc, defaultKID, newDID)
		require.NoError(t, err)

		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{doc})

		testOldDID, err := verifier.Verify(newDID, sig)
		require.NoError(t, err)
		require.Equal(t, oldDID, testOldDID)
	})

	t.Run("verify failure: bad jws", func(t *testing.T) {
		_, err := dr.Verify(newDID, "*$&W#)(@&*(^")

		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing DID rotation JWS")
	})

	t.Run("verify failure: verifier can't resolve doc", func(t *testing.T) {
		sig, err := dr.Create(doc, defaultKID, newDID)
		require.NoError(t, err)

		verifier := createBlankDIDRotator(t)

		_, err = verifier.Verify(newDID, sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolving prior DID doc")
	})
}

func Test_RoundTrip(t *testing.T) {
	me := createBlankDIDRotator(t)
	them := createBlankDIDRotator(t)

	oldDoc := createMockDoc(t, me, oldDID)
	newDoc := createMockDoc(t, me, newDID)
	theirDoc := createMockDoc(t, them, theirDID)

	setResolveDocs(me, []*did.Doc{oldDoc, newDoc, theirDoc})
	setResolveDocs(them, []*did.Doc{oldDoc, newDoc, theirDoc})

	myConnID := uuid.New().String()

	err := me.connStore.SaveConnectionRecord(&connection.Record{
		ConnectionID: myConnID,
		State:        connection.StateNameCompleted,
		TheirDID:     theirDID,
		MyDID:        oldDID,
		Namespace:    connection.MyNSPrefix,
	})
	require.NoError(t, err)

	theirConnID := uuid.New().String()

	err = them.connStore.SaveConnectionRecord(&connection.Record{
		ConnectionID: theirConnID,
		State:        connection.StateNameCompleted,
		TheirDID:     oldDID,
		MyDID:        theirDID,
		Namespace:    connection.MyNSPrefix,
	})
	require.NoError(t, err)

	sendMessage(t, me, them, myConnID)

	err = me.RotateConnectionDID(myConnID, defaultKID, newDID)
	require.NoError(t, err)

	// if I don't send a message after rotating, then I expect their response to be sent to my old DID...
	sendMessage(t, them, me, theirConnID)

	// ...so my connection record should still have the from_prior.
	myConnRec, err := me.connStore.GetConnectionRecord(myConnID)
	require.NoError(t, err)
	require.NotNil(t, myConnRec.MyDIDRotation)
	require.NotEqual(t, "", myConnRec.MyDIDRotation.FromPrior)

	// but if I send a message after rotating, they should update their connection with my rotation...
	sendMessage(t, me, them, myConnID)
	sendMessage(t, me, them, myConnID) // sending a second message, so they handle after already processing our rotation

	// ...so after I get a response to my *new* DID...
	sendMessage(t, them, me, theirConnID)

	// ...my connection record should no longer have the from_prior.
	myConnRec, err = me.connStore.GetConnectionRecord(myConnID)
	require.NoError(t, err)
	require.Nil(t, myConnRec.MyDIDRotation)
}

func TestDIDRotator_getUnverifiedJWS(t *testing.T) {
	t.Run("fail: can't parse JWS", func(t *testing.T) {
		jws := "(^#$*(#$^&*"

		dr := createBlankDIDRotator(t)

		_, _, err := dr.getUnverifiedJWS("foo", jws)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing DID rotation JWS")
	})

	t.Run("fail: can't parse payload", func(t *testing.T) {
		jws, err := jose.NewJWS(
			jose.Headers{"alg": "blahblah"}, nil, []byte("abcdefg"), &mockSigner{})
		require.NoError(t, err)

		sig, err := jws.SerializeCompact(false)
		require.NoError(t, err)

		dr := createBlankDIDRotator(t)

		_, _, err = dr.getUnverifiedJWS("foo", sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing DID rotation payload")
	})

	t.Run("fail: payload missing iss or sub", func(t *testing.T) {
		jws, err := jose.NewJWS(
			jose.Headers{"alg": "blahblah"}, nil, []byte("{}"), &mockSigner{})
		require.NoError(t, err)

		sig, err := jws.SerializeCompact(false)
		require.NoError(t, err)

		dr := createBlankDIDRotator(t)

		_, _, err = dr.getUnverifiedJWS("foo", sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload missing iss or sub")
	})

	t.Run("fail: payload subject mismatch", func(t *testing.T) {
		jws, err := jose.NewJWS(jose.Headers{"alg": "blahblah"}, nil,
			[]byte(`{"iss":"abc","sub":"def"}`), &mockSigner{})
		require.NoError(t, err)

		sig, err := jws.SerializeCompact(false)
		require.NoError(t, err)

		dr := createBlankDIDRotator(t)

		_, _, err = dr.getUnverifiedJWS("foo", sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload sub must be the DID of the message sender")
	})
}

func TestDIDRotator_verifyJWSAndPayload(t *testing.T) {
	rotator := createBlankDIDRotator(t)
	oldDID := "did:test:rotator"
	newDID := "did:test:new"
	doc := createMockDoc(t, rotator, oldDID)
	setResolveDocs(rotator, []*did.Doc{doc})

	fromPrior, e := rotator.Create(doc, defaultKID, newDID)
	require.NoError(t, e)

	t.Run("success", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{doc})

		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.NoError(t, err)
	})

	t.Run("fail: JWS headers missing KID", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		err := verifier.verifyJWSAndPayload(&jose.JSONWebSignature{
			ProtectedHeaders: jose.Headers{},
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "protected headers missing KID")
	})

	t.Run("fail: resolving signer DID doc", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolving prior DID doc")
	})

	t.Run("fail: selecting verification method from signer DID doc", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{doc})
		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		jws.ProtectedHeaders["kid"] = "AAAAAAAAAA"

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "kid not found in doc")
	})

	t.Run("fail: did doc VM has unsupported type", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{{
			ID: oldDID,
			VerificationMethod: []did.VerificationMethod{
				{
					ID:         defaultKID,
					Type:       "oops",
					Controller: oldDID,
					Value:      nil,
				},
			},
		}})

		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vm.Type 'oops' not supported")
	})

	t.Run("fail: kms get key handle error", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{doc})

		verifier.kms = &mockkms.KeyManager{
			PubKeyBytesToHandleErr: fmt.Errorf("kms error"),
		}

		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get verification key handle")
	})

	t.Run("fail: signature verification error", func(t *testing.T) {
		verifier := createBlankDIDRotator(t)
		setResolveDocs(verifier, []*did.Doc{doc})

		verifier.crypto = &mockcrypto.Crypto{
			VerifyErr: fmt.Errorf("verify error"),
		}

		jws, payload, err := verifier.getUnverifiedJWS(newDID, fromPrior)
		require.NoError(t, err)

		err = verifier.verifyJWSAndPayload(jws, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification")
	})
}

func createBlankDIDRotator(t *testing.T) *DIDRotator {
	t.Helper()

	kmsStorage, err := localkms.New("local-lock://test/master/key/", &mockProvider{
		storeProvider: mockstorage.NewMockStoreProvider(),
		secretLock:    &noop.NoLock{},
	})
	require.NoError(t, err)

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	vdr := &mockvdr.MockVDRegistry{
		CreateFunc: func(didID string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return nil, fmt.Errorf("not created")
		},
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return nil, fmt.Errorf("not found")
		},
	}

	dr, err := New(&mockProvider{
		kms:           kmsStorage,
		crypto:        cr,
		vdr:           vdr,
		storeProvider: mockstorage.NewMockStoreProvider(),
	})
	require.NoError(t, err)

	return dr
}

func createMockDoc(t *testing.T, dr *DIDRotator, docDID string) *did.Doc {
	t.Helper()

	keyType := kms.ECDSAP384TypeIEEEP1363

	return createMockDocOfType(t, dr, docDID, keyType)
}

func createMockDocOfType(t *testing.T, dr *DIDRotator, docDID string, keyType kms.KeyType) *did.Doc {
	t.Helper()

	_, pkb, err := dr.kms.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	var pkJWK *jwk.JWK

	var vm *did.VerificationMethod

	if keyType == kms.ED25519Type {
		vm = &did.VerificationMethod{
			ID:         defaultKID,
			Controller: docDID,
			Type:       ed25519VerificationKey2018,
			Value:      pkb,
		}
	} else {
		pkJWK, err = jwkkid.BuildJWK(pkb, keyType)
		require.NoError(t, err)

		pkJWK.Algorithm = "ECDSA"

		vm, err = did.NewVerificationMethodFromJWK(defaultKID, jsonWebKey2020, docDID, pkJWK)
		require.NoError(t, err)
	}

	newDoc := &did.Doc{
		ID: docDID,
		VerificationMethod: []did.VerificationMethod{
			*vm,
		},
	}

	return newDoc
}

func setResolveDocs(dr *DIDRotator, docs []*did.Doc) {
	dr.vdr = &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			for _, doc := range docs {
				if didID == doc.ID {
					return &did.DocResolution{DIDDocument: doc}, nil
				}
			}

			return nil, vdrapi.ErrNotFound
		},
	}
}

func sendMessage(t *testing.T, sender, recipient *DIDRotator, senderConnID string) {
	t.Helper()

	msgTemplate := service.DIDCommMsgMap{
		"id":   "12345",
		"type": "message",
		"body": map[string]interface{}{},
	}

	myConnRec, err := sender.connStore.GetConnectionRecord(senderConnID)
	require.NoError(t, err)

	msg, err := sender.HandleOutboundMessage(msgTemplate, myConnRec)
	require.NoError(t, err)

	err = recipient.HandleInboundMessage(msg, myConnRec.MyDID, myConnRec.TheirDID)
	require.NoError(t, err)
}

type mockProvider struct {
	kms           kms.KeyManager
	crypto        crypto.Crypto
	storeProvider storage.Provider
	secretLock    secretlock.Service
	vdr           vdrapi.Registry
}

func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.vdr
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storeProvider
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}

func (m *mockProvider) Crypto() crypto.Crypto {
	return m.crypto
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.kms
}

func (m *mockProvider) ProtocolStateStorageProvider() storage.Provider {
	return m.storeProvider
}

type mockSigner struct{}

// Sign mock sign.
func (m *mockSigner) Sign(data []byte) ([]byte, error) {
	return data, nil
}

// Headers returns nil.
func (m *mockSigner) Headers() jose.Headers {
	return nil
}
