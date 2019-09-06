/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestComputeDID(t *testing.T) {
	storedDoc := genesisDoc()
	require.NotNil(t, storedDoc)
	peerDID, err := computeDid(storedDoc)
	require.NoError(t, err)
	require.NotNil(t, peerDID)
	assert.Contains(t, peerDID, "did:peer:11")
}

func TestComputeDIDError(t *testing.T) {
	storedDoc := &did.Doc{ID: "did:peer:11"}
	_, err := computeDid(storedDoc)
	require.Error(t, err)
	assert.Equal(t, err.Error(), "the genesis version must include public keys and authentication")
}

func TestComputeHash(t *testing.T) {
	hash, err := computeHash([]byte("Test"))
	assert.Nil(t, err)
	assert.NotNil(t, hash)
}
func TestComputeHashError(t *testing.T) {
	hash, err := computeHash([]byte(""))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "empty bytes")
	assert.Nil(t, hash)
}
func TestValidateDid(t *testing.T) {
	peerDoc, err := peerDidDoc()
	require.NoError(t, err)
	require.NotNil(t, peerDoc)
	err = validateDID(peerDoc)
	require.NoError(t, err)
}
func TestValidateDIDError(t *testing.T) {
	peerDoc := invalidPeerDIDDoc()
	require.NotNil(t, peerDoc)
	err := validateDID(peerDoc)
	require.Error(t, err)
	require.Equal(t, "did doesnt follow matching regex", err.Error())
}
func TestValidateErrorHashString(t *testing.T) {
	peerDoc := &did.Doc{ID: "did:peer:11-479cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe"}
	err := validateDID(peerDoc)
	require.Error(t, err)
	require.Equal(t, "hash of the doc doesnt match the computed hash", err.Error())
}

func TestValidateDIDRegex(t *testing.T) {
	did1 := &did.Doc{ID: "did:peer:22"}
	err := validateDID(did1)
	require.Error(t, err)
	require.Equal(t, err.Error(), "did doesnt follow matching regex")

	did2 := &did.Doc{ID: "did:sidetree:22"}
	err = validateDID(did2)
	require.Error(t, err)
	require.Equal(t, err.Error(), "did doesnt follow matching regex")

	did3 := &did.Doc{ID: "did:peer:1-*&$*|||"}
	err = validateDID(did3)
	require.Error(t, err)
	require.Equal(t, err.Error(), "did doesnt follow matching regex")
}

func TestNewDoc(t *testing.T) {

	publicKey := []did.PublicKey{
		{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Type:       "Secp256k1VerificationKey2018",
			Controller: "did:example:123456789abcdefghi",
			Value:      []byte(`"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"`),
		},
	}
	auth := []did.VerificationMethod{
		{
			PublicKey: did.PublicKey{
				ID:         "did:example:123456789abcdefghs#key3",
				Type:       "RsaVerificationKey2018",
				Controller: "did:example:123456789abcdefghs",
				Value:      []byte(`"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"`),
			},
		},
	}

	//nolint:lll
	const expectedDID = "did:peer:11-7b22436f6e74657874223a6e756c6c2c224944223a22222c225075626c69634b6579223a5b7b224944223a226469643a6578616d706c653a313233343536373839616263646566676869236b6579732d31222c2254797065223a22536563703235366b31566572696669636174696f6e4b657932303138222c22436f6e74726f6c6c6572223a226469643a6578616d706c653a313233343536373839616263646566676869222c2256616c7565223a22496e4231596d78705930746c65554a68633255314f43493649434a494d304d7951565a32544531324e6d64745455356862544e31566b4671576e426d61324e4b5133644564323561626a5a364d336459625846515669493d227d5d2c2253657276696365223a6e756c6c2c2241757468656e7469636174696f6e223a5b7b225075626c69634b6579223a7b224944223a226469643a6578616d706c653a313233343536373839616263646566676873236b657933222c2254797065223a22527361566572696669636174696f6e4b657932303138222c22436f6e74726f6c6c6572223a226469643a6578616d706c653a313233343536373839616263646566676873222c2256616c7565223a22496e4231596d78705930746c6555686c65434936494349774d6d49354e324d7a4d47526c4e7a59335a6a41344e474e6c4d7a41344d4445324f47566c4d6a6b7a4d44557a596d457a4d3249794d7a566b4e7a45784e6d457a4d6a597a5a4449355a6a45304e5441354d7a5a694e7a4569227d7d5d2c2243726561746564223a6e756c6c2c2255706461746564223a6e756c6c2c2250726f6f66223a6e756c6c7de3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	doc, err := NewDoc(publicKey, auth)
	assert.Nil(t, err)
	assert.Equal(t, doc.ID, expectedDID)
}

func TestNewDocError(t *testing.T) {

	doc, err := NewDoc(nil, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "the genesis version must include public keys and authentication", err.Error())
	assert.Nil(t, doc)
}

// genesisDoc creates the doc without an id
func genesisDoc() *did.Doc {

	//nolint:lll
	pk := []did.PublicKey{
		{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Type:       "Secp256k1VerificationKey2018",
			Controller: "did:example:123456789abcdefghi",
			Value:      []byte(`"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"`),
		},
		{
			ID:         "did:example:123456789abcdefghw#key2",
			Type:       "RsaVerificationKey2018",
			Controller: "did:example:123456789abcdefghw",
			Value:      []byte(`"publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"`),
		},
	}
	auth := []did.VerificationMethod{
		{
			PublicKey: did.PublicKey{
				ID:         "did:example:123456789abcdefghs#key3",
				Type:       "RsaVerificationKey2018",
				Controller: "did:example:123456789abcdefghs",
				Value:      []byte(`"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"`),
			},
		},
	}

	doc := &did.Doc{
		Context:        []string{"https://w3id.org/did/v1", "https://w3id.org/did/v2"},
		PublicKey:      pk,
		Authentication: auth,
		Created:        &time.Time{},
	}
	return &did.Doc{Context: doc.Context, PublicKey: doc.PublicKey, Authentication: doc.Authentication,
		Created: doc.Created}
}

func peerDidDoc() (*did.Doc, error) {
	doc := genesisDoc()
	id, err := computeDid(doc)
	if err != nil {
		return nil, err
	}
	doc.ID = id
	return doc, nil
}

func invalidPeerDIDDoc() *did.Doc {
	doc := genesisDoc()
	doc.ID = "did:peer:11-"

	return doc
}
