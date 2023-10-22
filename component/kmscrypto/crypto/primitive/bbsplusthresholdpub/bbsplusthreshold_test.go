/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsplusthresholdpub_test

import (
	"crypto/rand"
	"encoding/base64"
	mathrand "math/rand"
	"testing"
	"time"

	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
	"github.com/stretchr/testify/require"
)

const (
	threshold = 2 // Security threshold (t-out-of-n)
	n         = 3 // Number of servers
	k         = 1 // Presignature to create
)

// nolint:gochecknoglobals
var curve = ml.Curves[ml.BLS12_381_BBS]

//nolint:lll
func TestBlsG2Pub_Verify(t *testing.T) {
	pkBase64 := "lOpN7uGZWivVIjs0325N/V0dAhoPomrgfXVpg7pZNdRWwFwJDVxoE7TvRyOx/Qr7GMtShNuS2Px/oScD+SMf08t8eAO78QRNErPzwNpfkP4ppcSTShStFDfFbsv9L9yb"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := "hPbLkeMZZ6KKzkjWoTVHeMeuLJfYWjmdAU1Vg5fZ/VZnIXxxeXBB+q0/EL8XQmWkOMMwEGA/D2dCb4MDuntKZpvHEHlvaFR6l1A4bYj0t2Jd6bYwGwCwirNbmSeIoEmJeRzJ1cSvsL+jxvLixdDPnw=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	bls := bbsplusthresholdpub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.Verify(messagesBytes, sigBytes, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// swap messages order
		invalidMessagesBytes := [][]byte{[]byte("message2"), []byte("message1")}

		err = bls.Verify(invalidMessagesBytes, sigBytes, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "invalid BLS12-381 signature")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.Verify(messagesBytes, sigBytes, []byte("invalid"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")

		pkBytesInvalid := make([]byte, len(pkBytes))

		_, err = rand.Read(pkBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(messagesBytes, sigBytes, pkBytesInvalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse public key: deserialize public key")
	})

	t.Run("invalid input signature", func(t *testing.T) {
		err = bls.Verify(messagesBytes, []byte("invalid"), pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature: invalid size of signature")

		sigBytesInvalid := make([]byte, len(sigBytes))

		_, err = rand.Read(sigBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(messagesBytes, sigBytesInvalid, pkBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse signature: deserialize G1 compressed signature")
	})
}

func TestBBSPlusPub_SignWithPartialSignatures(t *testing.T) {
	pubKey, privKey, precomputations, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)
	bls := bbsplusthresholdpub.New()

	messagesBytes := [][]byte{
		[]byte("_:c14n0 <http://purl.org/dc/terms/created> \"2023-10-19T13:25:42.654172871+02:00\"^^<http://www.w3.org/2001/XMLSchema#dateTime> ."),
		[]byte("_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> ."),
		[]byte("_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> ."),
		[]byte("_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:123456#key1> ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> \"1958-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> \"SMITH\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://schema.org/gender> \"Male\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> \"JOHN\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> ."),
		[]byte("<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> ."),
		[]byte("<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> \"Bahamas\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> \"C1\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> \"C09\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> \"999-999-999\" ."),
		[]byte("<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> \"Government of Example Permanent Resident Card.\" ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> \"83627465\" ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> \"Permanent Resident Card\" ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> \"2029-12-03T12:19:52Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> \"2019-12-03T12:19:52Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> ."),
		[]byte("<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> ."),
	}
	indices := generateRandomIndices(threshold, n)
	partialSignatures := make([][]byte, threshold)
	for i := 0; i < threshold; i++ {
		index := indices[i] - 1
		partyPrivKey := precomputations[index].PartyPrivateKey()
		partyPrivKeyBytes, err := partyPrivKey.Marshal()
		require.NoError(t, err)
		require.NotNil(t, partyPrivKeyBytes)

		partyBBS := bbsplusthresholdpub.NewParty()
		partialSignatureBytes, err := partyBBS.SignWithPresignature(messagesBytes,
			partyPrivKeyBytes,
			indices,
			precomputations[index].Presignatures[0])
		require.NoError(t, err)
		require.NotNil(t, partialSignatureBytes)

		partialSignature, err := bbsplusthresholdpub.ParsePartialSignature(partialSignatureBytes)
		require.NoError(t, err)
		require.NotNil(t, partialSignature)

		partialSignatureBytes2, err := partialSignature.ToBytes()
		require.NoError(t, err)
		require.NotNil(t, partialSignatureBytes2)
		require.Equal(t, partialSignatureBytes, partialSignatureBytes2)

		partialSignatures[i] = partialSignatureBytes
	}

	signatureBytes, err := bls.SignWithPartialSignatures(partialSignatures)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signatureBytes2, err := bls.SignWithKey(messagesBytes, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes2)
	require.Len(t, signatureBytes2, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes2, pubKeyBytes))
	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBBSPlusThresholdPub_SignWithKeyPair(t *testing.T) {
	pubKey, privKey, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	bls := bbsplusthresholdpub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	signatureBytes, err := bls.SignWithKey(messagesBytes, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBBSPlusThresholdPub_Sign(t *testing.T) {
	pubKey, privKey, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	bls := bbsplusthresholdpub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	// invalid private key bytes
	signatureBytes, err = bls.Sign(messagesBytes, []byte("invalid"))
	require.Error(t, err)
	require.EqualError(t, err, "unmarshal private key: invalid size of private key")
	require.Nil(t, signatureBytes)

	// at least one message must be passed
	signatureBytes, err = bls.Sign([][]byte{}, privKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "messages are not defined")
	require.Nil(t, signatureBytes)
}

//nolint:lll
func TestBBSPlusThresholdPub_VerifyProof(t *testing.T) {
	pkBase64 := "sVEbbh9jDPGSBK/oT/EeXQwFvNuC+47rgq9cxXKrwo6G7k4JOY/vEcfgZw9Vf/TpArbIdIAJCFMDyTd7l2atS5zExAKX0B/9Z3E/mgIZeQJ81iZ/1HUnUCT2Om239KFx"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	proofBase64 := "AAIBiN4EL9psRsIUlwQah7a5VROD369PPt09Z+jfzamP+/114a5RfWVMju3NCUl2Yv6ahyIdHGdEfxhC985ShlGQrRPLa+crFRiu2pfnAk+L6QMNooVMQhzJc2yYgktHen4QhsKV3IGoRRUs42zqPTP3BdqIPQeLgjDVi1d1LXEnP+WFQGEQmTKWTja4u1MsERdmAAAAdIb6HuFznhE3OByXN0Xp3E4hWQlocCdpExyNlSLh3LxK5duCI/WMM7ETTNS0Ozxe3gAAAAIuALkiwplgKW6YmvrEcllWSkG3H+uHEZzZGL6wq6Ac0SuktQ4n84tZPtMtR9vC1Rsu8f7Kwtbq1Kv4v02ct9cvj7LGcitzg3u/ZO516qLz+iitKeGeJhtFB8ggALcJOEsebPFl12cYwkieBbIHCBt4AAAAAxgEHt3iqKIyIQbTYJvtrMjGjT4zuimiZbtE3VXnqFmGaxVTeR7dh89PbPtsBI8LLMrCvFFpks9D/oTzxnw13RBmMgMlc1bcfQOmE9DZBGB7NCdwOnT7q4TVKhswOITKTQ=="
	proofBytes, err := base64.StdEncoding.DecodeString(proofBase64)
	require.NoError(t, err)

	nonce := []byte("nonce")

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	revealedMessagesBytes := messagesBytes[:1]

	bls := bbsplusthresholdpub.New()

	t.Run("valid signature proof", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})

	t.Run("test payload revealed bigger from messages", func(t *testing.T) {
		wrongProofBytes, errDecode := base64.StdEncoding.DecodeString(`AAwP/4nFun/RtaXtUVTppUimMRTcEROs3gbjh9iqjGQAsvD+ne2uzME26gY4zNBcMKpvyLD4I6UGm8ATKLQI4OUiBXHNCQZI4YEM5hWI7AzhFXLEEVDFL0Gzr4S04PvcJsmV74BqST8iI1HUO2TCjdT1LkhgPabP/Zy8IpnbWUtLZO1t76NFwCV8+R1YpOozTNKRQQAAAHSpyGry6Rx3PRuOZUeqk4iGFq67iHSiBybjo6muud7aUyCxd9AW3onTlV2Nxz8AJD0AAAACB3FmuAUcklAj5cdSdw7VY57y7p4VmfPCKaEp1SSJTJRZXiE2xUqDntend+tkq+jjHhLCk56zk5GoZzr280IeuLne4WgpB2kNN7n5dqRpy4+UkS5+kiorLtKiJuWhk+OFTiB8jFlTbm0dH3O3tm5CzQAAAAIhY6I8vQ96tdSoyGy09wEMCdWzB06GElVHeQhWVw8fukq1dUAwWRXmZKT8kxDNAlp2NS7fXpEGXZ9fF7+c1IJp`)
		require.NoError(t, errDecode)
		err = bls.VerifyProof(revealedMessagesBytes, wrongProofBytes, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "payload revealed bigger from messages")
	})

	t.Run("invalid size of signature proof payload", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, []byte("?"), nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of PoK payload")
	})

	t.Run("invalid size of signature proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, 5)

		copy(proofBytesCopy, proofBytes)

		err = bls.VerifyProof(revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of signature proof")
	})

	t.Run("invalid proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, len(proofBytes))

		copy(proofBytesCopy, proofBytes)
		proofBytesCopy[21] = 255 - proofBytesCopy[21]

		err = bls.VerifyProof(revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.ErrorContains(t, err, "parse signature proof: parse G1 point: failure [set bytes failed")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, []byte("invalid public key"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")
	})
}

//nolint:lll
func TestBBSPlusThresholdPub_VerifyProof_SeveralDisclosedMessages(t *testing.T) {
	pkBase64 := "l0Wtf3gy5f140G5vCoCJw2420hwk6Xw65/DX3ycv1W7/eMky8DyExw+o1s2bmq3sEIJatkiN8f5D4k0766x0UvfbupFX+vVkeqnlOvT6o2cag2osQdMFbBQqAybOM4Gm"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	proofBase64 := "AAQFpAE2VALtmriOzSMk/oqid4uJhPQRUVUuyenL/L4w4ykdyh0jCX64EFqCdLP+n8VrkOKXhHPKPoCOdHBOMv96aM15NFg867/MToMeNN0IFzZkzhs37qk1vWWFKReMF+cRsCAmkHO6An1goNHdY/4XquSV3LwykezraWt8+8bLvVn6ciaXBVxVcYkbIXRsVjqbAAAAdIl/C/W5G1pDbLMrUrBAYdpvzGHG25gktAuUFZb/SkIyy0uhtWJk2v6A+D3zkoEBsgAAAAJY/jfJR9kpGbSY5pfz+qPkqyNOTJbs6OEpfBwYGsyC7hspvBGUOYyvuKlS8SvKAXW7hVawAhYJbvnRwzeiP6P9kbZKtLQZIkRQB+mxRSbMk/0JgE1jApHOlPtgbqI9yIouhK9xT2wVZl79qTAwifonAAAABDTDo5VtXR2gloy+au7ai0wcnnzjMJ6ztQHRI1ApV5VuOQ19TYL7SW+C90p3QSZFQ5gtl90PHaUuEAHIb+7ZgbJvh5sc1DjKfThwPx0Ao0w8+xTbLhNlxvo6VE1cfbiuME+miCAibLgHjksQ8ctl322qnblYJLXiS4lvx/jtGvA3"
	proofBytes, err := base64.StdEncoding.DecodeString(proofBase64)
	require.NoError(t, err)

	nonce := []byte("nonce")

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}
	revealedMessagesBytes := [][]byte{messagesBytes[0], messagesBytes[2]}

	bls := bbsplusthresholdpub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})
}

func TestBBSPlusThresholdPub_DeriveProof(t *testing.T) {
	pubKey, privKey, _, err := generateKeyPairRandom(threshold, n, k)
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}
	bls := bbsplusthresholdpub.New()

	signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	nonce := []byte("nonce")
	revealedIndexes := []int{0, 2}
	proofBytes, err := bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
	require.NoError(t, err)
	require.NotEmpty(t, proofBytes)

	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
	}

	require.NoError(t, bls.VerifyProof(revealedMessages, proofBytes, nonce, pubKeyBytes))

	t.Run("DeriveProof with revealedIndexes larger than revealedMessages count", func(t *testing.T) {
		revealedIndexes = []int{0, 2, 4, 7, 9, 11}
		_, err = bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
		require.EqualError(t, err, "init proof of knowledge signature: invalid size: 6 revealed indexes is "+
			"larger than 4 messages")
	})
}

func generateRandomIndices(threshold, numOfParties int) []int {
	rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	used := make(map[int]bool)

	indices := make([]int, 0)
	for len(indices) < threshold {
		r := rng.Intn(numOfParties) + 1
		if !used[r] {
			used[r] = true
			indices = append(indices, r)
		}
	}
	return indices
}
