/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

func TestDeriveKEK_Util(t *testing.T) {
	z, err := DeriveECDHX25519(nil, nil)
	require.EqualError(t, err, "deriveECDHX25519: invalid key")
	require.Empty(t, z)

	validChachaKey, err := base64.RawURLEncoding.DecodeString("c8CSJr_27PN9xWCpzXNmepRndD6neQcnO9DS0YWjhNs")
	require.NoError(t, err)

	chachaKey := new([chacha.KeySize]byte)
	copy(chachaKey[:], validChachaKey)
	z, err = DeriveECDHX25519(chachaKey, nil)
	require.EqualError(t, err, "deriveECDHX25519: invalid key")
	require.Empty(t, z)

	validChachaKey2, err := base64.RawURLEncoding.DecodeString("AAjrHjiFLw6kf6CZ5zqH1ooG3y2aQhuqxmUvqJnIvDI")
	require.NoError(t, err)

	chachaKey2 := new([chacha.KeySize]byte)
	copy(chachaKey2[:], validChachaKey2)
	z, err = DeriveECDHX25519(chachaKey, chachaKey2)
	require.NoError(t, err)
	require.NotEmpty(t, z)

	// lowOrderPoint from golang.org/x/crypto/curve25519.
	// https://github.com/golang/crypto/blob/f4817d981/curve25519/vectors_test.go#L10
	lowOrderPoint := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	chachaKey2 = new([chacha.KeySize]byte)
	copy(chachaKey2[:], lowOrderPoint)
	// test error from curve25519.X25519() call in DeriveECDHX25519()
	_, err = DeriveECDHX25519(chachaKey, chachaKey2)
	require.EqualError(t, err, "deriveECDHX25519: bad input point: low order point")
}

func TestNonceGeneration(t *testing.T) {
	t.Run("Verify nonce against libsodium generated data", func(t *testing.T) {
		data := [][]string{
			{
				"6Gy2UWZCvYcTnpNvQX6ZNhz8FEofrhVxLCEPrjNTTZui", "9mGybrrDfGPdnGXA4BXbzJXnbg2w27bZ1ok6whbJrhF9",
				"EWqT43jjhcy4wJHamH2RFthdLAQhits8F",
			},
			{
				"GJBA64X9GReJrUttG4xQ1dLm726Sn3XQE5hAQeiCZtBV", "kRU8Ef7NTmhijeqKyWzZaZmVAq5UhnpfMfzsBYgBGrV",
				"Kr7Wi5EGyTVNQy44oeFcBJtJJ7dVvXEAL",
			},
			{
				"CYx2Jtgti3Rc45ZCgHMWxSCVYgivwcy2PKcXDpadJz5M", "2gWhujzcfRtpeZhiXeXoARqzCzBESdKUG5DoAzLCzhSY",
				"MZ53sJMYDDtA9JUTFSqmXmD7s7m6hVW2m",
			},
			{
				"At8qPKFRTPzTBjvEUxWzQ3Sc7B3Ywk5G2tEmrzcMWo8C", "2GBiu2FEtSpxDJ4C8bdCUfTfsqW8eb39M985uB85NbC8",
				"6UU5xChzZFsBHgzFMDga8jnLwSqcS46Ln",
			},
			{
				"7rRY74rDVcjghFP9y8fR15xxmZaHBuZnFrYTXwnmwrnE", "CCs3kZHuXSM7mcH5yrXp5bCzMqDsBztqcHsRvgmJBN7D",
				"MPEnkeoVe8X67yBK9k2AZdXHw4e2udx2X",
			},
		}

		for _, datum := range data {
			pub1 := base58.Decode(datum[0])
			pub2 := base58.Decode(datum[1])

			correctNonce := base58.Decode(datum[2])
			testNonce, err := Nonce(pub1, pub2)

			require.NoError(t, err)
			require.ElementsMatch(t, correctNonce, testNonce[:])
		}
	})
}

func TestKeyConversion(t *testing.T) {
	t.Run("Test public key conversion", func(t *testing.T) {
		// Test data generated using GoKillers/libsodium
		edPubs := []string{
			"GV28sQUKYSWdkYtu7h46ACGvjbpL7BUv8TZJr5Lukxra",
			"6a58vqYauxsAU2J1dGXNxTDcC6nPyntxM2bh8YWJBwTW",
			"9UKEhZgwcpbvrfxAyy7hzFzYJvtf48EvmjAfcFUZYLNk",
			"5aa4euy5AGiS9JqDeCTgWqUmFmd64ADKergicwoG2jFU",
			"BF3niopmPgYV6xRmTJMMR88ZMnHeJXoCYiQ4Q9qCMpHU",
			"AdHgkKSDMD3YLYzua8yczqFTeLgYdD6W3LR5wjogEUk9",
			"EFnybhqg65JqfankLNKeQb228dkNcVF1c7vzdtvNaz6J",
			"2HbU7ZiZ398b4SvU6b9GVGE4W3UEjYcTStgvNpPb2oUc",
			"2r4M2aL4YDE2Qy6MzLWb3it93Mt84oSGrPNJ9V6VaAF4",
			"CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz",
			"B7PGAJGqfei7cKFvaaF53uPDVmWBkVyLe5UqmrL3GVmF",
			"CJZRRZyhpz29qf8uBfmUWrHa8G3XwEmtYdwiNyT42XeK",
			"3q99EhPvy4ma62BGztcyabGHtX7sZjBtnfkJyE7JJmF8",
			"8HTpnbCjbFxX8Nwx131eHwJU7dsVaupuPKDtsaeF9phe",
			"89JQa4hvQU3Pk7oY8eBYrZp49ZkpVaZWLHSsxjmq9W1b",
			"EVQM6epVv9ZGkAnPJBX7ns8zS3Nf5EKd9iSpbv5aqCRn",
			"CiNPtf1mfdkEYRGCXiCurCNMjydZjuedbPG9kVgy4UyN",
			"DKS6yB7oGMExmAFKiEAYufDevQuAHCq9UtaKJFmSzJ3k",
			"8UwSjbTo3FwMC4CxqqLJBWik67ubBtE8RRC7FvxjA7xU",
			"Ati3h5YVzWUjdrT956dqYh5NXZaDYqRXoHpp5Htcjxoj",
		}

		curvePubs := []string{
			"8sKzfbhmTnCURJYwTsBvNbXyjNMzKy7kyZNMJe8PspLD",
			"BMKZw7RcyieQHihYMvSGVZ8UFogHjoorWndJnz9L25Hm",
			"D8X75d5pGTiHFYR7m2iqMjQehjd3v8MFejAGP2Mcirzu",
			"3JMxHyQEwnrHhKgemRvCtjp3Z2T9UGVTMXfBKWpNQe3B",
			"3gYHgo7UKQg2CV7RT67yYSRkN7X5UZhL8CTJZefU5i5x",
			"BA1dA5CZuSWPjyGsW94mT2kgUVRBUppiGPkd4M2RdD69",
			"7S8cYe1gd1jWy4DUp3nBVW5TmYXKnGcTMLk3xnhiEp1b",
			"G215pJNTMDWafrDGHenjbAkpWoM3w9dfY5tAbWEx8pyR",
			"37rPhyJfRcZk6v3Lq9kmZJMBUjyvfroniBXMiZdh7PVq",
			"5FmcvFtPrdxD5GJc5P9SpVzvhSNyJDdQGPnrLnzCV64z",
			"73GaEVd6oXEgqPKYmvbFg2jccMG5VLmq65Bn7gS56BRQ",
			"A6W67iKzaohB4LDNa4XsAaHQbbgzdLtmaNPq6TfciRaS",
			"AuANoekPVzVrNn3dbkmvMhRA926Z4rtH96jnksJ26MyK",
			"FD3XcmwNmoZQ1bKfLDyk151kqsh7xVXH5W7GHt9ZJRLJ",
			"5CpahvkR9BTzCtry63UeXgdWJBFdNBXd42trefE6K4jf",
			"3u8zsCK3uipjMrXjpXTWj9me74wLR45YxvN7qmE3aRFb",
			"5u3af9JJQQGSo42wgzeBBfhctoPUYTRXUGCMU64DpqpH",
			"6b2Hc6mxnZTBW9fkNEiDyGNKnt7XuQcbDVzMGoqJfR5Y",
			"DScPyc8TY6pEYWFZxQyhUvUoZEHbEJKxeE23wUS9A6hj",
			"CWY4n7zi6KysyvsVHXtBAW9cQ9esFerxLZfTedfom3mF",
		}

		for i, edKeyString := range edPubs {
			edKey := base58.Decode(edKeyString)

			curveKey := base58.Decode(curvePubs[i])

			convert, err := PublicEd25519toCurve25519(edKey)
			require.NoError(t, err)
			require.ElementsMatch(t, curveKey, convert)
		}
	})

	t.Run("Test private key conversion", func(t *testing.T) {
		// Test data generated using GoKillers/libsodium
		edPrivs := []string{
			"DH43p5VzoVzDkgkQzgzybE9Z2hK8KevuS9x56A6AEKscHBS3ZXaf6hU4kP6VPM421REUoxCssVeif9XCVaGhURS",
			"42LHpaJQCLs1JNANNqvbD5of5MDgsYEtZ4DXRJCouADyc6BGryHSv5BzHvvtFQu21XtMNP3nz5XRWVk2t8BBPS2b",
			"3KsjZqADnZhKy7gb6FmsaWGYAyyawHvoW4RccUfYYTNjG9y1RN8z6FjTQMEhW3rh93Xs4aEGdbbzs9zi63ovzHQm",
			"37uWqrXwpWK19P7EMNw7kXjMucvPSDuJbwjdZrFynebuFJL165w6hH4ergNWVZyB39atHhBjyK1U6WLMPrUL5FB8",
			"2bXak57U5YKF8j2Ked6JoTPJr1SBs7Fap99vL5EjPS69fqsE1gSmG1KLY3tE58CWaRRDf422dtTaJjpYw1tc3xoj",
			"4kR1WSRU3jzDU4EZgZGaf22a9SkoQcWWdYLRAyVDXMBhDGNc4wnREVtKb4rzZ9q6jP7ANCcsqVS7C4DkQ6AKkbAH",
			"3PRatPTTQ5d7Dj5eaLaRvnbE5J28M5s1PSaZ2THmZuvXRo9Piq6dnuXcdxr39ezceCHoHmGRpPwBfKK8dWb7BVi9",
			"5WTFGmXkxJc2p9XTXMwjrqCkTn1SJMCBAGQ3yDKEm9TVQF3nWwLWRneFrXzDzgBYcUo1Mxj3Ym46BYgqQWgLGSTW",
			"2x4qYudE5J2rA9JQFHTHevn4nYaVJtT3f7RCzqWjZ3726tCUHbgzg74QBSzhGbWVpfQhtaRZ8RsMkcnMjGqNzrj5",
			"2QAb1BPVidRV9dxb1BsZ137vXP1fQb2BbCBWo5fb5Tpj8vV1fU2vVake8JSiMBmU8XfcR8yxDmBezzbGQCKeEUds",
			"5e5yq8BzzZ9MYJxkrFX4DDR6RxvwiFP1TqtimpjeQdRF16Cfq1aqVEnKbh6eRAJd7PZXuq9hMYtwLyqCeMSaaTT4",
			"2tHVLALEobsefPsLprDJb7FPZ5Cj9F6zMU6hiVp9LSu2XP5AqCXxvKB18uwo4PHK8DNaAdkQ78diMtb5NBw3p9km",
			"5YCxw8E9kkt46DKRv5SkJ28ZH3DoMJhSHxpPoRQhPNaP3Ve4pJyaBoKotFvpLwuwi2MwjfDMZbkfBFvQKqudrp8Q",
			"277X3QJjmJVXgULzUJ87bYg76tTfnVbufhRCBJJNqBUP1hqPqueXLCKNfDrdp5atdKp18tLkSKT54yt4ef7ZL393",
			"4k7nC7YKkhmTArmKYXBqQWYXAX4wzhNkaWT5RUTbczaj54iAXdUvcoXUjBgK5J5cWbLp7q55sCnv3SwNSKBbPraP",
			"KKP9gymE9GvMn83LGqth7QuD7Vd4vbzsyLqCYgnnLPJdY8VuzciC4cdCvRpHvmGXXFUxyzNe7V97QBD3AxMXyPY",
			"5oST3U3ffd8iamT7QgadQvyPGh58nr9r4CCiMW45ucV8qupDcmMAUFTLiPCKKYX9tPV69qfe2wQLC9x53tzxBrzd",
			"38LdKpmjmed3AwDbKhCfjopoKTibn1WLVBsrGgnbRaw9mcXqRyoemmQgcnqR2au3DhB9hQFVVdbtqBeRJxyqQgwU",
			"2e3votxseb2bhdKHAx2uzgQWVExkz7eAHLF1KTQYiSpVzv6s9PkSu6nUBa1EqJFoJvPKiE1PxUMPvLm7Wc4mFWQ",
			"2Dt3qPTHyVPE4EpN5c62zTX1DQnJtQgbwXrkAHo6fKJYYgjnEA7Ggqie4ZfCukWG8sTvBLCoWbhQSJtV5PzFqLp9",
		}

		curvePrivs := []string{
			"3im72Q16HHqfgqziCKR7dKkZF59ZHEGxqc5nfhFqF223",
			"5sa8TDuj2Ha41Khou9yQ8kAVz6bxjwW1idv5QCbWMEcT",
			"6yCAYLdEcyVadtqCbG3ffMx2PqhE1gXfH3enPMwjbLYD",
			"HB3tAasj3hJQVa12EN9a4Ph7GrRyNPDQH1qMKBgZ8s2s",
			"ZyB9Vd461HHHBKzbXFERBMeauPN7smc8MvBRxjvBLyR",
			"9eSnTQusUh1aYdVhfzHUy1F4QLyHh4UpM3yV37vqoE4J",
			"9fhmCLQhwFSffe7J7iD8QUBtJ15szDGnaynD9A91EAby",
			"5KNPvL9JF7fpAEuuvGYRPRFa1KG68MFU5EWyW4wN5twb",
			"81SrqWepV72qmWrCDtyay6y2bb9SLXYDat7oCYBAb5s8",
			"G5besqGYbhA78K5hjV7umf1PyyhXV8HJhUhk6PypeWZw",
			"84QJE1CBi4h8xBhQMqwFwUuCYGLXFB31NBirfD3ENduJ",
			"3ic7MKSCj6YnfsGXwr2VACXC3CKhK5HxX81p17mWH4t6",
			"9gF459xtS64bFcDpaCZc5Utqm5SkUUEauKQxekRJZHbs",
			"4qF59e48Hq6nq7tKkJQcUHia2hD3iXVpjX91bW2sp1qs",
			"DSDoiSRmL41WQ4Q8RNWoPfeXSQGn4vwQB4ii9zt7VTpq",
			"BpaTEPTgUMr1XSjVAqMj2j8Q6ZvSEsmbruGfypu9XPDh",
			"Ajds6dh1M1MTetjLHzrYRXYZmepVUoJnTz9Q8VhhDBPg",
			"25ctY6ghvZV5RqTCdZySZVEfE6MLu4jEmFoTURDsQxDT",
			"1akW9fT6rNkbVPCrP4SpLXUhYYrKK69gnjZHnFk6adf",
			"18BWLZh74cem5mKbPZ7nqbBQ8zgqigg1BppVDEhMV3d",
		}

		for i, edKeyString := range edPrivs {
			edKey := base58.Decode(edKeyString)
			curveKey := base58.Decode(curvePrivs[i])

			convert, err := SecretEd25519toCurve25519(edKey)
			require.NoError(t, err)

			require.ElementsMatch(t, curveKey, convert)
		}
	})

	t.Run("Fail on converting nil Pub key", func(t *testing.T) {
		_, err := PublicEd25519toCurve25519(nil)
		require.EqualError(t, err, "public key is nil")
	})

	t.Run("Fail on converting Pub key of incorrect length", func(t *testing.T) {
		_, err := PublicEd25519toCurve25519([]byte{1, 2, 3, 4, 5})
		require.EqualError(t, err, "5-byte key size is invalid")
	})

	t.Run("Fail on converting nil Priv key", func(t *testing.T) {
		_, err := SecretEd25519toCurve25519(nil)
		require.EqualError(t, err, "private key is nil")
	})

	t.Run("Fail: invalid pubkey, cannot convert to curve25519", func(t *testing.T) {
		edKeyBytes := base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7")
		_, err := PublicEd25519toCurve25519(edKeyBytes)
		require.EqualError(t, err, "error converting public key")
	})
}
