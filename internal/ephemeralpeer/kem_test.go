package ephemeralpeer

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_derivePresharedKey(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")
	secretA := wgtypes.Key{0b1100, 1}
	secretB := wgtypes.Key{0b1010, 0, 2}

	newKeyPair := func(expectedCiphertext, sharedSecret []byte, err error) kemKeyPair {
		return kemKeyPair{
			algorithmName: "KEM",
			decapsulate: func(ciphertext []byte) ([]byte, error) {
				assert.Equal(t, expectedCiphertext, ciphertext)
				return sharedSecret, err
			},
		}
	}

	testCases := map[string]struct {
		keyPairs     []kemKeyPair
		ciphertexts  [][]byte
		presharedKey wgtypes.Key
		errWrapped   error
		errMessage   string
	}{
		"no_key_pair": {},
		"two_key_pairs": {
			keyPairs: []kemKeyPair{
				newKeyPair([]byte{1}, secretA[:], nil),
				newKeyPair([]byte{2}, secretB[:], nil),
			},
			ciphertexts:  [][]byte{{1}, {2}},
			presharedKey: wgtypes.Key{0b0110, 1, 2},
		},
		"decapsulation_error": {
			keyPairs:    []kemKeyPair{newKeyPair([]byte{1}, nil, errTest)},
			ciphertexts: [][]byte{{1}},
			errWrapped:  errTest,
			errMessage:  "decapsulating KEM ciphertext: test error",
		},
		"invalid_secret_length": {
			keyPairs:    []kemKeyPair{newKeyPair([]byte{1}, []byte{1}, nil)},
			ciphertexts: [][]byte{{1}},
			errWrapped:  errSharedSecretLength,
			errMessage:  "shared secret length is invalid: KEM shared secret has 1 bytes instead of 32",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			presharedKey, err := derivePresharedKey(testCase.keyPairs, testCase.ciphertexts)

			if testCase.errWrapped != nil {
				require.ErrorIs(t, err, testCase.errWrapped)
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.presharedKey, presharedKey)
		})
	}
}

func Test_generateKEMKeyPairs(t *testing.T) {
	t.Parallel()

	keyPairs, err := generateKEMKeyPairs()

	require.NoError(t, err)
	require.Len(t, keyPairs, 2)
	const (
		mcEliecePublicKeySize = 524160
		mlkemPublicKeySize    = 1568
	)
	assert.Equal(t, "Classic-McEliece-460896f-round3", keyPairs[0].algorithmName)
	assert.Len(t, keyPairs[0].publicKey, mcEliecePublicKeySize)
	assert.Equal(t, "ML-KEM-1024", keyPairs[1].algorithmName)
	assert.Len(t, keyPairs[1].publicKey, mlkemPublicKeySize)
}
