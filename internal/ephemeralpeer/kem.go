package ephemeralpeer

import (
	"crypto/mlkem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mceliece/mceliece460896"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// kemKeyPair is a post-quantum key encapsulation mechanism key pair.
type kemKeyPair struct {
	// algorithmName is the algorithm name expected by the relay config service.
	algorithmName string
	publicKey     []byte
	decapsulate   func(ciphertext []byte) (sharedSecret []byte, err error)
}

// generateKEMKeyPairs generates the key pairs of the key encapsulation mechanisms
// used by the official Mullvad mullvad-upgrade-tunnel program, see
// https://github.com/mullvad/wgephemeralpeer
func generateKEMKeyPairs() (keyPairs []kemKeyPair, err error) {
	// The McEliece "f" variant only speeds up key generation, so its keys and
	// ciphertexts are compatible with the non "f" variant implemented by circl.
	mcElieceScheme := mceliece460896.Scheme()
	mcEliecePublicKey, mcEliecePrivateKey, err := mcElieceScheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating Classic McEliece key pair: %w", err)
	}
	mcEliecePublicKeyData, err := mcEliecePublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encoding Classic McEliece public key: %w", err)
	}

	mlkemKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("generating ML-KEM key pair: %w", err)
	}

	return []kemKeyPair{
		{
			algorithmName: "Classic-McEliece-460896f-round3",
			publicKey:     mcEliecePublicKeyData,
			decapsulate: func(ciphertext []byte) (sharedSecret []byte, err error) {
				return mcElieceScheme.Decapsulate(mcEliecePrivateKey, ciphertext)
			},
		},
		{
			algorithmName: "ML-KEM-1024",
			publicKey:     mlkemKey.EncapsulationKey().Bytes(),
			decapsulate:   mlkemKey.Decapsulate,
		},
	}, nil
}

var errSharedSecretLength = errors.New("shared secret length is invalid")

// derivePresharedKey decapsulates each ciphertext with the key pair at the same
// index, and returns the XOR of all the shared secrets as Wireguard pre-shared key.
// The ciphertexts slice must have the same length as the key pairs slice.
func derivePresharedKey(keyPairs []kemKeyPair, ciphertexts [][]byte) (
	presharedKey wgtypes.Key, err error,
) {
	for i, keyPair := range keyPairs {
		sharedSecret, err := keyPair.decapsulate(ciphertexts[i])
		switch {
		case err != nil:
			return wgtypes.Key{}, fmt.Errorf("decapsulating %s ciphertext: %w",
				keyPair.algorithmName, err)
		case len(sharedSecret) != wgtypes.KeyLen:
			return wgtypes.Key{}, fmt.Errorf("%w: %s shared secret has %d bytes instead of %d",
				errSharedSecretLength, keyPair.algorithmName, len(sharedSecret), wgtypes.KeyLen)
		}
		for j := range presharedKey {
			presharedKey[j] ^= sharedSecret[j]
		}
	}
	return presharedKey, nil
}
