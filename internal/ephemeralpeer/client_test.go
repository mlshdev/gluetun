package ephemeralpeer

import (
	"crypto/mlkem"
	"io"
	"net/http"
	"testing"

	"github.com/cloudflare/circl/kem/mceliece/mceliece460896"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protowire"
)

// encapsulate acts as the relay config service: it encapsulates a shared
// secret for each KEM public key of the request given, and returns the
// ciphertexts and the XOR of the shared secrets.
func encapsulate(t *testing.T, requestMessage []byte) (
	ciphertexts [][]byte, presharedKey wgtypes.Key,
) {
	t.Helper()
	var algorithmNames []string
	err := rangeFields(requestMessage, func(number protowire.Number, _ protowire.Type, value []byte) error {
		if number != 3 {
			return nil
		}
		return rangeFields(value, func(_ protowire.Number, _ protowire.Type, kemPublicKey []byte) error {
			var algorithmName string
			var publicKey []byte
			err := rangeFields(kemPublicKey, func(number protowire.Number, wireType protowire.Type, value []byte) error {
				switch {
				case number == 1 && wireType == protowire.BytesType:
					algorithmName = string(value)
				case number == 2 && wireType == protowire.BytesType:
					publicKey = value
				}
				return nil
			})
			require.NoError(t, err)
			algorithmNames = append(algorithmNames, algorithmName)

			var ciphertext, sharedSecret []byte
			switch algorithmName {
			case "Classic-McEliece-460896f-round3":
				scheme := mceliece460896.Scheme()
				mcEliecePublicKey, err := scheme.UnmarshalBinaryPublicKey(publicKey)
				require.NoError(t, err)
				ciphertext, sharedSecret, err = scheme.Encapsulate(mcEliecePublicKey)
				require.NoError(t, err)
			case "ML-KEM-1024":
				encapsulationKey, err := mlkem.NewEncapsulationKey1024(publicKey)
				require.NoError(t, err)
				sharedSecret, ciphertext = encapsulationKey.Encapsulate()
			default:
				t.Fatalf("unexpected algorithm %q", algorithmName)
			}
			ciphertexts = append(ciphertexts, ciphertext)
			for i := range presharedKey {
				presharedKey[i] ^= sharedSecret[i]
			}
			return nil
		})
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Classic-McEliece-460896f-round3", "ML-KEM-1024"}, algorithmNames)
	return ciphertexts, presharedKey
}

func Test_Client_Register(t *testing.T) {
	t.Parallel()

	parentPublicKey := wgtypes.Key{1}
	ephemeralPublicKey := wgtypes.Key{2}

	testCases := map[string]struct {
		postQuantum bool
		daita       bool
	}{
		"post_quantum": {
			postQuantum: true,
		},
		"daita": {
			daita: true,
		},
		"post_quantum_and_daita": {
			postQuantum: true,
			daita:       true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			presharedKeys := make(chan wgtypes.Key, 1)
			registerURL := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				requestMessage, err := decodeGRPCFrame(body)
				assert.NoError(t, err)

				var responseMessage []byte
				var presharedKey wgtypes.Key
				if testCase.postQuantum {
					var ciphertexts [][]byte
					ciphertexts, presharedKey = encapsulate(t, requestMessage)
					responseMessage = encodePostQuantumResponse(ciphertexts...)
				}
				presharedKeys <- presharedKey
				if testCase.daita {
					responseMessage = appendDaitaResponse(responseMessage, []string{"machine"}, 0.5, 0.25)
				}
				w.Header().Set("Content-Type", "application/grpc")
				_, _ = w.Write(encodeGRPCFrame(responseMessage))
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			})
			client := &Client{httpClient: newHTTPClient(), registerURL: registerURL}

			response, err := client.Register(t.Context(), Request{
				ParentPublicKey:    parentPublicKey,
				EphemeralPublicKey: ephemeralPublicKey,
				PostQuantum:        testCase.postQuantum,
				Daita:              testCase.daita,
			})

			require.NoError(t, err)
			expectedResponse := Response{PresharedKey: <-presharedKeys}
			if testCase.postQuantum {
				assert.NotEqual(t, wgtypes.Key{}, expectedResponse.PresharedKey)
			}
			if testCase.daita {
				expectedResponse.Daita = DaitaConfig{
					Machines:        []string{"machine"},
					MaxPaddingFrac:  0.5,
					MaxBlockingFrac: 0.25,
				}
			}
			assert.Equal(t, expectedResponse, response)
		})
	}
}
