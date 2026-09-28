package ephemeralpeer

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func Test_encodeRequest(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		kemKeyPairs []kemKeyPair
		daita       bool
		expected    []byte
	}{
		"keys_only": {
			expected: []byte{
				0x0a, 0x02, 0x01, 0x02, // field 1 bytes
				0x12, 0x01, 0x03, // field 2 bytes
			},
		},
		"daita": {
			daita: true,
			expected: []byte{
				0x0a, 0x02, 0x01, 0x02, // field 1 bytes
				0x12, 0x01, 0x03, // field 2 bytes
				0x2a, 0x04, // field 5 message of 4 bytes
				0x08, 0x02, // version 2
				0x10, 0x02, // platform linux_wg_go
			},
		},
		"post_quantum_and_daita": {
			kemKeyPairs: []kemKeyPair{
				{algorithmName: "A", publicKey: []byte{7}},
				{algorithmName: "B", publicKey: []byte{8, 9}},
			},
			daita: true,
			expected: []byte{
				0x0a, 0x02, 0x01, 0x02, // field 1 bytes
				0x12, 0x01, 0x03, // field 2 bytes
				0x1a, 0x11, // field 3 message of 17 bytes
				0x0a, 0x06, // KEM public key message of 6 bytes
				0x0a, 0x01, 'A', // algorithm name
				0x12, 0x01, 0x07, // key data
				0x0a, 0x07, // KEM public key message of 7 bytes
				0x0a, 0x01, 'B', // algorithm name
				0x12, 0x02, 0x08, 0x09, // key data
				0x2a, 0x04, // field 5 message of 4 bytes
				0x08, 0x02, // version 2
				0x10, 0x02, // platform linux_wg_go
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := encodeRequest([]byte{1, 2}, []byte{3}, testCase.kemKeyPairs, testCase.daita)

			assert.Equal(t, testCase.expected, request)
		})
	}
}

func encodePostQuantumResponse(ciphertexts ...[]byte) []byte {
	var postQuantumResponse []byte
	for _, ciphertext := range ciphertexts {
		postQuantumResponse = protowire.AppendTag(postQuantumResponse, 1, protowire.BytesType)
		postQuantumResponse = protowire.AppendBytes(postQuantumResponse, ciphertext)
	}
	data := protowire.AppendTag(nil, 1, protowire.BytesType)
	return protowire.AppendBytes(data, postQuantumResponse)
}

func appendDaitaResponse(data []byte, machines []string,
	maxPaddingFrac, maxBlockingFrac float64,
) []byte {
	var daitaResponse []byte
	for _, machine := range machines {
		daitaResponse = protowire.AppendTag(daitaResponse, 1, protowire.BytesType)
		daitaResponse = protowire.AppendString(daitaResponse, machine)
	}
	daitaResponse = protowire.AppendTag(daitaResponse, 2, protowire.Fixed64Type)
	daitaResponse = protowire.AppendFixed64(daitaResponse, math.Float64bits(maxPaddingFrac))
	daitaResponse = protowire.AppendTag(daitaResponse, 3, protowire.Fixed64Type)
	daitaResponse = protowire.AppendFixed64(daitaResponse, math.Float64bits(maxBlockingFrac))

	data = protowire.AppendTag(data, 2, protowire.BytesType)
	return protowire.AppendBytes(data, daitaResponse)
}

func Test_decodeResponse(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		data             []byte
		ciphertextsCount int
		daita            bool
		ciphertexts      [][]byte
		daitaConfig      DaitaConfig
		errWrapped       error
		errMessage       string
	}{
		"empty": {},
		"empty_daita_expected": {
			daita:      true,
			errWrapped: errDaitaResponseMissing,
			errMessage: "DAITA response is missing",
		},
		"malformed": {
			data:       []byte{0x12},
			errMessage: "parsing field 2 value: unexpected EOF",
		},
		"daita": {
			data:  appendDaitaResponse(nil, []string{"machine1", "machine2"}, 0.5, 0.25),
			daita: true,
			daitaConfig: DaitaConfig{
				Machines:        []string{"machine1", "machine2"},
				MaxPaddingFrac:  0.5,
				MaxBlockingFrac: 0.25,
			},
		},
		"post_quantum": {
			data:             encodePostQuantumResponse([]byte{1}, []byte{2, 3}),
			ciphertextsCount: 2,
			ciphertexts:      [][]byte{{1}, {2, 3}},
		},
		"post_quantum_and_daita": {
			data: appendDaitaResponse(encodePostQuantumResponse([]byte{1}),
				[]string{"machine"}, 0, 1),
			ciphertextsCount: 1,
			daita:            true,
			ciphertexts:      [][]byte{{1}},
			daitaConfig: DaitaConfig{
				Machines:        []string{"machine"},
				MaxBlockingFrac: 1,
			},
		},
		"ciphertexts_missing": {
			data:             appendDaitaResponse(nil, []string{"machine"}, 0, 0),
			ciphertextsCount: 2,
			daita:            true,
			errWrapped:       errCiphertextsCount,
			errMessage:       "ciphertexts count mismatch: expected 2 and got 0",
		},
		"no_machine": {
			data:       appendDaitaResponse(nil, nil, 0, 0),
			daita:      true,
			errWrapped: errMachinesMissing,
			errMessage: "DAITA machines are missing",
		},
		"invalid_padding_fraction": {
			data:       appendDaitaResponse(nil, []string{"machine"}, 1.5, 0),
			daita:      true,
			errWrapped: errFractionInvalid,
			errMessage: "max padding fraction is not between 0 and 1: 1.5",
		},
		"invalid_blocking_fraction": {
			data:       appendDaitaResponse(nil, []string{"machine"}, 0, math.NaN()),
			daita:      true,
			errWrapped: errFractionInvalid,
			errMessage: "max blocking fraction is not between 0 and 1: NaN",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ciphertexts, daitaConfig, err := decodeResponse(testCase.data,
				testCase.ciphertextsCount, testCase.daita)

			if testCase.errWrapped != nil {
				require.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				require.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.ciphertexts, ciphertexts)
			assert.Equal(t, testCase.daitaConfig, daitaConfig)
		})
	}
}
