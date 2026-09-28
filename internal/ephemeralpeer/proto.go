package ephemeralpeer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// encodeRequest encodes an ephemeralpeer.EphemeralPeerRequestV1 message.
// It requests post-quantum key encapsulation for each KEM key pair given,
// and DAITA v2 for the Linux wireguard-go platform if daita is true, see
// https://github.com/mullvad/mullvadvpn-app/blob/main/talpid-tunnel-config-client/proto/ephemeralpeer.proto
func encodeRequest(parentPublicKey, ephemeralPublicKey []byte,
	kemKeyPairs []kemKeyPair, daita bool,
) []byte {
	const (
		parentPublicKeyField    = 1
		ephemeralPublicKeyField = 2
		postQuantumField        = 3
		daitaV2Field            = 5
	)
	var request []byte
	request = appendBytesField(request, parentPublicKeyField, parentPublicKey)
	request = appendBytesField(request, ephemeralPublicKeyField, ephemeralPublicKey)
	if len(kemKeyPairs) > 0 {
		request = appendBytesField(request, postQuantumField, encodePostQuantumRequest(kemKeyPairs))
	}
	if daita {
		request = appendBytesField(request, daitaV2Field, encodeDaitaRequest())
	}
	return request
}

// encodePostQuantumRequest encodes an ephemeralpeer.PostQuantumRequestV1 message.
func encodePostQuantumRequest(kemKeyPairs []kemKeyPair) []byte {
	const (
		kemPublicKeysField = 1
		algorithmNameField = 1
		keyDataField       = 2
	)
	var postQuantumRequest []byte
	for _, keyPair := range kemKeyPairs {
		var kemPublicKey []byte
		kemPublicKey = protowire.AppendTag(kemPublicKey, algorithmNameField, protowire.BytesType)
		kemPublicKey = protowire.AppendString(kemPublicKey, keyPair.algorithmName)
		kemPublicKey = appendBytesField(kemPublicKey, keyDataField, keyPair.publicKey)
		postQuantumRequest = appendBytesField(postQuantumRequest, kemPublicKeysField, kemPublicKey)
	}
	return postQuantumRequest
}

// encodeDaitaRequest encodes an ephemeralpeer.DaitaRequestV2 message.
func encodeDaitaRequest() []byte {
	const (
		daitaVersionField  = 1
		daitaPlatformField = 2
		daitaVersion       = 2
		platformLinuxWgGo  = 2
	)
	// The DAITA level field is left unset to use the default level 0.
	var daitaRequest []byte
	daitaRequest = protowire.AppendTag(daitaRequest, daitaVersionField, protowire.VarintType)
	daitaRequest = protowire.AppendVarint(daitaRequest, daitaVersion)
	daitaRequest = protowire.AppendTag(daitaRequest, daitaPlatformField, protowire.VarintType)
	daitaRequest = protowire.AppendVarint(daitaRequest, platformLinuxWgGo)
	return daitaRequest
}

func appendBytesField(data []byte, number protowire.Number, value []byte) []byte {
	data = protowire.AppendTag(data, number, protowire.BytesType)
	return protowire.AppendBytes(data, value)
}

var (
	errCiphertextsCount     = errors.New("ciphertexts count mismatch")
	errDaitaResponseMissing = errors.New("DAITA response is missing")
)

// decodeResponse decodes an ephemeralpeer.EphemeralPeerResponseV1 message,
// checking it contains the number of ciphertexts given and, if daita is true,
// the DAITA configuration.
func decodeResponse(data []byte, ciphertextsCount int, daita bool) (
	ciphertexts [][]byte, daitaConfig DaitaConfig, err error,
) {
	const (
		postQuantumField = 1
		daitaField       = 2
	)
	daitaFound := false
	err = rangeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) error {
		switch {
		case number == postQuantumField && wireType == protowire.BytesType:
			ciphertexts, err = decodePostQuantumResponse(value)
			return err
		case number == daitaField && wireType == protowire.BytesType:
			daitaFound = true
			daitaConfig, err = decodeDaitaResponse(value)
			return err
		default:
			return nil
		}
	})
	switch {
	case err != nil:
		return nil, DaitaConfig{}, err
	case len(ciphertexts) != ciphertextsCount:
		return nil, DaitaConfig{}, fmt.Errorf("%w: expected %d and got %d",
			errCiphertextsCount, ciphertextsCount, len(ciphertexts))
	case daita && !daitaFound:
		return nil, DaitaConfig{}, errDaitaResponseMissing
	}
	return ciphertexts, daitaConfig, nil
}

// decodePostQuantumResponse decodes an ephemeralpeer.PostQuantumResponseV1
// message, which contains the ciphertexts in the order of the KEM public keys
// sent in the request.
func decodePostQuantumResponse(data []byte) (ciphertexts [][]byte, err error) {
	const ciphertextsField = 1
	err = rangeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) error {
		if number == ciphertextsField && wireType == protowire.BytesType {
			ciphertexts = append(ciphertexts, value)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("decoding post-quantum response: %w", err)
	}
	return ciphertexts, nil
}

var (
	errMachinesMissing = errors.New("DAITA machines are missing")
	errFractionInvalid = errors.New("fraction is not between 0 and 1")
)

// decodeDaitaResponse decodes an ephemeralpeer.DaitaResponseV2 message.
func decodeDaitaResponse(data []byte) (config DaitaConfig, err error) {
	const (
		clientMachinesField  = 1
		maxPaddingFracField  = 2
		maxBlockingFracField = 3
	)
	err = rangeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) error {
		switch {
		case number == clientMachinesField && wireType == protowire.BytesType:
			config.Machines = append(config.Machines, string(value))
		case number == maxPaddingFracField && wireType == protowire.Fixed64Type:
			config.MaxPaddingFrac = math.Float64frombits(binary.LittleEndian.Uint64(value))
		case number == maxBlockingFracField && wireType == protowire.Fixed64Type:
			config.MaxBlockingFrac = math.Float64frombits(binary.LittleEndian.Uint64(value))
		}
		return nil
	})
	switch {
	case err != nil:
		return DaitaConfig{}, fmt.Errorf("decoding DAITA response: %w", err)
	case len(config.Machines) == 0:
		return DaitaConfig{}, errMachinesMissing
	case !(config.MaxPaddingFrac >= 0 && config.MaxPaddingFrac <= 1):
		return DaitaConfig{}, fmt.Errorf("max padding %w: %v", errFractionInvalid, config.MaxPaddingFrac)
	case !(config.MaxBlockingFrac >= 0 && config.MaxBlockingFrac <= 1):
		return DaitaConfig{}, fmt.Errorf("max blocking %w: %v", errFractionInvalid, config.MaxBlockingFrac)
	}
	return config, nil
}

// rangeFields calls the function given for each field of the protobuf message
// given. For varint and fixed width fields, the value given contains the raw
// little endian encoded bytes. For bytes fields, it contains the bytes content.
func rangeFields(data []byte, fn func(number protowire.Number,
	wireType protowire.Type, value []byte) error,
) error {
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			return fmt.Errorf("parsing field tag: %w", protowire.ParseError(n))
		}
		data = data[n:]

		n = protowire.ConsumeFieldValue(number, wireType, data)
		if n < 0 {
			return fmt.Errorf("parsing field %d value: %w", number, protowire.ParseError(n))
		}
		value := data[:n]
		data = data[n:]

		if wireType == protowire.BytesType {
			value, _ = protowire.ConsumeBytes(value)
		}

		err := fn(number, wireType, value)
		if err != nil {
			return err
		}
	}
	return nil
}
