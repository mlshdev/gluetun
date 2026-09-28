package ephemeralpeer

import (
	"context"
	"fmt"
	"net/http"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Client registers ephemeral peers with the Mullvad relay config service,
// which is only reachable within a Wireguard tunnel to a Mullvad relay.
type Client struct {
	httpClient  *http.Client
	registerURL string
}

func New() *Client {
	// registerPeerURL is the gRPC ephemeralpeer.EphemeralPeer/RegisterPeerV1 method
	// of the Mullvad relay config service.
	const registerPeerURL = "http://10.64.0.1:1337/ephemeralpeer.EphemeralPeer/RegisterPeerV1"
	return &Client{
		httpClient:  newHTTPClient(),
		registerURL: registerPeerURL,
	}
}

type Request struct {
	// ParentPublicKey is the public key of the Wireguard tunnel in use,
	// through which the request is sent.
	ParentPublicKey wgtypes.Key
	// EphemeralPublicKey is the public key to register as ephemeral peer.
	EphemeralPublicKey wgtypes.Key
	// PostQuantum requests a pre-shared key derived from post-quantum
	// key encapsulation mechanisms.
	PostQuantum bool
	// Daita requests DAITA machines for the ephemeral peer.
	Daita bool
}

type Response struct {
	// PresharedKey is the pre-shared key to use with the ephemeral peer.
	// It is the zero key if post-quantum was not requested.
	PresharedKey wgtypes.Key
	// Daita is the DAITA configuration, only set if DAITA was requested.
	Daita DaitaConfig
}

// DaitaConfig is the DAITA configuration negotiated with the relay config service.
type DaitaConfig struct {
	Machines        []string
	MaxPaddingFrac  float64
	MaxBlockingFrac float64
}

// Register registers the ephemeral public key of the request with the relay
// config service, and returns the pre-shared key and DAITA configuration
// to use with the ephemeral peer, depending on the request.
func (c *Client) Register(ctx context.Context, request Request) (response Response, err error) {
	var kemKeyPairs []kemKeyPair
	if request.PostQuantum {
		kemKeyPairs, err = generateKEMKeyPairs()
		if err != nil {
			return Response{}, fmt.Errorf("generating post-quantum key pairs: %w", err)
		}
	}

	requestMessage := encodeRequest(request.ParentPublicKey[:], request.EphemeralPublicKey[:],
		kemKeyPairs, request.Daita)
	responseMessage, err := negotiate(ctx, c.httpClient, c.registerURL, requestMessage)
	if err != nil {
		return Response{}, err
	}

	ciphertexts, daitaConfig, err := decodeResponse(responseMessage, len(kemKeyPairs), request.Daita)
	if err != nil {
		return Response{}, fmt.Errorf("decoding response: %w", err)
	}
	response.Daita = daitaConfig

	if request.PostQuantum {
		response.PresharedKey, err = derivePresharedKey(kemKeyPairs, ciphertexts)
		if err != nil {
			return Response{}, fmt.Errorf("deriving pre-shared key: %w", err)
		}
	}
	return response, nil
}
