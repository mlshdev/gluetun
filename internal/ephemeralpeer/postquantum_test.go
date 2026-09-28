package ephemeralpeer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeRunner sends errBeforeReady if set, otherwise signals it is ready
// and waits for its context to be canceled.
type fakeRunner struct {
	errBeforeReady error
}

func (f *fakeRunner) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	if f.errBeforeReady != nil {
		waitError <- f.errBeforeReady
		return
	}
	ready <- struct{}{}
	<-ctx.Done()
	waitError <- ctx.Err()
}

func Test_PostQuantum_Run(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")
	privateKey := wgtypes.Key{1}
	peerPublicKey := wgtypes.Key{2}

	testCases := map[string]struct {
		runnerError    error
		registerOK     bool
		configureError error
		logMessages    []string
		ready          bool
		errWrapped     error
		errMessage     string
	}{
		"runner_error": {
			runnerError: errTest,
			errWrapped:  errTest,
			errMessage:  "test error",
		},
		"register_error": {
			logMessages: []string{"Upgrading to a quantum-resistant tunnel"},
			errWrapped:  errHTTPStatusNotOK,
			errMessage: "upgrading to quantum-resistant tunnel: registering ephemeral peer: " +
				"attempt 1 of 4: HTTP status code is not OK: 502 502 Bad Gateway",
		},
		"configure_error": {
			registerOK:     true,
			configureError: errTest,
			logMessages:    []string{"Upgrading to a quantum-resistant tunnel"},
			errWrapped:     errTest,
			errMessage:     "upgrading to quantum-resistant tunnel: configuring ephemeral peer: test error",
		},
		"success": {
			registerOK: true,
			logMessages: []string{
				"Upgrading to a quantum-resistant tunnel",
				"Quantum-resistant tunnel enabled",
			},
			ready:      true,
			errWrapped: context.Canceled,
			errMessage: "context canceled",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			presharedKeys := make(chan wgtypes.Key, 1)
			registerURL := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if !testCase.registerOK {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				requestMessage, err := decodeGRPCFrame(body)
				assert.NoError(t, err)
				ciphertexts, presharedKey := encapsulate(t, requestMessage)
				presharedKeys <- presharedKey
				w.Header().Set("Content-Type", "application/grpc")
				_, _ = w.Write(encodeGRPCFrame(encodePostQuantumResponse(ciphertexts...)))
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			})

			logger := NewMockLogger(ctrl)
			var previousCall *gomock.Call
			for _, message := range testCase.logMessages {
				call := logger.EXPECT().Info(message)
				if previousCall != nil {
					call.After(previousCall)
				}
				previousCall = call
			}

			configureCalls := 0
			postQuantum := &PostQuantum{
				runner:        &fakeRunner{errBeforeReady: testCase.runnerError},
				client:        &Client{httpClient: newHTTPClient(), registerURL: registerURL},
				interfaceName: "wg0",
				privateKey:    privateKey,
				peerPublicKey: peerPublicKey,
				configureDevice: func(interfaceName string, config wgtypes.Config) error {
					configureCalls++
					assert.Equal(t, "wg0", interfaceName)
					require.NotNil(t, config.PrivateKey)
					presharedKey := <-presharedKeys
					expectedConfig := wgtypes.Config{
						PrivateKey: config.PrivateKey,
						Peers: []wgtypes.PeerConfig{{
							PublicKey:    peerPublicKey,
							UpdateOnly:   true,
							PresharedKey: &presharedKey,
						}},
					}
					assert.Equal(t, expectedConfig, config)
					assert.NotEqual(t, privateKey, *config.PrivateKey)
					return testCase.configureError
				},
				logger: logger,
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			waitError := make(chan error)
			ready := make(chan struct{})
			go postQuantum.Run(ctx, waitError, ready)

			var err error
			select {
			case err = <-waitError:
				assert.False(t, testCase.ready)
			case <-ready:
				assert.True(t, testCase.ready)
				cancel()
				err = <-waitError
			}

			require.ErrorIs(t, err, testCase.errWrapped)
			assert.ErrorContains(t, err, testCase.errMessage)
			expectedConfigureCalls := 0
			if testCase.registerOK {
				expectedConfigureCalls = 1
			}
			assert.Equal(t, expectedConfigureCalls, configureCalls)
		})
	}
}
