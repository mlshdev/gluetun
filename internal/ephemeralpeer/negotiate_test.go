package ephemeralpeer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (registerURL string) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	return server.URL + "/ephemeralpeer.EphemeralPeer/RegisterPeerV1"
}

func Test_negotiate(t *testing.T) {
	t.Parallel()

	requestMessage := []byte{1, 2, 3}
	responseMessage := []byte{4, 5}
	validResponse := encodeGRPCFrame(responseMessage)

	testCases := map[string]struct {
		handler         func(attempt int32, w http.ResponseWriter)
		attempts        int32
		responseMessage []byte
		errWrapped      error
		errMessage      string
	}{
		"success": {
			handler: func(_ int32, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/grpc")
				_, _ = w.Write(validResponse)
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			},
			attempts:        1,
			responseMessage: responseMessage,
		},
		"success_after_retry": {
			handler: func(attempt int32, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/grpc")
				if attempt == 1 {
					w.Header().Set("Grpc-Status", "14")
					return
				}
				_, _ = w.Write(validResponse)
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			},
			attempts:        2,
			responseMessage: responseMessage,
		},
		"grpc_error": {
			handler: func(_ int32, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Grpc-Status", "7")
				w.Header().Set("Grpc-Message", "peer%20not%20found")
			},
			attempts:   4,
			errWrapped: errGRPCStatusNotOK,
			errMessage: "registering ephemeral peer: attempt 1 of 4: gRPC status is not OK: code 7: peer not found",
		},
		"http_error": {
			handler: func(_ int32, w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadGateway)
			},
			attempts:   4,
			errWrapped: errHTTPStatusNotOK,
			errMessage: "attempt 4 of 4: HTTP status code is not OK: 502 502 Bad Gateway",
		},
		"grpc_status_missing": {
			handler: func(_ int32, w http.ResponseWriter) {
				_, _ = w.Write(validResponse)
			},
			attempts:   4,
			errWrapped: errGRPCStatusMissing,
			errMessage: "gRPC status is missing",
		},
		"bad_frame": {
			handler: func(_ int32, w http.ResponseWriter) {
				_, _ = w.Write([]byte{1, 0, 0, 0, 0})
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			},
			attempts:   4,
			errWrapped: errGRPCFrameCompressed,
			errMessage: "decoding gRPC frame: gRPC frame is compressed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var attempts atomic.Int32
			registerURL := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				attempt := attempts.Add(1)
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/grpc", r.Header.Get("Content-Type"))
				assert.Equal(t, "trailers", r.Header.Get("Te"))
				assert.Equal(t, 2, r.ProtoMajor)
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, encodeGRPCFrame(requestMessage), body)
				testCase.handler(attempt, w)
			})

			message, err := negotiate(t.Context(), newHTTPClient(), registerURL, requestMessage)

			if testCase.errWrapped != nil {
				require.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				require.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.responseMessage, message)
			assert.Equal(t, testCase.attempts, attempts.Load())
		})
	}
}

func Test_negotiate_canceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	registerURL := newTestServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		cancel()
	})

	_, err := negotiate(ctx, newHTTPClient(), registerURL, []byte{1})

	require.ErrorIs(t, err, context.Canceled)
	assert.EqualError(t, err, "registering ephemeral peer: context canceled")
}

func Test_decodeGRPCFrame(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		frame      []byte
		message    []byte
		errWrapped error
		errMessage string
	}{
		"too_short": {
			frame:      []byte{0, 0},
			errWrapped: errGRPCFrameTooShort,
			errMessage: "gRPC frame is too short: 2 bytes",
		},
		"length_mismatch": {
			frame:      []byte{0, 0, 0, 0, 2, 1},
			errWrapped: errGRPCFrameLength,
			errMessage: "gRPC frame length mismatch: header length 2 and message length 1",
		},
		"empty_message": {
			frame:   []byte{0, 0, 0, 0, 0},
			message: []byte{},
		},
		"valid": {
			frame:   encodeGRPCFrame([]byte{7, 8}),
			message: []byte{7, 8},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			message, err := decodeGRPCFrame(testCase.frame)

			if testCase.errWrapped != nil {
				require.ErrorIs(t, err, testCase.errWrapped)
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.message, message)
		})
	}
}
