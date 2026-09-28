package ephemeralpeer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// newHTTPClient returns an HTTP client using HTTP/2 without TLS
// with prior knowledge, as required to reach the relay config service.
// Its timeout is the maximum timeout of a single negotiation attempt.
func newHTTPClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{
		Timeout:   maxAttemptTimeout,
		Transport: &http.Transport{Protocols: protocols},
	}
}

const maxAttemptTimeout = 48 * time.Second

// negotiate sends the ephemeralpeer.EphemeralPeerRequestV1 message given to the
// relay config service and returns the ephemeralpeer.EphemeralPeerResponseV1
// message received. It retries with increasing timeouts, like the official Mullvad client.
func negotiate(ctx context.Context, client *http.Client, registerURL string,
	requestMessage []byte,
) (responseMessage []byte, err error) {
	const (
		initialAttemptTimeout = 8 * time.Second
		maxAttempts           = 4
	)
	attemptTimeout := initialAttemptTimeout
	errs := make([]error, 0, maxAttempts)
	for attempt := range maxAttempts {
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		responseMessage, err = registerPeer(attemptCtx, client, registerURL, requestMessage)
		cancel()
		switch {
		case err == nil:
			return responseMessage, nil
		case ctx.Err() != nil:
			return nil, fmt.Errorf("registering ephemeral peer: %w", ctx.Err())
		}
		errs = append(errs, fmt.Errorf("attempt %d of %d: %w", attempt+1, maxAttempts, err))
		attemptTimeout = min(2*attemptTimeout, maxAttemptTimeout) //nolint:mnd
	}
	return nil, fmt.Errorf("registering ephemeral peer: %w", errors.Join(errs...))
}

var errHTTPStatusNotOK = errors.New("HTTP status code is not OK")

func registerPeer(ctx context.Context, client *http.Client, registerURL string,
	requestMessage []byte,
) (responseMessage []byte, err error) {
	body := encodeGRPCFrame(requestMessage)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("Te", "trailers")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d %s", errHTTPStatusNotOK,
			response.StatusCode, response.Status)
	}

	const maxResponseSize = 1 << 20
	responseData, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Trailers are only populated once the body is fully read.
	err = checkGRPCStatus(response)
	if err != nil {
		return nil, err
	}

	responseMessage, err = decodeGRPCFrame(responseData)
	if err != nil {
		return nil, fmt.Errorf("decoding gRPC frame: %w", err)
	}
	return responseMessage, nil
}

const grpcFrameHeaderSize = 5

// encodeGRPCFrame returns the uncompressed gRPC length-prefixed message,
// see https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
func encodeGRPCFrame(message []byte) []byte {
	frame := make([]byte, grpcFrameHeaderSize+len(message))
	binary.BigEndian.PutUint32(frame[1:grpcFrameHeaderSize], uint32(len(message))) //nolint:gosec
	copy(frame[grpcFrameHeaderSize:], message)
	return frame
}

var (
	errGRPCFrameTooShort   = errors.New("gRPC frame is too short")
	errGRPCFrameCompressed = errors.New("gRPC frame is compressed")
	errGRPCFrameLength     = errors.New("gRPC frame length mismatch")
)

func decodeGRPCFrame(frame []byte) (message []byte, err error) {
	if len(frame) < grpcFrameHeaderSize {
		return nil, fmt.Errorf("%w: %d bytes", errGRPCFrameTooShort, len(frame))
	}

	if frame[0] != 0 {
		return nil, errGRPCFrameCompressed
	}

	length := binary.BigEndian.Uint32(frame[1:grpcFrameHeaderSize])
	message = frame[grpcFrameHeaderSize:]
	if uint64(length) != uint64(len(message)) {
		return nil, fmt.Errorf("%w: header length %d and message length %d",
			errGRPCFrameLength, length, len(message))
	}
	return message, nil
}

var (
	errGRPCStatusMissing = errors.New("gRPC status is missing")
	errGRPCStatusNotOK   = errors.New("gRPC status is not OK")
)

func checkGRPCStatus(response *http.Response) error {
	const grpcStatusKey = "Grpc-Status"
	status := response.Trailer.Get(grpcStatusKey)
	if status == "" { // trailers-only response
		status = response.Header.Get(grpcStatusKey)
	}

	const grpcStatusOK = "0"
	switch status {
	case "":
		return errGRPCStatusMissing
	case grpcStatusOK:
		return nil
	}

	const grpcMessageKey = "Grpc-Message"
	message := response.Trailer.Get(grpcMessageKey)
	if message == "" {
		message = response.Header.Get(grpcMessageKey)
	}
	unescapedMessage, err := url.PathUnescape(message)
	if err == nil {
		message = unescapedMessage
	}
	return fmt.Errorf("%w: code %s: %s", errGRPCStatusNotOK, status, message)
}
