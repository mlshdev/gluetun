package multihoptun

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestHeadersRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		local  netip.Addr
		remote netip.Addr
	}{
		"ipv4": {
			local:  netip.MustParseAddr("10.64.0.2"),
			remote: netip.MustParseAddr("185.65.134.1"),
		},
		"ipv6": {
			local:  netip.MustParseAddr("fc00:bbbb:bbbb:bb01::2"),
			remote: netip.MustParseAddr("2a03:1b20::1"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			multihopTun := NewMultihopTun(testCase.local, testCase.remote, 51820, 1400)
			multihopTun.localPort = 12345
			payload := []byte("wireguard payload")
			target := make([]byte, 1500)

			size, err := multihopTun.writePayload(target, payload)
			if err != nil {
				t.Fatalf("writing payload: %s", err)
			}
			if size != multihopTun.headerSize()+len(payload) {
				t.Fatalf("unexpected size %d", size)
			}

			parsed, err := udpPayload(target[:size])
			if err != nil {
				t.Fatalf("parsing payload: %s", err)
			}
			if !bytes.Equal(parsed, payload) {
				t.Fatalf("expected payload %q, got %q", payload, parsed)
			}
		})
	}
}

func TestIPv4HeaderChecksum(t *testing.T) {
	t.Parallel()

	// Example header from https://en.wikipedia.org/wiki/Internet_checksum
	header := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
	}
	const expected = 0xb861
	checksum := ipv4HeaderChecksum(header)
	if checksum != expected {
		t.Fatalf("expected checksum 0x%x, got 0x%x", expected, checksum)
	}
}

func TestUDPPayloadMalformed(t *testing.T) {
	t.Parallel()

	testCases := map[string][]byte{
		"empty":          {},
		"bad_version":    {0x55},
		"short_ipv4":     {0x45, 0x00},
		"short_ipv6":     {0x60, 0x00},
		"ipv4_too_long":  append([]byte{0x45, 0x00, 0xff, 0xff}, make([]byte, 24)...),
		"ipv4_short_udp": append([]byte{0x45, 0x00, 0x00, 0x18}, make([]byte, 20)...),
	}

	for name, packet := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := udpPayload(packet)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
