package multihoptun

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/conn"
	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/tun"
)

// This is a special implementation of `tun.Device` that allows to connect a
// `conn.Bind` from one WireGuard device to another's `tun.Device`. This way,
// we can create a multi-hop WireGuard device that can use the same private key
// and elude any MTU issues, since, for any single user packet, there is only
// ever a single read from the real tunnel device needed to send it to the
// entry hop.
//
// tun.Device.Write will push a buffer via writeRecv to be read by the recvfunc
// of conn.Bind, stripping IPv4/IPv6 + UDP headers in the process. When the
// packets have been transferred to the UDP receiver, writeDone will be used to
// return from tun.Device.Write. Conversely, conn.Bind.Send will push a buffer
// via readRecv to be read by tun.Device.Read, adding valid IPv4/IPv6 + UDP
// headers in the process.
//
// Implements tun.Device and can create instances of conn.Bind.
type MultihopTun struct {
	readRecv       chan packetBatch
	writeRecv      chan packetBatch
	isIpv4         bool
	localIp        []byte
	localPort      uint16
	remoteIp       []byte
	remotePort     uint16
	ipConnectionId uint16
	tunEvent       chan tun.Event
	mtu            int
	endpoint       conn.Endpoint
	closed         atomic.Bool
	shutdownChan   chan struct{}
}

type packetBatch struct {
	packet []byte
	size   int
	offset int
	// to be used to return the packet batch back to tun.Read and tun.Write
	completion chan packetBatch
}

func (pb *packetBatch) Size() int {
	return len(pb.packet)
}

func NewMultihopTun(local, remote netip.Addr, remotePort uint16, mtu int) MultihopTun {
	readRecv := make(chan packetBatch)
	writeRecv := make(chan packetBatch)
	endpoint, err := conn.NewStdNetBind().ParseEndpoint(netip.AddrPortFrom(remote, remotePort).String())
	if err != nil {
		panic("Failed to parse endpoint")
	}

	connectionId := uint16(rand.Uint32()>>16) | 1
	shutdownChan := make(chan struct{})

	return MultihopTun{
		readRecv,
		writeRecv,
		local.Is4(),
		local.AsSlice(),
		0,
		remote.AsSlice(),
		remotePort,
		connectionId,
		make(chan tun.Event),
		mtu,
		endpoint,
		atomic.Bool{},
		shutdownChan,
	}
}

func (st *MultihopTun) Binder() conn.Bind {
	socketShutdown := make(chan struct{})
	return &multihopBind{
		st,
		socketShutdown,
	}

}

// Events implements tun.Device.
func (st *MultihopTun) Events() <-chan tun.Event {
	return st.tunEvent
}

// File implements tun.Device.
func (*MultihopTun) File() *os.File {
	return nil
}

// MTU implements tun.Device.
func (st *MultihopTun) MTU() (int, error) {
	return st.mtu, nil
}

// Name implements tun.Device.
func (*MultihopTun) Name() (string, error) {
	return "stun", nil
}

// Write implements tun.Device.
func (st *MultihopTun) Write(packet []byte, offset int) (int, error) {
	completion := make(chan packetBatch)
	packetBatch := packetBatch{
		packet:     packet,
		offset:     offset,
		size:       len(packet),
		completion: completion,
	}

	select {
	case st.writeRecv <- packetBatch:
		break
	case <-st.shutdownChan:
		return 0, io.EOF
	}

	packetBatch, ok := <-completion

	if !ok {
		return 0, io.EOF
	}

	return packetBatch.size, nil
}

// Read implements tun.Device.
func (st *MultihopTun) Read(packet []byte, offset int) (n int, err error) {
	completion := make(chan packetBatch)
	packetBatch := packetBatch{
		packet:     packet,
		size:       0,
		offset:     offset,
		completion: completion,
	}

	select {
	case st.readRecv <- packetBatch:
		break
	case <-st.shutdownChan:
		return 0, io.EOF
	}

	var ok bool
	packetBatch, ok = <-completion

	if !ok {
		return 0, io.EOF
	}

	return packetBatch.size, nil
}

func (st *MultihopTun) writePayload(target, payload []byte) (size int, err error) {
	headerSize := st.headerSize()
	if headerSize+len(payload) > len(target) {
		err = errors.New(fmt.Sprintf("target buffer is too small, need %d, got %d", headerSize+len(payload), len(target)))
		return
	}

	if st.isIpv4 {
		return st.writeV4Payload(target, payload)
	} else {
		return st.writeV6Payload(target, payload)
	}
}

func (st *MultihopTun) writeV4Payload(target, payload []byte) (size int, err error) {
	size = st.headerSize() + len(payload)
	writeIPv4Header(target, uint16(size), st.ipConnectionId, st.localIp, st.remoteIp)
	st.writeUdpPayload(target[ipv4HeaderSize:], payload)
	return size, nil
}

func (st *MultihopTun) writeV6Payload(target, payload []byte) (size int, err error) {
	size = st.headerSize() + len(payload)
	writeIPv6Header(target, uint16(udpHeaderSize+len(payload)), uint32(st.ipConnectionId), st.localIp, st.remoteIp)
	st.writeUdpPayload(target[ipv6HeaderSize:], payload)
	return size, nil
}

func (st *MultihopTun) writeUdpPayload(target, payload []byte) {
	writeUDPHeader(target, st.localPort, st.remotePort, uint16(udpHeaderSize+len(payload)))
	copy(target[udpHeaderSize:], payload)
}

func (st *MultihopTun) headerSize() int {
	if st.isIpv4 {
		return ipv4HeaderSize + udpHeaderSize
	}
	return ipv6HeaderSize + udpHeaderSize
}

// BatchSize implements conn.Bind.
func (*MultihopTun) BatchSize() int {
	return 128
}

// BatchSize implements conn.Bind.
func (*MultihopTun) Flush() error {
	return nil
}

// Close implements tun.Device
func (st *MultihopTun) Close() error {
	if st.closed.CompareAndSwap(false, true) {
		close(st.shutdownChan)
	}
	return nil
}
