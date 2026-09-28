package multihoptun

import (
	"encoding/binary"
	"errors"
)

// Hand-written replacement for the gvisor header helpers used upstream, so
// this module does not depend on gvisor.

const (
	ipv4HeaderSize  = 20
	ipv6HeaderSize  = 40
	udpHeaderSize   = 8
	udpProtocol     = 17
	defaultHopLimit = 64
)

var errMalformedPacket = errors.New("malformed IP/UDP packet")

func writeIPv4Header(target []byte, totalLength, id uint16, src, dst []byte) {
	target[0] = 0x45 // version 4, IHL 5 (20 bytes)
	target[1] = 0    // TOS
	binary.BigEndian.PutUint16(target[2:4], totalLength)
	binary.BigEndian.PutUint16(target[4:6], id)
	binary.BigEndian.PutUint16(target[6:8], 0) // flags and fragment offset
	target[8] = defaultHopLimit
	target[9] = udpProtocol
	binary.BigEndian.PutUint16(target[10:12], 0)
	copy(target[12:16], src)
	copy(target[16:20], dst)
	binary.BigEndian.PutUint16(target[10:12], ipv4HeaderChecksum(target[:ipv4HeaderSize]))
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func writeIPv6Header(target []byte, payloadLength uint16, flowLabel uint32, src, dst []byte) {
	const flowLabelMask = 0x000fffff
	binary.BigEndian.PutUint32(target[0:4], 6<<28|flowLabel&flowLabelMask)
	binary.BigEndian.PutUint16(target[4:6], payloadLength)
	target[6] = udpProtocol
	target[7] = defaultHopLimit
	copy(target[8:24], src)
	copy(target[24:40], dst)
}

// writeUDPHeader writes the UDP header with a zero checksum. Wireguard devices
// reading from this tun device never verify the UDP checksum.
func writeUDPHeader(target []byte, srcPort, dstPort, length uint16) {
	binary.BigEndian.PutUint16(target[0:2], srcPort)
	binary.BigEndian.PutUint16(target[2:4], dstPort)
	binary.BigEndian.PutUint16(target[4:6], length)
	binary.BigEndian.PutUint16(target[6:8], 0)
}

// udpPayload returns the UDP payload of the IPv4 or IPv6 packet given.
func udpPayload(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errMalformedPacket
	}

	var udp []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < ipv4HeaderSize {
			return nil, errMalformedPacket
		}
		headerLength := int(packet[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLength < ipv4HeaderSize || totalLength < headerLength || totalLength > len(packet) {
			return nil, errMalformedPacket
		}
		udp = packet[headerLength:totalLength]
	case 6:
		if len(packet) < ipv6HeaderSize {
			return nil, errMalformedPacket
		}
		end := ipv6HeaderSize + int(binary.BigEndian.Uint16(packet[4:6]))
		if end > len(packet) {
			return nil, errMalformedPacket
		}
		udp = packet[ipv6HeaderSize:end]
	default:
		return nil, errMalformedPacket
	}

	if len(udp) < udpHeaderSize {
		return nil, errMalformedPacket
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < udpHeaderSize || udpLength > len(udp) {
		return nil, errMalformedPacket
	}
	return udp[udpHeaderSize:udpLength], nil
}
