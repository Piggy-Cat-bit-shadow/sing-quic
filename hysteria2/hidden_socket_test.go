package hysteria2

import (
	"errors"
	"net"
	"syscall"
	"testing"

	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2/realm"
)

// probeRawConn records that the owner of a hidden socket asked for its file descriptor. The
// fake descriptor is deliberately invalid, so quic-go's datagram check rejects it and this test
// never changes a real socket; what is pinned here is only that the chain of wrappers between
// quic-go and the descriptor is traversed at all.
type probeRawConn struct {
	controls int
}

func (c *probeRawConn) Control(f func(fd uintptr)) error {
	c.controls++
	f(^uintptr(0))
	return nil
}

func (c *probeRawConn) Read(func(fd uintptr) (done bool)) error {
	return errors.New("probe does not read")
}

func (c *probeRawConn) Write(func(fd uintptr) (done bool)) error {
	return errors.New("probe does not write")
}

type probeConn struct {
	net.Conn
	raw *probeRawConn
}

func (c *probeConn) SyscallConn() (syscall.RawConn, error) { return c.raw, nil }

type probePacketConn struct {
	net.PacketConn
	raw *probeRawConn
}

func (c *probePacketConn) SyscallConn() (syscall.RawConn, error) { return c.raw, nil }

// The obfuscation layers used to hide the UDP socket from quic-go entirely: the transport then
// fell back to its basic conn and left the kernel buffers at their defaults, and the per-call
// SetReadBuffer workaround in the client constructors did nothing because those wrappers do not
// forward SetReadBuffer. Sizing now happens at the entry points and walks Upstream() until it
// finds a syscall.Conn, so each of these wrappers must expose the descriptor.
func TestSetDesiredBufferSizesReachesHiddenSocket(t *testing.T) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer udpConn.Close()
	newConnProbe := func() (net.Conn, *probeRawConn) {
		raw := &probeRawConn{}
		return &probeConn{Conn: udpConn, raw: raw}, raw
	}
	newPacketProbe := func() (net.PacketConn, *probeRawConn) {
		raw := &probeRawConn{}
		return &probePacketConn{PacketConn: udpConn, raw: raw}, raw
	}
	testCases := []struct {
		name  string
		build func() (any, *probeRawConn)
	}{
		{"plain conn", func() (any, *probeRawConn) {
			return newConnProbe()
		}},
		{"salamander conn", func() (any, *probeRawConn) {
			conn, raw := newConnProbe()
			return NewSalamanderClientConn(conn, []byte("password")), raw
		}},
		{"gecko conn", func() (any, *probeRawConn) {
			conn, raw := newConnProbe()
			return NewGeckoClientConn(conn, []byte("password"), 0, 1200), raw
		}},
		{"salamander packet conn", func() (any, *probeRawConn) {
			conn, raw := newPacketProbe()
			return NewSalamanderConn(conn, []byte("password")), raw
		}},
		{"gecko packet conn", func() (any, *probeRawConn) {
			conn, raw := newPacketProbe()
			return NewGeckoConn(conn, []byte("password"), 0, 1200), raw
		}},
		{"realm punch conn", func() (any, *probeRawConn) {
			conn, raw := newPacketProbe()
			return NewSalamanderConn(realm.NewPunchPacketConn(conn, 1), []byte("password")), raw
		}},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			conn, raw := testCase.build()
			qtls.SetDesiredBufferSizes(conn)
			if raw.controls == 0 {
				t.Fatal("the socket behind the wrapper was never asked for its descriptor")
			}
		})
	}
}

// A conn without a descriptor must be ignored rather than panic: that is the shape of a
// UDP-over-TCP detour, where the stream socket must also not be sized like a datagram socket.
func TestSetDesiredBufferSizesIgnoresConnWithoutDescriptor(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	qtls.SetDesiredBufferSizes(NewSalamanderClientConn(client, []byte("password")))
}
