package qtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"

	"github.com/stretchr/testify/require"
)

// The matrix the receive-window split exists to survive: a real QUIC connection on loopback, 1, 10
// and 40 concurrent streams, and three reader behaviours - immediate, throttled, and paused long
// enough that the sender must wait for flow-control credit.
//
// # What is actually under test
//
// The policy lowers the ADVERTISED initial window by up to 7 MiB per stream. That is flow-control
// credit, so the failure it could cause is not a wrong number in a struct: it is a transfer that
// stalls, a stream that never finishes because the receiver never grants more, or a payload that
// arrives truncated when the reader is slow. Each row therefore checks the SHA-256 of every received
// byte and requires the transfer to COMPLETE, under a deadline, with the lowered grant.
//
// The same payload is run at the hysteria2 defaults (8 MiB stream, 20 MiB connection) and at the
// Network Extension policy (1 MiB / 12 MiB), so the comparison is within one process, one binary and
// one loopback path. Nothing here measures throughput as a performance number: loopback has no RTT
// and no loss, so a throughput figure from it would say nothing about a real network.
func TestReceiveWindowsDeliverUnderSlowAndPausedReaders(t *testing.T) {
	serverTLS, clientTLS := loopbackTLSConfigs(t)

	configurations := []struct {
		name    string
		options QUICOptions
	}{
		{name: "hysteria2 defaults", options: QUICOptions{}},
		{name: "Network Extension policy", options: QUICOptions{
			InitialStreamReceiveWindow:     1 << 20,
			InitialConnectionReceiveWindow: 12 << 20,
			MaxStreamReceiveWindow:         8 << 20,
			MaxConnectionReceiveWindow:     20 << 20,
		}},
	}
	// Payload sizes are chosen so that the Network Extension grant is genuinely EXCEEDED on the
	// single-stream and ten-stream rows: a payload that fits inside the initial window would never
	// wait for credit and would test nothing about the change.
	cases := []struct {
		name      string
		streams   int
		payload   int
		behaviour readerBehaviour
	}{
		{name: "1 stream, immediate read", streams: 1, payload: 4 << 20, behaviour: readImmediately},
		{name: "1 stream, throttled read", streams: 1, payload: 2 << 20, behaviour: readThrottled},
		{name: "1 stream, paused then resumed", streams: 1, payload: 2 << 20, behaviour: readAfterPause},
		{name: "10 streams, immediate read", streams: 10, payload: 2 << 20, behaviour: readImmediately},
		{name: "10 streams, paused then resumed", streams: 10, payload: 1 << 20, behaviour: readAfterPause},
		{name: "40 streams, immediate read", streams: 40, payload: 256 << 10, behaviour: readImmediately},
	}

	for _, configuration := range configurations {
		for _, testCase := range cases {
			t.Run(configuration.name+"/"+testCase.name, func(t *testing.T) {
				runLoopbackStreamCase(t, serverTLS, clientTLS, configuration.options, testCase.streams, testCase.payload, testCase.behaviour)
			})
		}
	}
}

// TestReceiveWindowsRejectAnInvertedCeilingOnTheWire is the same path with the caller error the
// normalisation exists for: a ceiling below its grant. ApplyQUICOptions raises the ceiling rather
// than shrinking the grant, and the connection must still complete - a window that can never grow
// is a valid window, but a grant above its ceiling is not something quic-go will negotiate.
func TestReceiveWindowsRejectAnInvertedCeilingOnTheWire(t *testing.T) {
	serverTLS, clientTLS := loopbackTLSConfigs(t)
	runLoopbackStreamCase(t, serverTLS, clientTLS, QUICOptions{
		InitialStreamReceiveWindow:     2 << 20,
		MaxStreamReceiveWindow:         256 << 10,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     512 << 10,
	}, 1, 3<<20, readAfterPause)
}

type readerBehaviour int

const (
	readImmediately readerBehaviour = iota
	readThrottled
	readAfterPause
)

func runLoopbackStreamCase(t *testing.T, serverTLS, clientTLS *tls.Config, options QUICOptions, streams int, payload int, behaviour readerBehaviour) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "listen loopback UDP")
	defer serverConn.Close()

	serverConfig := &quic.Config{}
	ApplyQUICOptions(serverConfig, QUICOptions{})
	listener, err := quic.Listen(serverConn, serverTLS, serverConfig)
	require.NoError(t, err, "listen QUIC")
	defer listener.Close()

	expected := make([]byte, payload)
	_, err = rand.Read(expected)
	require.NoError(t, err, "payload")
	want := sha256.Sum256(expected)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- servePayloadStreams(ctx, listener, expected, streams)
	}()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "listen client UDP")
	defer clientConn.Close()

	clientConfig := &quic.Config{
		// What the sing-quic hysteria2 client presets before it applies this outbound's options.
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 20 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
	}
	ApplyQUICOptions(clientConfig, options)

	conn, err := quic.Dial(ctx, clientConn, listener.Addr(), clientTLS, clientConfig)
	require.NoError(t, err, "dial QUIC")
	defer conn.CloseWithError(0, "")

	for index := 0; index < streams; index++ {
		stream, streamErr := conn.OpenStreamSync(ctx)
		require.NoError(t, streamErr, "open stream %d", index)
		// The stream does not exist on the peer until its first frame arrives, so the request
		// header is what tells the server to start sending. A client that only read would open a
		// stream the server never learns about.
		request := make([]byte, 8)
		binary.BigEndian.PutUint64(request, uint64(len(expected)))
		_, writeErr := stream.Write(request)
		require.NoError(t, writeErr, "request stream %d", index)
		received := readStream(t, ctx, stream, len(expected), behaviour)
		require.Equal(t, want, sha256.Sum256(received),
			"stream %d delivered a different payload under the %d/%d byte windows", index,
			clientConfig.InitialStreamReceiveWindow, clientConfig.InitialConnectionReceiveWindow)
		_ = stream.Close()
	}

	select {
	case serverErr := <-serverDone:
		require.NoError(t, serverErr, "server side")
	case <-ctx.Done():
		t.Fatal("the server never finished serving every stream: the connection stalled")
	}
}

// servePayloadStreams writes the payload on each accepted stream and closes it, so the receiving
// side sees a complete stream with a final size rather than an infinite one.
//
// ONE connection carrying `streams` streams, which is how the real protocols use a QUIC session:
// accepting a connection per stream would put every stream on its own connection and the
// connection-level window would never be exercised at all.
func servePayloadStreams(ctx context.Context, listener *quic.Listener, payload []byte, streams int) error {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	// The connection is deliberately NOT closed here. A QUIC CONNECTION_CLOSE discards unacked
	// stream data, so closing as soon as the writers return races the last STREAM frame and turns a
	// complete transfer into a read error on the peer. The test's client closes the connection once
	// it has read every byte, and listener.Close() reclaims whatever is left.
	var writers sync.WaitGroup
	for index := 0; index < streams; index++ {
		stream, acceptErr := conn.AcceptStream(ctx)
		if acceptErr != nil {
			return acceptErr
		}
		writers.Add(1)
		go func(stream *quic.Stream) {
			defer writers.Done()
			// Read the request header first: until the client's first frame arrives this stream
			// does not exist here at all, so the header is also what announces it.
			request := make([]byte, 8)
			if _, readErr := io.ReadFull(stream, request); readErr != nil {
				return
			}
			wanted := int(binary.BigEndian.Uint64(request))
			if wanted != len(payload) {
				return
			}
			_, _ = stream.Write(payload)
			_ = stream.Close()
		}(stream)
	}
	// Wait for every writer before returning: the deferred CloseWithError would otherwise tear the
	// connection down while the streams are still being written.
	writers.Wait()
	return nil
}

// readStream applies one reader behaviour and returns exactly the bytes it received.
//
// The pause is deliberately longer than one round trip and short enough to keep the test fast: it is
// the window where the sender has filled the advertised credit and is waiting for an update, which
// is the state a paused application puts a memory-constrained receiver in.
func readStream(t *testing.T, ctx context.Context, stream *quic.Stream, size int, behaviour readerBehaviour) []byte {
	t.Helper()
	if behaviour == readAfterPause {
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("canceled while paused")
		}
	}
	buffer := make([]byte, 0, size)
	chunk := make([]byte, 32<<10)
	for {
		read, err := stream.Read(chunk)
		if read > 0 {
			buffer = append(buffer, chunk[:read]...)
			if behaviour == readThrottled {
				select {
				case <-time.After(time.Millisecond):
				case <-ctx.Done():
					t.Fatal("canceled while throttling")
				}
			}
		}
		if err == io.EOF {
			return buffer
		}
		if err != nil {
			select {
			case <-ctx.Done():
				t.Fatalf("read failed after %d of %d bytes: %v", len(buffer), size, err)
			default:
				t.Fatalf("read failed after %d of %d bytes: %v", len(buffer), size, err)
			}
		}
	}
}

// loopbackTLSConfigs builds the two ends of a self-signed loopback handshake. It is generated per
// test run rather than checked in, so no fixture can go stale and nothing about the production trust
// store is implied.
func loopbackTLSConfigs(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate key")

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "serial")

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sing-quic receive window loopback"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create certificate")

	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	nextProtos := []string{"sing-quic/receive-window-test"}

	return &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: nextProtos},
		&tls.Config{InsecureSkipVerify: true, NextProtos: nextProtos}
}
