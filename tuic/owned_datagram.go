package tuic

import (
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
)

// *buf.Buffer is a valid datagram owner: the transport calls Release exactly once, after the
// payload has been copied into the outgoing packet.
var _ quic.DatagramOwner = (*buf.Buffer)(nil)

// ownedDatagramSender is the part of *quic.Conn this helper needs, so the release contract can be
// tested without a live QUIC connection.
type ownedDatagramSender interface {
	SendDatagramOwned(payload []byte, owner quic.DatagramOwner) error
}

// sendOwnedDatagram sends one packed datagram and transfers ownership of the buffer.
//
// On a nil return the transport owns the payload and will release it after serialization; the
// caller must not touch the buffer again. On an error the transport has taken nothing, so the
// buffer is released here — the caller still has the message and can act on the failure.
func sendOwnedDatagram(sender ownedDatagramSender, payload []byte, owner quic.DatagramOwner) error {
	if err := sender.SendDatagramOwned(payload, owner); err != nil {
		owner.Release()
		return err
	}
	return nil
}
