package tuic

import (
	"errors"
	"testing"

	"github.com/sagernet/quic-go"
)

type ownedSenderFunc func(payload []byte, owner quic.DatagramOwner) error

func (f ownedSenderFunc) SendDatagramOwned(payload []byte, owner quic.DatagramOwner) error {
	return f(payload, owner)
}

type countingOwner struct {
	releases int
}

func (o *countingOwner) Release() { o.releases++ }

func TestSendOwnedDatagramTransfersOwnershipOnSuccess(t *testing.T) {
	owner := &countingOwner{}
	payload := []byte{0x01, 0x02, 0x03}
	var seen []byte
	var seenOwner quic.DatagramOwner
	err := sendOwnedDatagram(ownedSenderFunc(func(p []byte, o quic.DatagramOwner) error {
		seen = p
		seenOwner = o
		return nil
	}), payload, owner)
	if err != nil {
		t.Fatal(err)
	}
	if seenOwner != owner || len(seen) != len(payload) {
		t.Fatalf("the transport must receive the payload and its owner")
	}
	if owner.releases != 0 {
		t.Fatalf("the helper must not release after a successful transfer, released %d times", owner.releases)
	}
}

func TestSendOwnedDatagramReleasesOnError(t *testing.T) {
	owner := &countingOwner{}
	refused := errors.New("refused")
	err := sendOwnedDatagram(ownedSenderFunc(func([]byte, quic.DatagramOwner) error {
		return refused
	}), []byte{0x01}, owner)
	if !errors.Is(err, refused) {
		t.Fatalf("error = %v, want %v", err, refused)
	}
	if owner.releases != 1 {
		t.Fatalf("a refused send must release the payload exactly once, released %d times", owner.releases)
	}
}
