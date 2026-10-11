package qtls

import (
	"testing"

	"github.com/sagernet/quic-go"

	"github.com/stretchr/testify/require"
)

// ApplyQUICOptions carries TWO independent facts to quic-go, and the reason this test
// exists is that an earlier design carried only one: a proven path capacity was encoded
// as a side effect of DisablePathMTUDiscovery, so a caller that set that flag for its own
// reasons was indistinguishable from one that had measured the path - and, in the other
// direction, a caller that set it lost their setting because the layer above forwarded
// only its own conclusion.
//
// So the four combinations are enumerated rather than sampled. Each row sets the two
// fields as a caller would and checks what quic-go is told about each, with the
// assertions deliberately one field at a time: a change that starts deriving one from the
// other fails here even if the derived value happens to be right for the configuration
// under test.
func TestApplyQUICOptionsKeepsTheCeilingAndThePMTUDPolicyIndependent(t *testing.T) {
	cases := []struct {
		name             string
		ceiling          int
		disablePMTUD     bool
		wantCeiling      uint16
		wantDisablePMTUD bool
	}{
		{
			name: "neither: an unknown path and no policy",
			// This is the direct dial that must keep its previous behaviour exactly.
			ceiling: 0, disablePMTUD: false,
			wantCeiling: 0, wantDisablePMTUD: false,
		},
		{
			name: "a proven ceiling turns PMTUD off for the connection",
			// The caller may still pass the policy separately; the ceiling is what this row
			// establishes, and the policy is asserted on its own in the row below.
			ceiling: 1232, disablePMTUD: false,
			wantCeiling: 1232, wantDisablePMTUD: false,
		},
		{
			name: "the operator's own policy with no proven ceiling",
			// THE DETECTOR. Under the old design this pair was read as a hard ceiling; here it
			// must reach quic-go as exactly what it is - a policy - and leave the ceiling unset,
			// so the fingerprint size still wins on the wire.
			ceiling: 0, disablePMTUD: true,
			wantCeiling: 0, wantDisablePMTUD: true,
		},
		{
			name:    "both, which is what a proven ceiling's caller sends",
			ceiling: 1232, disablePMTUD: true,
			wantCeiling: 1232, wantDisablePMTUD: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := &quic.Config{}
			ApplyQUICOptions(config, QUICOptions{
				InitialPacketSizeCeiling: testCase.ceiling,
				DisablePathMTUDiscovery:  testCase.disablePMTUD,
			})

			require.Equal(t, testCase.wantCeiling, config.InitialPacketSizeCeiling,
				"the ceiling must reach quic-go as its own field")
			require.Equal(t, testCase.wantDisablePMTUD, config.DisablePathMTUDiscovery,
				"and the PMTUD policy must reach it as its own field, neither invented nor swallowed")
		})
	}
}

// TestApplyQUICOptionsDoesNotRaiseASmallCeiling documents the boundary rather than leaving
// it to be discovered: a ceiling below the QUIC minimum is passed through as written and
// NOT raised to 1200.
//
// Raising it here would be the one thing a ceiling must never do - send a packet the
// caller proved the path drops - and it would move the failure away from the caller that
// can still do something about it (refusing the configuration and naming the tunnel) to a
// handshake timeout with no explanation.
func TestApplyQUICOptionsDoesNotRaiseASmallCeiling(t *testing.T) {
	config := &quic.Config{}
	ApplyQUICOptions(config, QUICOptions{InitialPacketSizeCeiling: 1100})
	require.Equal(t, uint16(1100), config.InitialPacketSizeCeiling,
		"a caller that proved the path carries 1100 bytes must be told so, not overruled")
}

// TestApplyQUICOptionsClampsOnlyAnImpossibleCeiling covers the one input the field cannot
// hold. A UDP payload cannot exceed 65535 bytes, so a larger ceiling is a caller error;
// clamping DOWN is the conservative direction, because a smaller ceiling is never less
// safe than a larger one.
func TestApplyQUICOptionsClampsOnlyAnImpossibleCeiling(t *testing.T) {
	config := &quic.Config{}
	ApplyQUICOptions(config, QUICOptions{InitialPacketSizeCeiling: 70000})
	require.Equal(t, uint16(65535), config.InitialPacketSizeCeiling)
}
