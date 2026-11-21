package qtls

import (
	"testing"

	"github.com/sagernet/quic-go"

	"github.com/stretchr/testify/require"
)

// ApplyQUICOptions used to have one window knob per level, and it wrote the same value into the
// INITIAL and the MAXIMUM window. Those are two different statements and the difference is the
// whole point of the split: the initial window is flow-control credit advertised in the handshake
// and bounds what a peer may hold in flight while an application is not reading, while the maximum
// is a local auto-tuning ceiling that is never sent anywhere.
//
// The rows below pin the precedence, because there are now three ways to say it and only one of
// them is new:
//
//   - the legacy StreamReceiveWindow/ConnectionReceiveWindow still means ONE value for both, and
//     still wins when set, so not one existing caller changes behaviour;
//   - the split fields fill only what the legacy field left alone;
//   - a ceiling below its initial value is raised to it, because the initial value is already
//     promised to the peer and cannot be taken back.
func TestApplyQUICOptionsSplitsTheInitialAndMaximumReceiveWindows(t *testing.T) {
	cases := []struct {
		name           string
		options        QUICOptions
		wantInitialStr uint64
		wantMaxStr     uint64
		wantInitialCon uint64
		wantMaxCon     uint64
	}{
		{
			name:    "nothing configured leaves every window to quic-go",
			options: QUICOptions{},
		},
		{
			name:           "the legacy stream window still means both",
			options:        QUICOptions{StreamReceiveWindow: 8 << 20},
			wantInitialStr: 8 << 20, wantMaxStr: 8 << 20,
		},
		{
			name:           "the legacy connection window still means both",
			options:        QUICOptions{ConnectionReceiveWindow: 20 << 20},
			wantInitialCon: 20 << 20, wantMaxCon: 20 << 20,
		},
		{
			name: "a split initial window alone raises an unset ceiling to it",
			// Not "leaves the ceiling at zero": a grant with no ceiling would be a window that
			// cannot grow, which is a different configuration from the one asked for. The
			// normalisation below makes the grant the ceiling in that case.
			options:        QUICOptions{InitialStreamReceiveWindow: 1 << 20},
			wantInitialStr: 1 << 20, wantMaxStr: 1 << 20,
		},
		{
			name:       "a split ceiling alone leaves the grant untouched",
			options:    QUICOptions{MaxConnectionReceiveWindow: 20 << 20},
			wantMaxCon: 20 << 20,
		},
		{
			name: "a split pair is applied field by field",
			options: QUICOptions{
				InitialStreamReceiveWindow:     1 << 20,
				MaxStreamReceiveWindow:         8 << 20,
				InitialConnectionReceiveWindow: 12 << 20,
				MaxConnectionReceiveWindow:     20 << 20,
			},
			wantInitialStr: 1 << 20, wantMaxStr: 8 << 20,
			wantInitialCon: 12 << 20, wantMaxCon: 20 << 20,
		},
		{
			name: "the operator's explicit value wins over a split default",
			options: QUICOptions{
				StreamReceiveWindow:            16 << 20,
				ConnectionReceiveWindow:        32 << 20,
				InitialStreamReceiveWindow:     1 << 20,
				MaxStreamReceiveWindow:         8 << 20,
				InitialConnectionReceiveWindow: 12 << 20,
				MaxConnectionReceiveWindow:     20 << 20,
			},
			wantInitialStr: 16 << 20, wantMaxStr: 16 << 20,
			wantInitialCon: 32 << 20, wantMaxCon: 32 << 20,
		},
		{
			name:           "a ceiling below its grant is raised to the grant, not the reverse",
			options:        QUICOptions{InitialStreamReceiveWindow: 4 << 20, MaxStreamReceiveWindow: 1 << 20},
			wantInitialStr: 4 << 20, wantMaxStr: 4 << 20,
		},
		{
			name:           "the same normalisation applies at the connection level",
			options:        QUICOptions{InitialConnectionReceiveWindow: 12 << 20, MaxConnectionReceiveWindow: 6 << 20},
			wantInitialCon: 12 << 20, wantMaxCon: 12 << 20,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := &quic.Config{}
			ApplyQUICOptions(config, testCase.options)
			require.Equal(t, testCase.wantInitialStr, config.InitialStreamReceiveWindow,
				"initial stream window")
			require.Equal(t, testCase.wantMaxStr, config.MaxStreamReceiveWindow,
				"maximum stream window")
			require.Equal(t, testCase.wantInitialCon, config.InitialConnectionReceiveWindow,
				"initial connection window")
			require.Equal(t, testCase.wantMaxCon, config.MaxConnectionReceiveWindow,
				"maximum connection window")
		})
	}
}

// The two clients that already set windows before calling ApplyQUICOptions (hysteria, hysteria2,
// TUIC) must keep exactly what they set when the caller does not override it: the split fields are
// an addition, not a replacement for the preset.
func TestApplyQUICOptionsKeepsTheCallersPresetWindows(t *testing.T) {
	config := &quic.Config{
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 20 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
	}
	ApplyQUICOptions(config, QUICOptions{})
	require.Equal(t, uint64(8<<20), config.InitialStreamReceiveWindow)
	require.Equal(t, uint64(8<<20), config.MaxStreamReceiveWindow)
	require.Equal(t, uint64(20<<20), config.InitialConnectionReceiveWindow)
	require.Equal(t, uint64(20<<20), config.MaxConnectionReceiveWindow)

	// And a policy that only lowers the grant leaves the ceiling at the preset.
	ApplyQUICOptions(config, QUICOptions{
		InitialStreamReceiveWindow:     1 << 20,
		InitialConnectionReceiveWindow: 12 << 20,
	})
	require.Equal(t, uint64(1<<20), config.InitialStreamReceiveWindow, "the grant is what the policy owns")
	require.Equal(t, uint64(8<<20), config.MaxStreamReceiveWindow, "the ceiling was not asked to change")
	require.Equal(t, uint64(12<<20), config.InitialConnectionReceiveWindow)
	require.Equal(t, uint64(20<<20), config.MaxConnectionReceiveWindow)
}
