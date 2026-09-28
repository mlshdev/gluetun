package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type noopFilterChoicesGetter struct{}

func (noopFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{}
}

func Test_ServerSelection_setDefaults_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		initial  ServerSelection
		expected string
	}{
		"empty_mode_set_to_random": {
			expected: "random",
		},
		"random_mode_kept": {
			initial:  ServerSelection{Mode: "random"},
			expected: "random",
		},
		"ordered_mode_kept": {
			initial:  ServerSelection{Mode: "ordered"},
			expected: "ordered",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.initial.setDefaults(providers.Mullvad, false)

			assert.Equal(t, testCase.expected, testCase.initial.Mode)
		})
	}
}

func Test_ServerSelection_validate_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mode       string
		errMessage string
	}{
		"random": {
			mode: "random",
		},
		"ordered": {
			mode: "ordered",
		},
		"empty": {
			errMessage: "the selection mode specified is not valid",
		},
		"invalid": {
			mode:       "invalid",
			errMessage: "the selection mode specified is not valid",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			warner := NewMockWarner(ctrl)

			ss := ServerSelection{}.WithDefaults(providers.Mullvad)
			ss.Mode = testCase.mode

			err := ss.validate(providers.Mullvad, noopFilterChoicesGetter{}, warner)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_validateFeatureFilters_mullvadDaita(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider   string
		vpnType    string
		daita      bool
		errMessage string
	}{
		"daita_off_other_provider": {
			provider: providers.Protonvpn,
			vpnType:  vpn.OpenVPN,
		},
		"daita_mullvad_wireguard": {
			provider: providers.Mullvad,
			vpnType:  vpn.Wireguard,
			daita:    true,
		},
		"daita_other_provider": {
			provider:   providers.Protonvpn,
			vpnType:    vpn.Wireguard,
			daita:      true,
			errMessage: "DAITA is not supported",
		},
		"daita_mullvad_openvpn": {
			provider:   providers.Mullvad,
			vpnType:    vpn.OpenVPN,
			daita:      true,
			errMessage: "DAITA is not supported for VPN type openvpn",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := ServerSelection{
				VPN:          testCase.vpnType,
				MullvadDaita: new(testCase.daita),
			}.WithDefaults(testCase.provider)

			err := validateFeatureFilters(selection, testCase.provider)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

func Test_ServerSelection_toLinesNode_mullvadDaita(t *testing.T) {
	t.Parallel()

	selection := ServerSelection{
		VPN:                vpn.Wireguard,
		MullvadDaita:       new(true),
		MullvadDaitaDirect: new(true),
	}.WithDefaults(providers.Mullvad)

	assert.Contains(t, selection.String(), `├── Mullvad DAITA: yes
|   └── Direct only: yes
`)
}

func Test_validateFeatureFilters_mullvadPostQuantum(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider    string
		vpnType     string
		postQuantum bool
		errMessage  string
	}{
		"post_quantum_off_other_provider": {
			provider: providers.Protonvpn,
			vpnType:  vpn.OpenVPN,
		},
		"post_quantum_mullvad_wireguard": {
			provider:    providers.Mullvad,
			vpnType:     vpn.Wireguard,
			postQuantum: true,
		},
		"post_quantum_other_provider": {
			provider:    providers.Protonvpn,
			vpnType:     vpn.Wireguard,
			postQuantum: true,
			errMessage:  "post-quantum is not supported",
		},
		"post_quantum_mullvad_openvpn": {
			provider:    providers.Mullvad,
			vpnType:     vpn.OpenVPN,
			postQuantum: true,
			errMessage:  "post-quantum is not supported for VPN type openvpn",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := ServerSelection{
				VPN:                testCase.vpnType,
				MullvadPostQuantum: new(testCase.postQuantum),
			}.WithDefaults(testCase.provider)

			err := validateFeatureFilters(selection, testCase.provider)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

func Test_ServerSelection_toLinesNode_mullvadPostQuantum(t *testing.T) {
	t.Parallel()

	selection := ServerSelection{
		VPN:                vpn.Wireguard,
		MullvadPostQuantum: new(true),
	}.WithDefaults(providers.Mullvad)

	assert.Contains(t, selection.String(), "├── Mullvad post-quantum: yes\n")
}
