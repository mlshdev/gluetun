package models

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Connection_Equal(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		a     Connection
		b     Connection
		equal bool
	}{
		"empty": {
			equal: true,
		},
		"different_daita": {
			a: Connection{Daita: true},
			b: Connection{},
		},
		"exit_set_on_one": {
			a: Connection{Exit: &Connection{}},
			b: Connection{},
		},
		"same_exits": {
			a:     Connection{Exit: &Connection{IP: netip.MustParseAddr("1.2.3.4")}},
			b:     Connection{Exit: &Connection{IP: netip.MustParseAddr("1.2.3.4")}},
			equal: true,
		},
		"different_exits": {
			a: Connection{Exit: &Connection{IP: netip.MustParseAddr("1.2.3.4")}},
			b: Connection{Exit: &Connection{IP: netip.MustParseAddr("1.2.3.5")}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			equal := testCase.a.Equal(testCase.b)

			assert.Equal(t, testCase.equal, equal)
		})
	}
}
