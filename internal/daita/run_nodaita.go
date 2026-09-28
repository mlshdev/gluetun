//go:build !daita

package daita

import (
	"context"
	"errors"

	"github.com/qdm12/gluetun/internal/wireguard"
)

// Daita is not usable since this program is built without the daita tag.
type Daita struct{}

var errNotCompiled = errors.New("DAITA is not compiled in this program, build it with the daita tag")

func New(Settings, wireguard.NetLinker, wireguard.Logger) (*Daita, error) {
	return nil, errNotCompiled
}

func (*Daita) Run(context.Context, chan<- error, chan<- struct{}) {
	panic(errNotCompiled.Error())
}
