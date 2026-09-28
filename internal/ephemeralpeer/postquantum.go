package ephemeralpeer

import (
	"context"
	"errors"
	"fmt"

	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PostQuantum wraps a Wireguard runner to upgrade its tunnel to a
// quantum-resistant tunnel once it is ready, the same way the official
// Mullvad app does, see https://github.com/mullvad/wgephemeralpeer
type PostQuantum struct {
	runner          Runner
	client          *Client
	interfaceName   string
	privateKey      wgtypes.Key
	peerPublicKey   wgtypes.Key
	configureDevice func(interfaceName string, config wgtypes.Config) error
	logger          Logger
}

func NewPostQuantum(runner Runner, settings wireguard.Settings, logger Logger) (
	postQuantum *PostQuantum, err error,
) {
	privateKey, err := wgtypes.ParseKey(settings.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	peerPublicKey, err := wgtypes.ParseKey(settings.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return &PostQuantum{
		runner:          runner,
		client:          New(),
		interfaceName:   settings.InterfaceName,
		privateKey:      privateKey,
		peerPublicKey:   peerPublicKey,
		configureDevice: configureDevice,
		logger:          logger,
	}, nil
}

func (p *PostQuantum) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	runnerCtx, runnerCancel := context.WithCancel(ctx)
	defer runnerCancel()
	runnerWaitError := make(chan error, 1)
	runnerReady := make(chan struct{})
	go p.runner.Run(runnerCtx, runnerWaitError, runnerReady)

	select {
	case err := <-runnerWaitError:
		waitError <- err
		return
	case <-runnerReady:
	}

	err := p.upgrade(runnerCtx)
	if err != nil {
		runnerCancel()
		<-runnerWaitError
		waitError <- fmt.Errorf("upgrading to quantum-resistant tunnel: %w", err)
		return
	}

	ready <- struct{}{}
	waitError <- <-runnerWaitError
}

// upgrade registers an ephemeral peer with a post-quantum pre-shared key
// through the tunnel, and reconfigures the tunnel to use it.
func (p *PostQuantum) upgrade(ctx context.Context) error {
	p.logger.Info("Upgrading to a quantum-resistant tunnel")
	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating ephemeral private key: %w", err)
	}

	response, err := p.client.Register(ctx, Request{
		ParentPublicKey:    p.privateKey.PublicKey(),
		EphemeralPublicKey: ephemeralPrivateKey.PublicKey(),
		PostQuantum:        true,
	})
	if err != nil {
		return err
	}

	config := wgtypes.Config{
		PrivateKey: &ephemeralPrivateKey,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    p.peerPublicKey,
			UpdateOnly:   true,
			PresharedKey: &response.PresharedKey,
		}},
	}
	err = p.configureDevice(p.interfaceName, config)
	if err != nil {
		return fmt.Errorf("configuring ephemeral peer: %w", err)
	}
	p.logger.Info("Quantum-resistant tunnel enabled")
	return nil
}

func configureDevice(interfaceName string, config wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("opening wgctrl: %w", err)
	}
	err = client.ConfigureDevice(interfaceName, config)
	closeErr := client.Close()
	switch {
	case err != nil:
		return errors.Join(err, closeErr)
	case closeErr != nil:
		return fmt.Errorf("closing wgctrl: %w", closeErr)
	}
	return nil
}
