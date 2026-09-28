//go:build daita

package daita

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/cleanup"
	"github.com/qdm12/gluetun/internal/ephemeralpeer"
	"github.com/qdm12/gluetun/internal/netlink"
	gtun "github.com/qdm12/gluetun/internal/tun"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/conn"
	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/device"
	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/tun"
	"github.com/qdm12/gluetun/third_party/mullvad-wireguard-go/tun/multihoptun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Daita runs a userspace Wireguard tunnel to a Mullvad relay with DAITA
// enabled, optionally reaching an exit relay through it (multihop).
type Daita struct {
	settings  Settings
	netlinker wireguard.NetLinker
	logger    wireguard.Logger
	client    *ephemeralpeer.Client
}

func New(settings Settings, netlinker wireguard.NetLinker,
	logger wireguard.Logger,
) (*Daita, error) {
	settings.SetDefaults()
	err := settings.Check()
	if err != nil {
		return nil, err
	}

	return &Daita{
		settings:  settings,
		netlinker: netlinker,
		logger:    logger,
		client:    ephemeralpeer.New(),
	}, nil
}

var errDeviceClosed = errors.New("wireguard device closed")

// Run runs the DAITA tunnel and waits until the context is done, then it cleans up
// the interface. It sends an error to waitError if any error occurs during setup or
// waiting, otherwise it sends the context error when the context is done.
// It sends a signal to ready once the DAITA machines are enabled.
func (d *Daita) Run(ctx context.Context, waitError chan<- error, ready chan<- struct{}) {
	var cleanups cleanup.Cleanups
	defer cleanups.Cleanup(d.logger)

	deviceClosed, err := d.setup(ctx, &cleanups)
	if err != nil {
		waitError <- err
		return
	}

	ready <- struct{}{}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-deviceClosed:
		err = errDeviceClosed
	}
	cleanups.Cleanup(d.logger)
	waitError <- err
}

var errTUNNameMismatch = errors.New("TUN device name is mismatching")

func (d *Daita) setup(ctx context.Context, cleanups *cleanup.Cleanups) (
	deviceClosed <-chan struct{}, err error,
) {
	settings := d.settings.Wireguard
	switch settings.Implementation {
	case "kernelspace":
		d.logger.Warn("DAITA requires the userspace Wireguard implementation, " +
			"ignoring WIREGUARD_IMPLEMENTATION=kernelspace")
	case "auto":
		d.logger.Info("Using userspace implementation required by DAITA")
	}

	parentPrivateKey, relayPeer, err := parseKeys(settings)
	if err != nil {
		return nil, err
	}

	err = gtun.Setup()
	if err != nil {
		return nil, fmt.Errorf("setting up userspace tun device: %w", err)
	}

	realTUN, err := tun.CreateTUN(settings.InterfaceName, int(settings.MTU))
	if err != nil {
		return nil, fmt.Errorf("creating TUN device: %w", err)
	}
	cleanups.Add("closing TUN device", 8, realTUN.Close) //nolint:mnd

	tunName, err := realTUN.Name()
	switch {
	case err != nil:
		return nil, fmt.Errorf("getting created TUN device name: %w", err)
	case tunName != settings.InterfaceName:
		return nil, fmt.Errorf("%w: expected %q and got %q",
			errTUNNameMismatch, settings.InterfaceName, tunName)
	}

	link, err := d.netlinker.LinkByName(settings.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("finding link: %w", err)
	}
	cleanups.Add("deleting link", 5, func() error { //nolint:mnd
		return d.netlinker.LinkDel(link.Index)
	})

	err = wireguard.AddAddresses(link.Index, settings.Addresses, *settings.IPv6, d.netlinker)
	if err != nil {
		return nil, fmt.Errorf("adding addresses to interface: %w", err)
	}

	// The negotiation device uses the parent key to reach the relay config
	// service. In multihop mode, it is replaced by the entry and exit devices
	// so it must not close the TUN device.
	negotiationTUN := realTUN
	if d.settings.Exit != nil {
		negotiationTUN = newDetachableTUN(realTUN)
	}
	negotiationDevice := device.NewDevice(negotiationTUN, conn.NewDefaultBind(),
		makeDeviceLogger(d.logger, ""))
	cleanups.Add("closing Wireguard device", 6, closeDevice(negotiationDevice)) //nolint:mnd

	parentConfig := deviceConfig{
		privateKey:   parentPrivateKey,
		firewallMark: settings.FirewallMark,
		peer:         relayPeer,
	}
	err = configureAndUp(negotiationDevice, parentConfig)
	if err != nil {
		return nil, err
	}

	d.logger.Info("Connecting to " + settings.Endpoint.String())
	err = d.setupRouting(link.Index, cleanups)
	if err != nil {
		return nil, err
	}

	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral private key: %w", err)
	}

	if d.settings.PostQuantum {
		d.logger.Info("Negotiating quantum-resistant DAITA ephemeral peer")
	} else {
		d.logger.Info("Negotiating DAITA ephemeral peer")
	}
	response, err := d.client.Register(ctx, ephemeralpeer.Request{
		ParentPublicKey:    parentPrivateKey.PublicKey(),
		EphemeralPublicKey: ephemeralPrivateKey.PublicKey(),
		PostQuantum:        d.settings.PostQuantum,
		Daita:              true,
	})
	if err != nil {
		return nil, err
	}

	if d.settings.Exit == nil {
		ephemeralConfig := parentConfig
		ephemeralConfig.privateKey = ephemeralPrivateKey
		ephemeralConfig.peer.presharedKey = response.PresharedKey
		err = negotiationDevice.IpcSet(ephemeralConfig.uapiString())
		if err != nil {
			return nil, fmt.Errorf("setting ephemeral peer configuration: %w", err)
		}
		err = enableDaita(negotiationDevice, relayPeer.publicKey, response.Daita)
		if err != nil {
			return nil, err
		}
		d.logger.Info(enabledMessage(d.settings.PostQuantum))
		return negotiationDevice.Wait(), nil
	}

	return d.setupMultihop(ctx, realTUN, negotiationDevice, parentPrivateKey,
		ephemeralPrivateKey, relayPeer, response, cleanups)
}

func enabledMessage(postQuantum bool) string {
	if postQuantum {
		return "DAITA enabled with quantum-resistant tunnel"
	}
	return "DAITA enabled"
}

func (d *Daita) setupMultihop(ctx context.Context, realTUN tun.Device,
	negotiationDevice *device.Device, parentPrivateKey, ephemeralPrivateKey wgtypes.Key,
	relayPeer peerConfig, entryResponse ephemeralpeer.Response, cleanups *cleanup.Cleanups,
) (deviceClosed <-chan struct{}, err error) {
	settings := d.settings.Wireguard
	exit := d.settings.Exit

	negotiationDevice.Close()
	// Clear the read deadline set to unblock the negotiation device TUN reader.
	err = realTUN.File().SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("resetting TUN read deadline: %w", err)
	}

	tunnelIP, err := tunnelIPv4(settings.Addresses)
	if err != nil {
		return nil, err
	}
	// The entry device encapsulates the exit device packets of MTU size in
	// IPv4 (20B) UDP (8B) packets, on top of which it adds its own Wireguard
	// overhead (32B), so its MTU must be larger to avoid fragmentation.
	const ipv4UDPWireguardOverhead = 60
	entryMTU := int(settings.MTU) + ipv4UDPWireguardOverhead
	multihopTUN := multihoptun.NewMultihopTun(tunnelIP, exit.Endpoint.Addr(),
		exit.Endpoint.Port(), entryMTU)

	entryDevice := device.NewDevice(&multihopTUN, conn.NewDefaultBind(),
		makeDeviceLogger(d.logger, "entry: "))
	cleanups.Add("closing entry Wireguard device", 7, closeDevice(entryDevice)) //nolint:mnd
	entryPeer := relayPeer
	entryPeer.presharedKey = entryResponse.PresharedKey
	const ipv4Bits = 32
	entryPeer.allowedIPs = []netip.Prefix{netip.PrefixFrom(exit.Endpoint.Addr(), ipv4Bits)}
	entryConfig := deviceConfig{
		privateKey:   ephemeralPrivateKey,
		firewallMark: settings.FirewallMark,
		peer:         entryPeer,
	}
	err = configureAndUp(entryDevice, entryConfig)
	if err != nil {
		return nil, fmt.Errorf("entry device: %w", err)
	}
	err = enableDaita(entryDevice, entryPeer.publicKey, entryResponse.Daita)
	if err != nil {
		return nil, fmt.Errorf("entry device: %w", err)
	}

	exitDevice := device.NewDevice(realTUN, multihopTUN.Binder(),
		makeDeviceLogger(d.logger, "exit: "))
	cleanups.Add("closing exit Wireguard device", 6, closeDevice(exitDevice)) //nolint:mnd
	exitPublicKey, err := wgtypes.ParseKey(exit.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing exit public key: %w", err)
	}
	exitPeer := relayPeer
	exitPeer.publicKey = exitPublicKey
	exitPeer.endpoint = exit.Endpoint
	exitConfig := deviceConfig{
		privateKey: parentPrivateKey,
		peer:       exitPeer,
	}
	err = configureAndUp(exitDevice, exitConfig)
	if err != nil {
		return nil, fmt.Errorf("exit device: %w", err)
	}

	if d.settings.PostQuantum {
		err = d.upgradeExit(ctx, exitDevice, exitConfig)
		if err != nil {
			return nil, fmt.Errorf("exit device: %w", err)
		}
	}

	d.logger.Info(enabledMessage(d.settings.PostQuantum) + " on entry relay " +
		settings.Endpoint.String() + " to reach exit relay " + exit.Endpoint.String())

	closed := make(chan struct{})
	go func() {
		select {
		case <-entryDevice.Wait():
		case <-exitDevice.Wait():
		}
		close(closed)
	}()
	return closed, nil
}

// upgradeExit registers a new ephemeral peer with a post-quantum pre-shared key
// with the exit relay config service, reached through the exit tunnel, and
// reconfigures the exit device to use it.
func (d *Daita) upgradeExit(ctx context.Context, exitDevice *device.Device,
	exitConfig deviceConfig,
) error {
	d.logger.Info("Negotiating quantum-resistant exit ephemeral peer")
	exitEphemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating ephemeral private key: %w", err)
	}

	response, err := d.client.Register(ctx, ephemeralpeer.Request{
		ParentPublicKey:    exitConfig.privateKey.PublicKey(),
		EphemeralPublicKey: exitEphemeralPrivateKey.PublicKey(),
		PostQuantum:        true,
	})
	if err != nil {
		return err
	}

	exitConfig.privateKey = exitEphemeralPrivateKey
	exitConfig.peer.presharedKey = response.PresharedKey
	err = exitDevice.IpcSet(exitConfig.uapiString())
	if err != nil {
		return fmt.Errorf("setting ephemeral peer configuration: %w", err)
	}
	return nil
}

func (d *Daita) setupRouting(linkIndex uint32, cleanups *cleanup.Cleanups) error {
	settings := d.settings.Wireguard
	err := d.netlinker.LinkSetUp(linkIndex)
	if err != nil {
		return fmt.Errorf("setting the interface UP: %w", err)
	}
	cleanups.Add("shutting down link", 4, func() error { //nolint:mnd
		return d.netlinker.LinkSetDown(linkIndex)
	})

	err = wireguard.AddRoutes(linkIndex, settings.AllowedIPs, settings.FirewallMark,
		d.netlinker, d.logger)
	if err != nil {
		return fmt.Errorf("adding routes for interface: %w", err)
	}

	if *settings.IPv6 {
		// requires net.ipv6.conf.all.disable_ipv6=0
		ruleCleanup6, err := wireguard.AddRule(settings.RulePriority,
			settings.FirewallMark, netlink.FamilyV6, d.netlinker, d.logger)
		if err != nil {
			return fmt.Errorf("adding IPv6 rule: %w", err)
		}
		cleanups.Add("removing IPv6 rule", 1, ruleCleanup6)
	}

	ruleCleanup, err := wireguard.AddRule(settings.RulePriority,
		settings.FirewallMark, netlink.FamilyV4, d.netlinker, d.logger)
	if err != nil {
		return fmt.Errorf("adding IPv4 rule: %w", err)
	}
	cleanups.Add("removing IPv4 rule", 1, ruleCleanup)
	return nil
}

func parseKeys(settings wireguard.Settings) (privateKey wgtypes.Key,
	relayPeer peerConfig, err error,
) {
	privateKey, err = wgtypes.ParseKey(settings.PrivateKey)
	if err != nil {
		return wgtypes.Key{}, peerConfig{}, fmt.Errorf("parsing private key: %w", err)
	}

	relayPeer = peerConfig{
		endpoint:            settings.Endpoint,
		persistentKeepalive: settings.PersistentKeepaliveInterval,
		// Traffic selection is done with routes, like the wireguard package.
		allowedIPs: []netip.Prefix{
			netip.PrefixFrom(netip.IPv4Unspecified(), 0),
			netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		},
	}

	relayPeer.publicKey, err = wgtypes.ParseKey(settings.PublicKey)
	if err != nil {
		return wgtypes.Key{}, peerConfig{}, fmt.Errorf("parsing public key: %w", err)
	}

	if settings.PreSharedKey != "" {
		relayPeer.presharedKey, err = wgtypes.ParseKey(settings.PreSharedKey)
		if err != nil {
			return wgtypes.Key{}, peerConfig{}, fmt.Errorf("parsing pre-shared key: %w", err)
		}
	}

	return privateKey, relayPeer, nil
}

func configureAndUp(wgDevice *device.Device, config deviceConfig) error {
	err := wgDevice.IpcSet(config.uapiString())
	if err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}
	err = wgDevice.Up()
	if err != nil {
		return fmt.Errorf("bringing device up: %w", err)
	}
	return nil
}

var (
	errPeerNotFound    = errors.New("peer not found")
	errDaitaNotEnabled = errors.New("DAITA could not be enabled")
)

func enableDaita(wgDevice *device.Device, peerPublicKey wgtypes.Key,
	config ephemeralpeer.DaitaConfig,
) error {
	peer := wgDevice.LookupPeer(device.NoisePublicKey(peerPublicKey))
	if peer == nil {
		return fmt.Errorf("enabling DAITA: %w", errPeerNotFound)
	}
	// Capacities used by the official Mullvad client.
	const eventsCapacity = 2048
	const actionsCapacity = 1024
	ok := peer.EnableDaita(strings.Join(config.Machines, "\n"),
		eventsCapacity, actionsCapacity, config.MaxPaddingFrac, config.MaxBlockingFrac)
	if !ok {
		return errDaitaNotEnabled
	}
	return nil
}

func closeDevice(wgDevice *device.Device) func() error {
	return func() error {
		wgDevice.Close()
		return nil
	}
}

func makeDeviceLogger(logger wireguard.Logger, prefix string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debugf(prefix+format, args...)
		},
		Errorf: func(format string, args ...any) {
			logger.Errorf(prefix+format, args...)
		},
	}
}

// detachableTUN wraps a TUN device so that closing the wireguard device
// using it stops its TUN reader without closing the underlying TUN device,
// which can then be used by another wireguard device.
type detachableTUN struct {
	tun.Device
	events    chan tun.Event
	closeOnce sync.Once
}

func newDetachableTUN(device tun.Device) *detachableTUN {
	return &detachableTUN{
		Device: device,
		events: make(chan tun.Event),
	}
}

// Events returns an event channel never emitting, so the underlying
// TUN device events are kept for the next wireguard device.
func (t *detachableTUN) Events() <-chan tun.Event {
	return t.events
}

// Close closes the events channel and unblocks any pending read by
// setting a read deadline in the past on the underlying TUN file.
func (t *detachableTUN) Close() (err error) {
	t.closeOnce.Do(func() {
		close(t.events)
		err = t.Device.File().SetReadDeadline(time.Now())
	})
	return err
}
