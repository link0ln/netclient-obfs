package functions

import (
	"context"
	"sync"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/wireguard"
	nmmodels "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
)

const (
	connCheckInterval  = 20 * time.Second
	directGracePeriod  = 75 * time.Second // time to let a direct path establish after (re)trying
	handshakeFreshness = 150 * time.Second
)

// StartConnectivityManager runs the liveness-based adaptive relay decision.
//
// It tries a direct (hole-punched) path first; if the host stays isolated behind
// NAT past the grace period (no fresh WireGuard handshake with any non-relay
// peer), it reports a relay verdict so the server routes it through the relay.
// The direct path is re-probed periodically AND immediately whenever the host's
// public endpoint changes (roaming between mobile/Wi-Fi/other networks), so a
// host recovers a direct connection as soon as it lands on a hole-punchable
// network. The verdict is reported via the host NAT type, which the server's
// auto-relay reconciler acts on.
func StartConnectivityManager(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(connCheckInterval)
	defer ticker.Stop()

	relayed := false
	directDeadline := time.Now().Add(directGracePeriod)
	lastEndpoint := ""

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nc := config.Netclient()
			server := config.GetServer(config.CurrServer)
			if nc == nil || server == nil || !server.Stun || nc.IsStatic {
				continue
			}
			// Public hosts never need a relay.
			if config.HostNatType == nmmodels.NAT_Types.Public {
				continue
			}

			// Roaming: on a public-endpoint change just give the background probe a
			// fresh grace window before any new relay decision. The relay is NOT
			// torn down here — while relayed, the server keeps a warm background
			// probe session to each peer (real endpoint + keepalive, no allowed
			// IPs), so a direct path is re-detected in the background and the
			// switch happens seamlessly, without dropping connectivity.
			ep := ""
			if config.HostPublicIP != nil {
				ep = config.HostPublicIP.String()
			}
			if ep != lastEndpoint {
				lastEndpoint = ep
				slog.Info("connectivity: public endpoint changed, re-evaluating direct", "endpoint", ep)
				directDeadline = time.Now().Add(directGracePeriod)
			}

			// Continuous evaluation. A fresh handshake with any non-relay peer means
			// a direct path exists right now — including the background probe session
			// maintained while relayed. Because both the relay session and the direct
			// probe are kept warm, flipping the verdict (which the server's auto-relay
			// reconciler turns into an un-relay / re-relay) moves the routing onto an
			// already-established session with no handshake gap.
			verdict := nmmodels.NAT_Types.BehindNAT
			switch {
			case hasDirectConnectivity(server.AutoRelayPubKey):
				if relayed {
					slog.Info("connectivity: direct path proven live in background, un-relaying")
				}
				relayed = false
				verdict = nmmodels.NAT_Types.BehindNAT
				directDeadline = time.Now().Add(directGracePeriod)
			case relayed:
				verdict = nmmodels.NAT_Types.Symmetric
			case time.Now().After(directDeadline):
				relayed = true
				verdict = nmmodels.NAT_Types.Symmetric
				slog.Info("connectivity: no direct path to peers within grace, requesting relay")
			default:
				verdict = nmmodels.NAT_Types.BehindNAT
			}

			if verdict != config.HostNatType {
				slog.Info("connectivity: verdict changed", "from", config.HostNatType, "to", verdict)
				config.HostNatType = verdict
				if err := UpdateHostSettings(true); err != nil {
					slog.Warn("connectivity: failed to publish verdict", "error", err.Error())
				}
			}
		}
	}
}

// hasDirectConnectivity reports whether the host has a fresh WireGuard handshake
// with at least one of its expected peers, excluding the auto-relay node (which
// is public and always reachable, so a handshake with it must not mask isolation
// from the actual peers). It returns true ONLY on positive proof (a fresh
// handshake). All "no information" cases (no peers, unreadable device state)
// return false: without proof we must not claim a direct path, otherwise a
// transient empty/unreadable state would un-relay a correctly-relayed node and
// cause relay<->direct flapping.
func hasDirectConnectivity(relayPubKey string) bool {
	nc := config.Netclient()
	peers := nc.HostPeers
	if len(peers) == 0 {
		return false
	}
	devicePeers, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		return false
	}
	nonRelayPeers := 0
	for i := range peers {
		p := &peers[i]
		if p.Remove {
			continue
		}
		pk := p.PublicKey.String()
		if relayPubKey != "" && pk == relayPubKey {
			continue
		}
		nonRelayPeers++
		dp, ok := devicePeers[pk]
		if !ok {
			continue
		}
		if !dp.LastHandshakeTime.IsZero() && time.Since(dp.LastHandshakeTime) < handshakeFreshness {
			return true
		}
	}
	// No fresh handshake with any non-relay peer. Direct connectivity is NOT
	// proven — return false even when there are currently no non-relay peers
	// (e.g. a transient peer-update where the relayed peer is briefly absent).
	// Treating "no peers to check" as "direct works" caused relay<->direct
	// flapping: a momentary empty set un-relayed a correctly-relayed node.
	_ = nonRelayPeers
	return false
}
