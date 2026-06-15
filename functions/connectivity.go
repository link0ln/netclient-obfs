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

			// Roaming: re-probe direct on a public-endpoint change. A stable relayed
			// connection is not torn down to re-test direct (that drops connectivity
			// for the grace period); recovery happens when the host lands on a new
			// network, which is the roaming case.
			ep := ""
			if config.HostPublicIP != nil {
				ep = config.HostPublicIP.String()
			}
			if ep != lastEndpoint {
				lastEndpoint = ep
				if relayed {
					slog.Info("connectivity: endpoint changed, re-probing direct", "endpoint", ep)
				}
				relayed = false
				directDeadline = time.Now().Add(directGracePeriod)
			}

			verdict := nmmodels.NAT_Types.BehindNAT
			if relayed {
				verdict = nmmodels.NAT_Types.Symmetric
			} else if hasDirectConnectivity(server.AutoRelayPubKey) {
				// Direct works; nothing to do.
			} else if time.Now().After(directDeadline) {
				relayed = true
				verdict = nmmodels.NAT_Types.Symmetric
				slog.Info("connectivity: no direct path to peers, requesting relay")
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
// from the actual peers). Returns true when there are no non-relay peers, or when
// peer state can't be read, to avoid relaying spuriously.
func hasDirectConnectivity(relayPubKey string) bool {
	nc := config.Netclient()
	peers := nc.HostPeers
	if len(peers) == 0 {
		return true
	}
	devicePeers, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		return true
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
	return nonRelayPeers == 0
}
