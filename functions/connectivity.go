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
	connCheckInterval  = 10 * time.Second
	directGracePeriod  = 75 * time.Second  // time to let a direct path establish after (re)trying
	handshakeFreshness = 150 * time.Second // a WG handshake older than this is treated as no direct path
	// rxStallTimeout drives ACTIVE liveness: with the default 20s persistent
	// keepalive we keep sending to a direct peer, so a working path keeps the
	// inbound byte counter moving. If we are still transmitting but have received
	// nothing for this long, the direct path is dead — detected in ~35s instead of
	// waiting up to handshakeFreshness (~150s) for the handshake to go stale. This
	// is what makes the direct->relay fallback fast.
	rxStallTimeout = 35 * time.Second
)

// peerTraffic tracks per-peer byte counters to detect a stalled (dead) direct path.
type peerTraffic struct {
	rx, tx        int64
	lastRxAdvance time.Time
	lastTxAdvance time.Time
}

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
	traffic := map[string]*peerTraffic{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
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
			case hasDirectConnectivity(server.AutoRelayPubKey, traffic, now):
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

// hasDirectConnectivity reports whether the host has a LIVE direct path to at
// least one of its expected peers, excluding the auto-relay node (which is
// public and always reachable, so a handshake with it must not mask isolation
// from the actual peers).
//
// A peer's direct path is live when it has a fresh WireGuard handshake AND its
// inbound byte counter is moving. The byte-counter (active liveness) check is
// what makes the direct->relay fallback fast: with the default 20s keepalive we
// keep transmitting, so if we are still sending but have received nothing for
// rxStallTimeout (~35s) the path is dead — detected long before the handshake
// goes stale (~150s). The traffic map carries per-peer counter state across
// ticks and is pruned to the current peer set.
//
// Returns true ONLY on positive proof. All "no information" cases (no peers,
// unreadable device state) return false: without proof we must not claim a
// direct path, otherwise a transient empty/unreadable state would un-relay a
// correctly-relayed node and cause relay<->direct flapping.
func hasDirectConnectivity(relayPubKey string, traffic map[string]*peerTraffic, now time.Time) bool {
	nc := config.Netclient()
	peers := nc.HostPeers
	if len(peers) == 0 {
		return false
	}
	devicePeers, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	live := false
	for i := range peers {
		p := &peers[i]
		if p.Remove {
			continue
		}
		pk := p.PublicKey.String()
		if relayPubKey != "" && pk == relayPubKey {
			continue
		}
		dp, ok := devicePeers[pk]
		if !ok {
			continue
		}
		seen[pk] = true

		st := traffic[pk]
		if st == nil {
			st = &peerTraffic{rx: dp.ReceiveBytes, tx: dp.TransmitBytes, lastRxAdvance: now, lastTxAdvance: now}
			traffic[pk] = st
		} else {
			if dp.ReceiveBytes > st.rx {
				st.lastRxAdvance = now
			}
			if dp.TransmitBytes > st.tx {
				st.lastTxAdvance = now
			}
			st.rx = dp.ReceiveBytes
			st.tx = dp.TransmitBytes
		}

		if dp.LastHandshakeTime.IsZero() || now.Sub(dp.LastHandshakeTime) >= handshakeFreshness {
			continue // no (fresh) handshake — not a live direct path
		}
		// Active liveness: only conclude "dead" when we are still transmitting
		// (keepalive/traffic) yet receiving nothing. If we are not transmitting
		// either, the stall is uninformative and we fall back to the handshake.
		txActive := now.Sub(st.lastTxAdvance) < rxStallTimeout
		rxStalled := now.Sub(st.lastRxAdvance) >= rxStallTimeout
		if txActive && rxStalled {
			continue // direct path to this peer is dead
		}
		live = true
	}
	for pk := range traffic {
		if !seen[pk] {
			delete(traffic, pk)
		}
	}
	return live
}
