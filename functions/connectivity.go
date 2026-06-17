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
	// observedRefresh re-publishes observed peer endpoints even when unchanged, to
	// keep the server's cache (3m TTL) warm on a stable mesh with fixed endpoints.
	observedRefresh = 60 * time.Second
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
	lastObserved := map[string]string{}
	lastObservedPublish := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			nc := config.Netclient()
			server := config.GetServer(config.CurrServer)
			if nc == nil || server == nil || !server.Stun {
				continue
			}

			// Report the real external WG endpoints we observe for our peers (the
			// data-path reflexive addresses). A relay sees every peer's true source
			// address; the server hands these to other peers as hole-punch
			// candidates. Publish when the set changes, AND refresh periodically even
			// when unchanged: the server caches observations with a TTL, so a stable
			// mesh (fixed endpoints) must keep refreshing or the cache expires and the
			// hole-punch candidate is lost. This runs even on a STATIC node — the relay
			// is static yet is the single most important observer (it is in every
			// relayed peer's data path).
			if obs := collectObservedEndpoints(now); len(obs) > 0 &&
				(!sameStringMap(obs, lastObserved) || now.Sub(lastObservedPublish) > observedRefresh) {
				if err := PublishObservedEndpoints(obs); err != nil {
					slog.Warn("connectivity: failed to publish observed endpoints", "error", err.Error())
				} else {
					slog.Info("connectivity: published observed endpoints", "count", len(obs), "endpoints", obs)
					lastObserved = obs
					lastObservedPublish = now
				}
			}

			// The relay decision below is for NAT'd nodes only. A static node (e.g. the
			// relay itself) never needs a relay, but still reports observations above.
			if nc.IsStatic {
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
				slog.Info("connectivity: public endpoint changed, re-evaluating", "endpoint", ep)
				directDeadline = time.Now().Add(directGracePeriod)
			}

			// A host must be relayed unless it can reach EVERY peer over a direct
			// (hole-punched) path. If even one peer is reachable only via the relay,
			// that peer can't reach us back directly either, so we stay relayed so it
			// can reach us through the relay. We un-relay only once ALL peers are
			// directly reachable — this both fixes "others can't reach a symmetric
			// host" and avoids relay<->direct flapping when some peers punch and some
			// don't. The background probe sessions are kept warm, so the switch has
			// no handshake gap.
			reachable, total := directReachability(server.AutoRelayPubKey, traffic, now)
			verdict := nmmodels.NAT_Types.BehindNAT
			switch {
			case total == 0:
				verdict = nmmodels.NAT_Types.BehindNAT // no peers yet — nothing to decide
			case reachable == total:
				if relayed {
					slog.Info("connectivity: all peers reachable directly, un-relaying")
				}
				relayed = false
				verdict = nmmodels.NAT_Types.BehindNAT
				directDeadline = time.Now().Add(directGracePeriod)
			case relayed:
				verdict = nmmodels.NAT_Types.Symmetric
			case time.Now().After(directDeadline):
				relayed = true
				verdict = nmmodels.NAT_Types.Symmetric
				slog.Info("connectivity: some peers not directly reachable, requesting relay", "reachable", reachable, "total", total)
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

// collectObservedEndpoints reads the WG device and returns the real external
// endpoint (peer-pubkey -> "ip:port") for every peer we currently have a live
// session with (an endpoint plus a fresh handshake). For a relay this is every
// relayed peer's true source address — the correct hole-punch target to advertise
// to other peers, even when the peer's own STUN self-report is wrong or stale.
func collectObservedEndpoints(now time.Time) map[string]string {
	out := map[string]string{}
	devicePeers, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		return out
	}
	for pk, dp := range devicePeers {
		if dp.Endpoint == nil || dp.Endpoint.IP == nil || dp.Endpoint.Port == 0 {
			continue
		}
		// Only report PUBLIC reflexive addresses. A private/loopback/link-local
		// endpoint is never a valid cross-NAT hole-punch target; reporting one would
		// poison the server's observed-endpoint cache (e.g. a local path a peer
		// learned over another overlay), so skip it.
		ip := dp.Endpoint.IP
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if dp.LastHandshakeTime.IsZero() || now.Sub(dp.LastHandshakeTime) >= handshakeFreshness {
			continue
		}
		out[pk] = dp.Endpoint.String()
	}
	return out
}

// sameStringMap reports whether two string maps are identical.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// directReachability returns how many of the host's non-relay peers currently
// have a LIVE direct (hole-punched) path, and the total number of such peers it
// could evaluate. The auto-relay node is excluded (it is public and always
// reachable, so it must not mask isolation from the actual peers).
//
// A peer's direct path is live when it has a fresh WireGuard handshake AND its
// inbound byte counter is moving. The byte-counter (active liveness) check makes
// the direct->relay fallback fast: with the default 20s keepalive we keep
// transmitting, so if we are still sending but have received nothing for
// rxStallTimeout (~35s) the path is dead — detected long before the handshake
// goes stale (~150s). The traffic map carries per-peer counter state across
// ticks and is pruned to the current peer set.
//
// "No information" cases (no peers, unreadable device state) return (0,0) so the
// caller treats them as "nothing decided", never as "all reachable".
func directReachability(relayPubKey string, traffic map[string]*peerTraffic, now time.Time) (reachable, total int) {
	nc := config.Netclient()
	peers := nc.HostPeers
	if len(peers) == 0 {
		return 0, 0
	}
	devicePeers, err := wireguard.GetPeersFromDevice(ncutils.GetInterfaceName())
	if err != nil {
		return 0, 0
	}
	seen := map[string]bool{}
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
		total++

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
		reachable++
	}
	for pk := range traffic {
		if !seen[pk] {
			delete(traffic, pk)
		}
	}
	return reachable, total
}
