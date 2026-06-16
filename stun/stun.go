package stun

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logger"
	nmmodels "github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"gortc.io/stun"
)

// StunServers holds the STUN servers to use. Self-hosted ONLY — there is NO
// third-party default (no Google). It is populated from the server's advertised
// StunServers, or pointed at the self-hosted server as a fallback; if neither is
// known, it stays empty and STUN is simply skipped (never an external call).
var (
	StunServers = []StunServer{}
)

// StunServer - struct to hold data required for using stun server
type StunServer struct {
	Domain string `json:"domain" yaml:"domain"`
	Port   int    `json:"port" yaml:"port"`
}

// LoadStunServers - load customized stun servers
func LoadStunServers(list string) {
	l1 := strings.Split(list, ",")
	stunServers := []StunServer{}
	for _, v := range l1 {
		l2 := strings.Split(v, ":")
		if len(l2) < 2 {
			continue
		}
		port, _ := strconv.Atoi(l2[1])
		sS := StunServer{Domain: l2[0], Port: port}
		stunServers = append(stunServers, sS)
	}
	if len(stunServers) > 0 {
		StunServers = stunServers
	}

}

// SetDefaultStunServers clears the STUN list. With no self-hosted server known,
// STUN is disabled rather than falling back to any third-party service.
func SetDefaultStunServers() {
	StunServers = []StunServer{}
}

// UseSelfStunServer points STUN at the self-hosted server (host:port). Used as the
// fallback when the server has not yet pushed its StunServers list, so the client
// never depends on a third-party STUN service.
func UseSelfStunServer(host string, port int) {
	if host == "" {
		StunServers = []StunServer{}
		return
	}
	if port <= 0 {
		port = 3478
	}
	StunServers = []StunServer{{Domain: host, Port: port}}
}

// DoesIPExistLocally - checks if the IP address exists on a local interface
func DoesIPExistLocally(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err == nil {
			for j := range addrs {
				netIP, _, err := net.ParseCIDR(addrs[j].String())
				if err == nil {
					if netIP.Equal(ip) {
						return true
					}
				}
			}
		}
	}
	return false
}

// HolePunch - performs udp hole punching on the given port
func HolePunch(portToStun, proto int) (publicIP net.IP, publicPort int, natType string) {
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		SetDefaultStunServers()
	}
	if !server.Stun {
		return
	}

	network := "udp4"
	if proto != 4 {
		network = "udp6"
	}
	firstIdx := -1
	for i, stunServer := range StunServers {
		pubIP, pubPort, nType, err := callHolePunch(stunServer, portToStun, network)
		if err != nil {
			slog.Warn("callHolePunch error", "network", network, "error", err.Error())
			continue
		}
		publicIP, publicPort, natType = pubIP, pubPort, nType
		firstIdx = i
		break
	}

	// NAT type here is only public vs behind_nat. Whether a behind-NAT host actually
	// needs a relay is decided by the liveness-based connectivity manager (which
	// observes real WireGuard handshakes), not by STUN heuristics — STUN cannot
	// reliably predict hole-punch success (e.g. CGNAT passes the symmetric test yet
	// can't be punched). detectSymmetric is kept for diagnostics only.
	_ = firstIdx
	slog.Debug("hole punching complete", "public ip", publicIP.String(), "public port", strconv.Itoa(publicPort), "nat type", natType)
	return
}

// detectSymmetric reports whether the NAT maps a single local socket to different
// external ports for two different STUN destinations (symmetric NAT).
func detectSymmetric(network string, servers []StunServer) bool {
	if len(servers) < 2 {
		return false
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return false
	}
	defer conn.Close()
	s0, err0 := net.ResolveUDPAddr(network, net.JoinHostPort(servers[0].Domain, fmt.Sprintf("%d", servers[0].Port)))
	s1, err1 := net.ResolveUDPAddr(network, net.JoinHostPort(servers[1].Domain, fmt.Sprintf("%d", servers[1].Port)))
	if err0 != nil || err1 != nil {
		return false
	}
	p0, ok0 := stunMappedPort(conn, s0)
	p1, ok1 := stunMappedPort(conn, s1)
	return ok0 && ok1 && p0 != p1
}

// stunMappedPort sends a STUN binding request to server from conn (an unconnected
// UDP socket) and returns the external port the NAT assigned for this socket.
func stunMappedPort(conn *net.UDPConn, server *net.UDPAddr) (int, bool) {
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteToUDP(req.Raw, server); err != nil {
		return 0, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return 0, false
		}
		resp := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if resp.Decode() != nil {
			continue
		}
		if resp.TransactionID != req.TransactionID {
			continue
		}
		var xorAddr stun.XORMappedAddress
		if xorAddr.GetFrom(resp) != nil {
			return 0, false
		}
		return xorAddr.Port, true
	}
}

func callHolePunch(stunServer StunServer, portToStun int, network string) (publicIP net.IP, publicPort int, natType string, err error) {
	s, err := net.ResolveUDPAddr(network, net.JoinHostPort(stunServer.Domain, fmt.Sprintf("%d", stunServer.Port)))
	if err != nil {
		logger.Log(1, "failed to resolve udp addr: ", network, err.Error())
		return nil, 0, "", err
	}
	l := &net.UDPAddr{
		IP:   net.ParseIP(""),
		Port: portToStun,
	}
	slog.Debug(fmt.Sprintf("hole punching port %d via stun server %s:%d", portToStun, stunServer.Domain, stunServer.Port))
	publicIP, publicPort, natType, err = doStunTransaction(l, s)
	if err != nil {
		logger.Log(3, "stun transaction failed: ", stunServer.Domain, err.Error())
		return nil, 0, natType, err
	}

	return
}

func doStunTransaction(lAddr, rAddr *net.UDPAddr) (publicIP net.IP, publicPort int, natType string, err error) {
	conn, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil {
		logger.Log(1, "failed to dial: ", err.Error())
		return
	}
	re := conn.LocalAddr().String()
	lIP := re[0:strings.LastIndex(re, ":")]
	if strings.ContainsAny(lIP, "[") {
		lIP = strings.ReplaceAll(lIP, "[", "")
	}
	if strings.ContainsAny(lIP, "]") {
		lIP = strings.ReplaceAll(lIP, "]", "")
	}

	privIp := net.ParseIP(lIP)
	defer func() {
		if publicIP != nil && privIp != nil && !privIp.Equal(publicIP) {
			natType = nmmodels.NAT_Types.BehindNAT
		} else {
			natType = nmmodels.NAT_Types.Public
		}
	}()
	defer conn.Close()
	c, err := stun.NewClient(conn)
	if err != nil {
		logger.Log(1, "failed to create stun client: ", err.Error())
		return
	}
	defer c.Close()
	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	// Sending request to STUN server, waiting for response message.
	var err1 error
	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			logger.Log(1, "0:stun error: ", res.Error.Error())
			err1 = res.Error
			return
		}
		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			logger.Log(1, "1:stun error: ", res.Error.Error())
			return
		}
		publicIP = xorAddr.IP
		publicPort = xorAddr.Port
	})
	if err != nil {
		logger.Log(1, "2:stun error: ", err.Error())
	}
	if err1 != nil {
		logger.Log(3, "3:stun error: ", err1.Error())
		return nil, 0, natType, err1
	}
	return
}
