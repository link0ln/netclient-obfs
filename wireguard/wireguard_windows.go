package wireguard

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	awgipc "github.com/amnezia-vpn/amneziawg-go/ipc"
	awgtun "github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/google/uuid"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TODO: update from netsh to a more programmatic approach.

// NCIface.Create - makes a new Wireguard interface and sets given addresses
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	// When AmneziaWG obfuscation is enabled we must use the userspace amneziawg-go
	// dataplane (the wireguard-nt kernel driver cannot apply jc/s/h obfuscation),
	// so force userspace over Wintun even though Windows normally uses the driver.
	if amneziaWGEnabled() {
		slog.Info("AmneziaWG enabled: using userspace amneziawg-go dataplane (windows)")
		return nc.createUserSpaceWGWindows()
	}

	var ifaceMetric uint32
	if !nc.IsTestIface {
		ifaceMetric, _ = getResolvingInterfaceMetric()
	}

	adapter, err := driver.OpenAdapter(nc.Name)
	if err != nil {
		slog.Info("creating Windows tunnel")
		idString := config.Netclient().Host.ID.String()
		if idString == "" {
			idString = config.DefaultHostID
		}
		if nc.IsTestIface {
			idString = uuid.NewString()
		}
		windowsGUID, err := windows.GUIDFromString("{" + idString + "}")
		if err != nil {
			slog.Error("generating guid error: ", "error", err)
			return err
		}
		adapter, err = driver.CreateAdapter(nc.Name, "WireGuard", &windowsGUID)
		if err != nil {
			// Check if adapter already exists - try to open it again
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "Cannot create a file when that file already exists") {
				slog.Info("adapter already exists, attempting to open it")
				// Retry opening the adapter - it might have been created by another process
				var openErr error
				adapter, openErr = driver.OpenAdapter(nc.Name)
				if openErr != nil {
					slog.Error("creating adapter error (adapter exists but cannot be opened): ", "error", err, "openError", openErr)
					return fmt.Errorf("adapter exists but cannot be opened: %w (original error: %v)", openErr, err)
				}
				slog.Info("successfully opened existing adapter")
				err = nil // Clear the error since we successfully opened the adapter
			} else {
				slog.Error("creating adapter error: ", "error", err)
				return err
			}
		}
	} else {
		slog.Info("re-using existing adapter")
	}

	slog.Info("created Windows tunnel")
	nc.Iface = adapter
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return err
	}

	if ifaceMetric != 0 {
		_, err = runPSCommand(fmt.Sprintf("Set-NetIPInterface -InterfaceAlias '%s' -InterfaceMetric %d", nc.Name, ifaceMetric+1))
		if err != nil {
			return err
		}
	}

	return nil
}

// NCIface.ApplyAddrs - applies addresses to windows tunnel ifaces, unused currently
func (nc *NCIface) ApplyAddrs() error {
	adapter := nc.Iface
	prefixAddrs := []netip.Prefix{}
	for i := range nc.Addresses {

		maskSize, _ := nc.Addresses[i].Network.Mask.Size()
		slog.Info("appending address", "address", fmt.Sprintf("%s/%d to nm interface", nc.Addresses[i].IP.String(), maskSize))
		addr, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", nc.Addresses[i].IP.String(), maskSize))
		if err == nil {
			prefixAddrs = append(prefixAddrs, addr)
		} else {
			slog.Error("failed to append ip to Netclient adapter", "error", err)
		}
	}

	switch a := adapter.(type) {
	case *driver.Adapter:
		return a.LUID().SetIPAddresses(prefixAddrs)
	case *userspaceWGWin:
		luid := a.luid()
		slog.Info("setting addresses on userspace adapter", "luid", uint64(luid), "addrs", fmt.Sprintf("%v", prefixAddrs))
		if err := luid.SetIPAddresses(prefixAddrs); err != nil {
			return fmt.Errorf("winipcfg SetIPAddresses (luid=%d): %w", uint64(luid), err)
		}
		return nil
	default:
		return fmt.Errorf("unknown windows interface type %T", adapter)
	}
}

// userspaceWGWin bundles the userspace amneziawg-go dataplane objects (Wintun
// tun + wireguard device + UAPI named-pipe listener) so they satisfy the
// netIface contract (Close) and can be torn down together. Used on Windows when
// AmneziaWG obfuscation is enabled, in place of the wireguard-nt kernel driver.
type userspaceWGWin struct {
	tun    awgtun.Device
	device *awgdevice.Device
	uapi   net.Listener
	wg     sync.WaitGroup
}

// Close satisfies netIface: stops the UAPI listener, shuts down the device and
// waits for the accept goroutine, then closes the Wintun adapter.
func (u *userspaceWGWin) Close() error {
	if activeUserspaceWin == u {
		activeUserspaceWin = nil
	}
	if u.uapi != nil {
		u.uapi.Close()
	}
	if u.device != nil {
		u.device.Close() // also closes the underlying tun
	}
	u.wg.Wait()
	return nil
}

// luid returns the Wintun adapter LUID for IP/route configuration via winipcfg.
func (u *userspaceWGWin) luid() winipcfg.LUID {
	if nt, ok := u.tun.(*awgtun.NativeTun); ok {
		return winipcfg.LUID(nt.LUID())
	}
	return 0
}

// userspacePeers reads peer handshake times directly from the userspace
// amneziawg-go device via its UAPI (device.IpcGet), used on Windows where wgctrl
// cannot read the device. Returns (nil, false) when no userspace device is active
// so callers fall back to wgctrl.
func userspacePeers(string) (map[string]wgtypes.Peer, bool) {
	if activeUserspaceWin == nil || activeUserspaceWin.device == nil {
		return nil, false
	}
	uapi, err := activeUserspaceWin.device.IpcGet()
	if err != nil {
		return nil, false
	}
	peers := make(map[string]wgtypes.Peer)
	var cur *wgtypes.Peer
	var curKey string
	flush := func() {
		if cur != nil && curKey != "" {
			peers[curKey] = *cur
		}
	}
	for _, line := range strings.Split(uapi, "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "public_key":
			flush()
			cur, curKey = nil, ""
			b, derr := hex.DecodeString(kv[1])
			if derr != nil || len(b) != 32 {
				continue
			}
			var key wgtypes.Key
			copy(key[:], b)
			p := wgtypes.Peer{PublicKey: key}
			cur, curKey = &p, key.String()
		case "last_handshake_time_sec":
			if cur != nil {
				if sec, perr := strconv.ParseInt(kv[1], 10, 64); perr == nil && sec > 0 {
					cur.LastHandshakeTime = time.Unix(sec, 0)
				}
			}
		}
	}
	flush()
	return peers, true
}

// createUserSpaceWGWindows brings up the netmaker interface on Windows using the
// userspace amneziawg-go dataplane over Wintun and applies the server-delivered
// AmneziaWG obfuscation profile. Requires wintun.dll alongside the executable.
func (nc *NCIface) createUserSpaceWGWindows() error {
	tunDev, err := awgtun.CreateTUN(nc.Name, config.Netclient().MTU)
	if err != nil {
		return fmt.Errorf("failed to create wintun tun: %w", err)
	}
	dev := awgdevice.NewDevice(tunDev, awgconn.NewDefaultBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, "[netclient] "))
	if err := dev.Up(); err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to bring up userspace device: %w", err)
	}
	if awgConf := buildAWGUAPIConfig(); awgConf != "" {
		if err := dev.IpcSet(awgConf); err != nil {
			dev.Close()
			return fmt.Errorf("failed to apply AmneziaWG obfuscation profile: %w", err)
		}
		slog.Info("applied AmneziaWG obfuscation profile from server config (windows userspace)")
	}
	uapi, err := awgipc.UAPIListen(nc.Name)
	if err != nil {
		dev.Close()
		return fmt.Errorf("failed to listen on UAPI named pipe: %w", err)
	}
	u := &userspaceWGWin{tun: tunDev, device: dev, uapi: uapi}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		for {
			conn, acceptErr := uapi.Accept()
			if acceptErr != nil {
				return
			}
			go dev.IpcHandle(conn)
		}
	}()
	nc.Iface = u
	activeUserspaceWin = u
	slog.Info("created Windows userspace (amneziawg-go) tunnel")
	return nil
}

// activeUserspaceWin points at the live userspace dataplane (if any) so apply()
// can configure it directly via UAPI, bypassing wgctrl. Set in
// createUserSpaceWGWindows, cleared in userspaceWGWin.Close.
var activeUserspaceWin *userspaceWGWin

// applyUserspace configures the userspace amneziawg-go device on Windows directly
// via its UAPI (device.IpcSet), bypassing wgctrl. This is required because
// wgctrl's multi-client dispatch tries the in-kernel client first; on our Wintun
// adapter it returns "Access is denied" (not os.ErrNotExist), so the loop never
// reaches the userspace named-pipe client. Returns handled=false when no userspace
// device is active (the wireguard-nt kernel-driver path), so apply() uses wgctrl.
func applyUserspace(c *wgtypes.Config) (bool, error) {
	if activeUserspaceWin == nil || activeUserspaceWin.device == nil {
		return false, nil
	}
	if err := activeUserspaceWin.device.IpcSet(wgtypesToUAPI(c)); err != nil {
		return true, fmt.Errorf("device.IpcSet: %w", err)
	}
	return true, nil
}

// wgtypesToUAPI serializes a wgtypes.Config into the WireGuard UAPI "set" text
// protocol (hex-encoded keys), suitable for device.IpcSet. Mirrors what wgctrl
// would send over the socket/pipe.
func wgtypesToUAPI(c *wgtypes.Config) string {
	var b strings.Builder
	if c.PrivateKey != nil {
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey[:]))
	}
	if c.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *c.ListenPort)
	}
	if c.FirewallMark != nil {
		fmt.Fprintf(&b, "fwmark=%d\n", *c.FirewallMark)
	}
	if c.ReplacePeers {
		b.WriteString("replace_peers=true\n")
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.UpdateOnly {
			b.WriteString("update_only=true\n")
		}
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}
		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
		}
		for j := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", p.AllowedIPs[j].String())
		}
	}
	return b.String()
}

// RemoveRoutes - remove routes to the interface
func RemoveRoutes(addrs []ifaceAddress) {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("removing ipv4 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("removing ipv6 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String(), err.Error())
			}
		}
	}
}

// SetRoutes - sets additional routes to the interface
func SetRoutes(addrs []ifaceAddress) error {
	for _, addr := range addrs {
		if (len(config.GetNodes()) > 1 && addr.IP == nil) || addr.Network.IP == nil || addr.Network.String() == IPv4Network ||
			addr.Network.String() == IPv6Network || (len(config.GetNodes()) > 1 && addr.GwIP == nil) {
			continue
		}
		if addr.Network.IP.To4() != nil {
			slog.Info("adding ipv4 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			out, err := ncutils.RunCmd(cmd, false)
			if err != nil && !strings.Contains(out, "already exists") {
				slog.Error("failed to apply", "ipv4 egress range", addr.Network.String(), err.Error())
			}
		} else {
			slog.Info("adding ipv6 route to interface", "route", fmt.Sprintf("%s -> %s ->%s", addr.IP.String(), addr.Network.String(), addr.GwIP.String()))
			cmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=%s metric=%d",
				addr.Network.String(), ncutils.GetInterfaceName(), addr.GwIP.String(), "active", addr.Metric)
			out, err := ncutils.RunCmd(cmd, false)
			if err != nil && !strings.Contains(out, "already exists") {
				slog.Error("failed to apply", "ipv6 egress range", addr.Network.String(), err.Error())
			}
		}
	}
	return nil
}

func getInterfaceInfo() (iList []string, err error) {
	//get current interfaces
	output, err := ncutils.RunCmd("netsh int ipv4 show interfaces", true)
	if err != nil {
		return iList, err
	}

	if strings.Contains(output, "\r") {
		iList = strings.Split(output, "\r")
	} else if strings.Contains(output, "\n") {
		iList = strings.Split(output, "\n")
	}

	return iList, nil
}

// getDefaultGateway - an internal function to get the default gateway route entry
func getDefaultGateway() (output []string, err error) {

	//get current ipv4 route
	input, err := ncutils.RunCmd("netsh int ipv4 show route", true)
	if err != nil {
		return []string{}, err
	}

	//split the output to multiple lines
	var rList []string
	if strings.Contains(input, "\r") {
		rList = strings.Split(input, "\r")
	} else if strings.Contains(input, "\n") {
		rList = strings.Split(input, "\n")
	}

	//get the lines with gateway route
	rLines := []string{}
	for _, l := range rList {
		if strings.Contains(l, IPv4Network) {
			rLines = append(rLines, l)
		}
	}

	if len(rLines) == 0 {
		//get current ipv6 route
		input, err := ncutils.RunCmd("netsh int ipv6 show route", true)
		if err != nil {
			return []string{}, err
		}

		//split the output to multiple lines
		var rList []string
		if strings.Contains(input, "\r") {
			rList = strings.Split(input, "\r")
		} else if strings.Contains(input, "\n") {
			rList = strings.Split(input, "\n")
		}

		//get the lines with gateway route
		for _, l := range rList {
			if strings.Contains(l, IPv6Network) {
				rLines = append(rLines, l)
			}
		}
	}

	//in case that multiple default gateway in the route table, return the one with higher priority
	if len(rLines) == 0 {
		output = []string{}
	} else if len(rLines) == 1 {
		output = strings.Fields(rLines[0])
	} else {
		metric := 10000
		iList, err := getInterfaceInfo()
		if err != nil {
			iList = []string{}
		} else {
			//remove the empty and title lines
			iList = iList[3:]
		}
		for _, r := range rLines {
			//on Windows, when "Automatic Metric" is enabled on interface, there is a default metric for each route entry
			//So the overall metric will be "default metric"+"route entry metric"
			dMetric := 0
			rArray := strings.Fields(r)

			//get the default metric value,  dMetric, by matching the interface Idx
			if len(iList) > 0 {
				for _, if1 := range iList {
					iArray := strings.Fields(if1)

					//match with Idx, first column in interface info,  last second column in route info
					if strings.TrimSpace(rArray[len(rArray)-2]) == strings.TrimSpace(iArray[0]) {
						//default metric in in the second column in inteface info
						j, err := strconv.Atoi(iArray[1])
						if err == nil && j >= 0 {
							dMetric = j
							break
						}
					}
				}
			}

			//get the gateway ip with lowest metric
			i, err := strconv.Atoi(rArray[2])
			if err == nil && i+dMetric <= metric {
				metric = i
				output = rArray
			}
		}
	}

	if len(output) == 0 {
		output = strings.Fields(rLines[0])
	}
	return output, nil
}

// GetDefaultGatewayIp - get current default gateway ip
func GetDefaultGatewayIp() (ip net.IP, err error) {

	//filter and get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		return ip, errors.New("no default gateway found, please run command route -n to check in the route table")
	}

	//get the ip address from the last column
	ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
	ip = net.ParseIP(ipString)

	return ip, nil
}

// SetInternetGw - set a new default gateway and the route to Internet Gw's ip address
func SetInternetGw(publicKey string, networkIP net.IP) (err error) {
	err = setDefaultRoutesOnHost(publicKey, networkIP)
	if err == nil {
		GetIGWMonitor().Monitor(publicKey, networkIP)
	}

	return err
}

func setDefaultRoutesOnHost(publicKey string, networkIP net.IP) error {
	if ipv4 := networkIP.To4(); ipv4 != nil {
		return setInternetGwV4(publicKey, networkIP)
	} else {
		return setInternetGwV6(publicKey, networkIP)
	}
}

// setInternetGwV6 - set a new default gateway and the route to Internet Gw's ip address
func setInternetGwV6(publicKey string, networkIP net.IP) (err error) {

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "0" && ipString != networkIP.String() {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv6 set route %s interface=%s nexthop=%s store=active metric=50", IPv6Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 50 manaull to avoid issue", "error")
				slog.Error("netsh int ipv6 set route ::/0 interface=<Idx> nexthop=<ipv6 address> store=active metric=50", "error")
			}
		}

		igw, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
		if err == nil {
			destination := igw.Endpoint.IP.String() + "/128"
			gwRouteCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=active metric=1", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)
			_, err = ncutils.RunCmd(gwRouteCmd, true)
			if err != nil {
				slog.Error("Failed to add route to gateway", "error", err.Error())
			}
		}
	}

	//add new gateway route with metric 0 for setting to top priority
	addGwCmd := fmt.Sprintf("netsh int ipv6 add route %s interface=%s nexthop=%s store=active metric=0", IPv6Network, ncutils.GetInterfaceName(), networkIP.String())

	_, err = ncutils.RunCmd(addGwCmd, true)
	if err != nil {
		slog.Error("Failed to add route table", "error", err.Error())
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP
	return nil
}

// setInternetGwV4 - set a new default gateway and the route to Internet Gw's ip address
func setInternetGwV4(publicKey string, networkIP net.IP) (err error) {

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "0" && ipString != networkIP.String() {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=50", IPv4Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 50 manaull to avoid issue", "error")
				slog.Error("netsh int ipv4 set route 0.0.0.0/0 interface=<Idx> nexthop=<192.168.1.1> store=active metric=50", "error")
			}
		}

		igw, err := GetPeer(ncutils.GetInterfaceName(), publicKey)
		if err == nil {
			destination := igw.Endpoint.IP.String() + "/32"
			gwRouteCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=active metric=1", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)
			slog.Info(gwRouteCmd)
			_, err = ncutils.RunCmd(gwRouteCmd, true)
			if err != nil {
				slog.Error("Failed to add route to gateway", "error", err.Error())
			}
		}
	}

	//add new gateway route with metric 0 for setting to top priority
	addGwCmd := fmt.Sprintf("netsh int ipv4 add route %s interface=%s nexthop=%s store=active metric=0", IPv4Network, ncutils.GetInterfaceName(), networkIP.String())

	_, err = ncutils.RunCmd(addGwCmd, true)
	if err != nil {
		slog.Error("Failed to add route table", "error", err.Error())
		return err
	}

	config.Netclient().CurrGwNmIP = networkIP

	return nil
}

// RestoreInternetGw - restore the old default gateway and delte the route to the Internet Gw's ip address
func RestoreInternetGw() (err error) {
	err = resetDefaultRoutesOnHost()
	if err == nil {
		GetIGWMonitor().Stop()
	}

	return err
}

func resetDefaultRoutesOnHost() error {
	if ipv4 := config.Netclient().OriginalDefaultGatewayIp.To4(); ipv4 != nil {
		return restoreInternetGwV4()
	} else {
		return restoreInternetGwV6()
	}
}

// restoreInternetGwV6 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV6() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv6 delete route %s interface=%s store=active", IPv6Network, ncutils.GetInterfaceName())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	var destination string
	for _, peer := range config.Netclient().HostPeers {
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.String() == IPv6Network {
				destination = peer.Endpoint.IP.String() + "/128"
			}
		}
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "50" {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv6 set route %s interface=%s nexthop=%s store=active metric=0", IPv6Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 0 manually to avoid issue", "error")
				slog.Error("netsh int ipv6 set route ::/0 interface=<Idx> nexthop=<ipv6 address> store=active metric=0", "error")
			}
		}

		if destination != "" {
			delCmd := fmt.Sprintf("netsh int ipv6 delete route %s %s store=active", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]))
			_, err = ncutils.RunCmd(delCmd, true)
			if err != nil {
				slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
				return err
			}
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// restoreInternetGwV4 - restore the old default gateway and delte the route to the Internet Gw's ip address
func restoreInternetGwV4() (err error) {

	delCmd := fmt.Sprintf("netsh int ipv4 delete route %s interface=%s store=active", IPv4Network, ncutils.GetInterfaceName())

	_, err = ncutils.RunCmd(delCmd, true)
	if err != nil {
		slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
		return err
	}

	var destination string
	for _, peer := range config.Netclient().HostPeers {
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.String() == IPv4Network {
				destination = peer.Endpoint.IP.String() + "/32"
			}
		}
	}

	//get current default gateway route
	gwRoute, err := getDefaultGateway()
	if err != nil || len(gwRoute) == 0 {
		slog.Error("no default gateway found, please run command route -n to check in the route table", "error", err.Error())
	} else {
		//if default gateway metric is 0, then reset it to 50
		ipString := strings.TrimSpace(gwRoute[len(gwRoute)-1])
		metric := strings.TrimSpace(gwRoute[2])
		if metric == "50" {
			//set the original gateway metric to 50
			setGwCmd := fmt.Sprintf("netsh int ipv4 set route %s interface=%s nexthop=%s store=active metric=0", IPv4Network, strings.TrimSpace(gwRoute[len(gwRoute)-2]), ipString)

			_, err = ncutils.RunCmd(setGwCmd, true)
			if err != nil {
				slog.Error("Failed to set original gateway route metric", "error", err.Error())
				slog.Error("please change the metric to 0 manually to avoid issue", "error")
				slog.Error("netsh int ipv4 set route 0.0.0.0/0 interface=<Idx> nexthop=<192.168.1.1> store=active metric=0", "error")
			}
		}

		if destination != "" {
			delCmd := fmt.Sprintf("netsh int ipv4 delete route %s %s store=active", destination, strings.TrimSpace(gwRoute[len(gwRoute)-2]))
			_, err = ncutils.RunCmd(delCmd, true)
			if err != nil {
				slog.Error("Failed to delete route, please delete it manually", "error", err.Error())
				return err
			}
		}
	}

	config.Netclient().CurrGwNmIP = net.ParseIP("")
	return config.WriteNetclientConfig()
}

// NCIface.Close - closes the managed WireGuard interface
func (nc *NCIface) Close() {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	err := nc.Iface.Close()
	if err != nil {
		logger.Log(0, "error closing netclient interface -", err.Error())
	}

	// clean up egress range routes
	for i := range nc.Addresses {
		if nc.Addresses[i].Network.String() == "0.0.0.0/0" ||
			nc.Addresses[i].Network.String() == "::/0" {
			continue
		}
		if nc.Addresses[i].AddRoute {
			maskSize, _ := nc.Addresses[i].Network.Mask.Size()
			logger.Log(1, "removing egress range", fmt.Sprintf("%s/%d from nm interface", nc.Addresses[i].IP.String(), maskSize))
			cmd := fmt.Sprintf("route delete %s", nc.Addresses[i].IP.String())
			_, err := ncutils.RunCmd(cmd, false)
			if err != nil {
				logger.Log(0, "failed to remove egress range", nc.Addresses[i].IP.String())
			}
		}
	}
}

// NCIface.SetMTU - sets the MTU of the windows WireGuard Iface adapter
func (nc *NCIface) SetMTU() error {
	// TODO figure out how to change MTU of adapter
	return nil
}

// DeleteOldInterface - removes named interface
func DeleteOldInterface(iface string) {
	logger.Log(0, "deleting interface", iface)
	if _, err := ncutils.RunCmd("wireguard.exe /uninstalltunnelservice "+iface, true); err != nil {
		logger.Log(1, err.Error())
	}
}

func isEconnRefused(err error) bool {
	var winerrno windows.Errno
	return errors.As(err, &winerrno) && errors.Is(winerrno, windows.WSAECONNREFUSED)
}

func getResolvingInterfaceMetric() (uint32, error) {
	testDomain := "netmaker.io"

	output, err := runPSCommand("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex, ServerAddresses | ConvertTo-Json")
	if err != nil {
		return 0, err
	}

	type dnsEntry struct {
		InterfaceIndex  int      `json:"InterfaceIndex"`
		ServerAddresses []string `json:"ServerAddresses"`
	}

	var entries []dnsEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entries); err != nil {
		return 0, err
	}

	var lowest uint32 = math.MaxUint32
	for _, entry := range entries {
		for _, dnsServer := range entry.ServerAddresses {
			resolveOut, err := runPSCommand(fmt.Sprintf(
				"Resolve-DnsName '%s' -Server '%s' -Type A -ErrorAction SilentlyContinue",
				testDomain, dnsServer))
			if err == nil && strings.Contains(resolveOut, testDomain) {
				metricOut, err := runPSCommand(fmt.Sprintf(
					"(Get-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4).InterfaceMetric",
					entry.InterfaceIndex))
				if err != nil {
					return 0, err
				}

				metric, err := strconv.ParseUint(strings.TrimSpace(metricOut), 10, 32)
				if err != nil {
					return 0, err
				}

				if lowest > uint32(metric) {
					lowest = uint32(metric)
				}
			}
		}
	}

	if lowest == math.MaxUint32 {
		return 0, fmt.Errorf("no interface found that could resolve %s", testDomain)
	}

	return lowest, nil
}

func runPSCommand(command string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.Output()
	return string(out), err
}
