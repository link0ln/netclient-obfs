//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"errors"
	"net"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/gravitl/netclient/config"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// applyUserspace is a no-op on unix: the userspace amneziawg-go device is
// configured via wgctrl over the unix socket (/var/run/wireguard), which works.
// Returning handled=false keeps the wgctrl code path in apply().
func applyUserspace(*wgtypes.Config) (bool, error) { return false, nil }

// userspacePeers is a no-op on unix; wgctrl reads the device fine.
func userspacePeers(string) (map[string]wgtypes.Peer, bool) { return nil, false }

// == private ==

var tunDevice *device.Device
var wg sync.WaitGroup
var uapi net.Listener

func (nc *NCIface) createUserSpaceWG() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	tunIface, err := tun.CreateTUN(nc.Name, config.Netclient().MTU)
	if err != nil {
		return err
	}
	nc.Iface = tunIface
	tunDevice = device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[netclient] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	// Apply the AmneziaWG DPI-obfuscation profile delivered from the netmaker
	// server (global setting). When disabled/unset the device stays vanilla WG.
	// The parameters must be identical on all peers or the tunnel won't establish.
	if awgConf := buildAWGUAPIConfig(); awgConf != "" {
		if err = tunDevice.IpcSet(awgConf); err != nil {
			slog.Error("failed to apply AmneziaWG obfuscation profile", "error", err)
			return err
		}
		slog.Info("applied AmneziaWG obfuscation profile from server config")
	}
	uapi, err = getUAPIByInterface(nc.Name)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tunDevice.Wait():
				slog.Debug("tunDevice.Wait() returned")
				return
			default:
				if uapi == nil {
					return
				}
				uapiConn, uapiErr := uapi.Accept()
				if uapiErr != nil {
					slog.Debug("uapi error:", "error", uapiErr)
					continue
				}
				go tunDevice.IpcHandle(uapiConn)
			}
		}
	}()
	return nil
}

func getUAPIByInterface(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}

func (nc *NCIface) closeUserspaceWg() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	slog.Debug("Closing userspace WireGuard interface", "interface", nc.Name)

	if tunDevice != nil {
		tunDevice.Close()
	}
	if uapi != nil {
		uapi.Close()
	}
	wg.Wait()

	slog.Debug("Closed userspace WireGuard interface", "interface", nc.Name)

	return nil
}

func isEconnRefused(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errors.Is(errno, syscall.ECONNREFUSED)
}
