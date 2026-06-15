package wireguard

import (
	"fmt"
	"strings"

	"github.com/gravitl/netclient/config"
)

// amneziaWGEnabled reports whether the current server delivered an enabled
// AmneziaWG obfuscation profile. Cross-platform: used by the Linux/unix and
// Windows interface paths to decide whether to force the userspace dataplane.
func amneziaWGEnabled() bool {
	server := config.GetServer(config.CurrServer)
	return server != nil && server.AmneziaWG.Enabled
}

// buildAWGUAPIConfig builds the amneziawg-go UAPI set string (jc/jmin/jmax,
// s1-s4, h1-h4, i1-i5) from the server-delivered AmneziaWG config. Returns ""
// when obfuscation is disabled or no server config is available. Zero-valued
// numeric fields are omitted (amneziawg rejects non-positive jc/jmin/jmax;
// s1-s4 default to 0).
func buildAWGUAPIConfig() string {
	server := config.GetServer(config.CurrServer)
	if server == nil || !server.AmneziaWG.Enabled {
		return ""
	}
	a := server.AmneziaWG
	var b strings.Builder
	writeInt := func(k string, v int) {
		if v > 0 {
			fmt.Fprintf(&b, "%s=%d\n", k, v)
		}
	}
	writeStr := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	writeInt("jc", a.Jc)
	writeInt("jmin", a.Jmin)
	writeInt("jmax", a.Jmax)
	writeInt("s1", a.S1)
	writeInt("s2", a.S2)
	writeInt("s3", a.S3)
	writeInt("s4", a.S4)
	writeStr("h1", a.H1)
	writeStr("h2", a.H2)
	writeStr("h3", a.H3)
	writeStr("h4", a.H4)
	writeStr("i1", a.I1)
	writeStr("i2", a.I2)
	writeStr("i3", a.I3)
	writeStr("i4", a.I4)
	writeStr("i5", a.I5)
	return b.String()
}
