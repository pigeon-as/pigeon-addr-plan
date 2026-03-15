// Pigeon address plan — ranges, bit widths, and WireGuard routing transform.
//
// Address layout — network first, then host:
//
//	 fdaa::/16                                    PigeonULARange
//	  fdaa:NNNN:NNNN::/48                        network = HashPrefix(ULA, NetworkBits, name)
//	    fdaa:NNNN:NNNN:HHHH:HHHH::/80            host    = HashPrefix(net, HostBits, hostname)
//	      fdaa:NNNN:NNNN:HHHH:HHHH::1            addr    = HostAddr(host, 1)
//
// WireGuard routing: [TransposePigeonULA] exchanges network and host fields so each
// physical host owns a non-overlapping /48 for cryptokey routing (AllowedIPs):
//
//	App view:  fdaa:[net32]:[host32]:[rest]      — same-network VMs share /48
//	Wire view: fdaa:[host32]:[net32]:[rest]      — each host owns /48

package addr

import "net/netip"

const (
	NetworkBits = 32 // ULA /16 → /48 per network
	HostBits    = 32 // network /48 → /80 per host
)

var pigeonULA = netip.MustParsePrefix("fdaa::/16")

func PigeonULARange() netip.Prefix { return pigeonULA }

func IsPigeonIP(ip netip.Addr) bool { return pigeonULA.Contains(ip) }

// TransposePigeonULA is self-inverse.
func TransposePigeonULA(addr netip.Addr) netip.Addr {
	b := addr.As16()
	// Exchange bytes 2–5 (network) and 6–9 (host).
	for i := range NetworkBits / 8 {
		b[2+i], b[6+i] = b[6+i], b[2+i]
	}
	return netip.AddrFrom16(b)
}
