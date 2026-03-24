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

import (
	"fmt"
	"net/netip"
)

const (
	NetworkBits = 32 // ULA /16 → /48 per network
	HostBits    = 32 // network /48 → /80 per host
)

var (
	pigeonULA = netip.MustParsePrefix("fdaa::/16")
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
)

func PigeonULARange() netip.Prefix { return pigeonULA }

// CGNATRange returns the Carrier Grade NAT range (100.64.0.0/10).
func CGNATRange() netip.Prefix { return cgnat }

// IsPigeonIP reports whether ip falls within pigeon's ULA range.
func IsPigeonIP(ip netip.Addr) bool { return pigeonULA.Contains(ip) }

// TransposePigeonULA is self-inverse.
func TransposePigeonULA(ip netip.Addr) (netip.Addr, bool) {
	if !IsPigeonIP(ip) {
		return netip.Addr{}, false
	}
	b := ip.As16()
	// Exchange bytes 2–5 (network) and 6–9 (host).
	for i := range NetworkBits / 8 {
		b[2+i], b[6+i] = b[6+i], b[2+i]
	}
	return netip.AddrFrom16(b), true
}

// PigeonHostIP returns the overlay IP for a physical host.
// Deterministically derived from hostname: fdaa:0:0:HHHH:HHHH::1 (app-view).
func PigeonHostIP(hostname string) (netip.Addr, error) {
	host, err := HashPrefix(PigeonULARange(), NetworkBits, hostname)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("hash host prefix: %w", err)
	}
	ip, err := HostAddr(host, 1)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("host addr: %w", err)
	}
	transposed, ok := TransposePigeonULA(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("transpose %s: not a pigeon ULA address", ip)
	}
	return transposed, nil
}

// PigeonHostRoute returns the wire-view /48 routing prefix for a physical host.
// Used as the WireGuard AllowedIPs entry for cryptokey routing.
func PigeonHostRoute(hostname string) (netip.Prefix, error) {
	return HashPrefix(PigeonULARange(), NetworkBits, hostname)
}
