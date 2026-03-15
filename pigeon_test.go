package addr

import (
	"net/netip"
	"testing"
)

func TestPigeonULARange(t *testing.T) {
	r := PigeonULARange()
	if r.String() != "fdaa::/16" {
		t.Fatalf("PigeonULARange() = %s, want fdaa::/16", r)
	}
}

func TestIsPigeonIP(t *testing.T) {
	if !IsPigeonIP(netip.MustParseAddr("fdaa::1")) {
		t.Fatal("fdaa::1 should be pigeon IP")
	}
	if IsPigeonIP(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("2001:db8::1 should not be pigeon IP")
	}
}

func TestNetworkBits(t *testing.T) {
	if NetworkBits != 32 {
		t.Fatalf("NetworkBits = %d, want 32", NetworkBits)
	}
}

func TestHostBits(t *testing.T) {
	if HostBits != 32 {
		t.Fatalf("HostBits = %d, want 32", HostBits)
	}
}

// TestAddressTree verifies the full pigeon address hierarchy:
//
//	fdaa::/16 → fdaa:NNNN:NNNN::/48 → fdaa:NNNN:NNNN:HHHH:HHHH::/80 → ::1
func TestAddressTree(t *testing.T) {
	ula := PigeonULARange()

	// Network: /48 per namespace.
	net, err := HashPrefix(ula, NetworkBits, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if net.Bits() != 48 {
		t.Fatalf("network bits = %d, want 48", net.Bits())
	}
	if !ula.Contains(net.Addr()) {
		t.Fatalf("network %s not in ULA %s", net, ula)
	}

	// Host: /80 per host within network.
	host, err := HashPrefix(net, HostBits, "worker-01")
	if err != nil {
		t.Fatal(err)
	}
	if host.Bits() != 80 {
		t.Fatalf("host bits = %d, want 80", host.Bits())
	}
	if !net.Contains(host.Addr()) {
		t.Fatalf("host %s not in network %s", host, net)
	}

	// Gateway: ::1 in the host prefix.
	gw, err := HostAddr(host, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !host.Contains(gw) {
		t.Fatalf("gateway %s not in host %s", gw, host)
	}
}

func TestNetworkDeterministic(t *testing.T) {
	a, _ := HashPrefix(PigeonULARange(), NetworkBits, "prod")
	b, _ := HashPrefix(PigeonULARange(), NetworkBits, "prod")
	if a != b {
		t.Fatalf("not deterministic: %s != %s", a, b)
	}
}

func TestNetworkDifferentNames(t *testing.T) {
	a, _ := HashPrefix(PigeonULARange(), NetworkBits, "prod")
	b, _ := HashPrefix(PigeonULARange(), NetworkBits, "staging")
	if a == b {
		t.Fatal("different names produced same network")
	}
}

func TestTransposePigeonULA_RoundTrip(t *testing.T) {
	ip := netip.MustParseAddr("fdaa:1111:2222:3333:4444:5555:6666:7777")
	if TransposePigeonULA(TransposePigeonULA(ip)) != ip {
		t.Fatalf("TransposePigeonULA is not self-inverse: got %s", TransposePigeonULA(TransposePigeonULA(ip)))
	}
}

func TestTransposePigeonULA_Fields(t *testing.T) {
	// App view: net=1111:2222, host=3333:4444
	app := netip.MustParseAddr("fdaa:1111:2222:3333:4444::1")
	wire := TransposePigeonULA(app)
	// Wire view: host=3333:4444, net=1111:2222
	want := netip.MustParseAddr("fdaa:3333:4444:1111:2222::1")
	if wire != want {
		t.Fatalf("TransposePigeonULA(%s) = %s, want %s", app, wire, want)
	}
}

func TestTransposePigeonULA_HostRouting(t *testing.T) {
	// Two VMs on the same host, different networks.
	// After transpose, they should share a /48 (host-routable for WireGuard AllowedIPs).
	net1, _ := HashPrefix(PigeonULARange(), NetworkBits, "prod")
	net2, _ := HashPrefix(PigeonULARange(), NetworkBits, "staging")
	host1, _ := HashPrefix(net1, HostBits, "worker-01")
	host2, _ := HashPrefix(net2, HostBits, "worker-01")
	vm1, _ := HostAddr(host1, 1)
	vm2, _ := HostAddr(host2, 1)

	// In wire view, same host → first 6 bytes (fdaa + host32) should match.
	wire1 := TransposePigeonULA(vm1).As16()
	wire2 := TransposePigeonULA(vm2).As16()
	for i := 0; i < 6; i++ {
		if wire1[i] != wire2[i] {
			t.Fatalf("wire view byte %d differs: %02x != %02x", i, wire1[i], wire2[i])
		}
	}
}

func TestTransposePigeonULA_PreservesPrefix(t *testing.T) {
	// TransposePigeonULA must not touch bytes 0-1 (fdaa) or 10-15 (rest).
	ip := netip.MustParseAddr("fdaa:aaaa:bbbb:cccc:dddd:1111:2222:3333")
	swapped := TransposePigeonULA(ip)
	b := swapped.As16()
	if b[0] != 0xfd || b[1] != 0xaa {
		t.Fatal("swap altered fdaa prefix")
	}
	orig := ip.As16()
	for i := 10; i < 16; i++ {
		if b[i] != orig[i] {
			t.Fatalf("swap altered byte %d: %02x != %02x", i, b[i], orig[i])
		}
	}
}
