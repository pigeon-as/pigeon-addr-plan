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

func TestTransposePigeonULA_RoundTrip(t *testing.T) {
	ip := netip.MustParseAddr("fdaa:1111:2222:3333:4444:5555:6666:7777")
	w, ok := TransposePigeonULA(ip)
	if !ok {
		t.Fatal("expected ok")
	}
	rt, ok := TransposePigeonULA(w)
	if !ok {
		t.Fatal("expected ok on round-trip")
	}
	if rt != ip {
		t.Fatalf("not self-inverse: got %s", rt)
	}
}

func TestTransposePigeonULA_Fields(t *testing.T) {
	app := netip.MustParseAddr("fdaa:1111:2222:3333:4444::1")
	wire, ok := TransposePigeonULA(app)
	if !ok {
		t.Fatal("expected ok")
	}
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
	w1, _ := TransposePigeonULA(vm1)
	w2, _ := TransposePigeonULA(vm2)
	wire1 := w1.As16()
	wire2 := w2.As16()
	for i := 0; i < 6; i++ {
		if wire1[i] != wire2[i] {
			t.Fatalf("wire view byte %d differs: %02x != %02x", i, wire1[i], wire2[i])
		}
	}
}

func TestCGNATRange(t *testing.T) {
	r := CGNATRange()
	if r.String() != "100.64.0.0/10" {
		t.Fatalf("CGNATRange() = %s, want 100.64.0.0/10", r)
	}
	if !r.Contains(netip.MustParseAddr("100.64.0.1")) {
		t.Fatal("100.64.0.1 should be in CGNAT range")
	}
	if r.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("10.0.0.1 should not be in CGNAT range")
	}
}

func TestPigeonHostIP(t *testing.T) {
	ip, err := PigeonHostIP("worker-01")
	if err != nil {
		t.Fatal(err)
	}
	if !IsPigeonIP(ip) {
		t.Fatalf("overlay addr %s not in pigeon ULA range", ip)
	}

	// Should be deterministic.
	ip2, err := PigeonHostIP("worker-01")
	if err != nil {
		t.Fatal(err)
	}
	if ip != ip2 {
		t.Fatalf("not deterministic: %s != %s", ip, ip2)
	}

	// App-view: network field (bytes 2-5) should be zero, host field (bytes 6-9) non-zero.
	b := ip.As16()
	allZero := true
	for i := 2; i < 6; i++ {
		if b[i] != 0 {
			allZero = false
		}
	}
	if !allZero {
		t.Fatalf("app-view network field should be zero, got %x", b[2:6])
	}
}

func TestPigeonHostRoute(t *testing.T) {
	p, err := PigeonHostRoute("worker-01")
	if err != nil {
		t.Fatal(err)
	}
	if p.Bits() != 48 {
		t.Fatalf("bits = %d, want 48", p.Bits())
	}
	if !PigeonULARange().Contains(p.Addr()) {
		t.Fatalf("wire prefix %s not in pigeon ULA range", p)
	}

	// PigeonHostIP and PigeonHostRoute should agree: transposing the overlay
	// IP should land in the wire prefix.
	ip, _ := PigeonHostIP("worker-01")
	wire, _ := TransposePigeonULA(ip)
	if !p.Contains(wire) {
		t.Fatalf("transposed overlay %s not in wire prefix %s", wire, p)
	}
}
