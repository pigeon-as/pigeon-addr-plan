package addr

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
)

func TestHashPrefix_Deterministic(t *testing.T) {
	base := netip.MustParsePrefix("fd10::/16")
	a, err := HashPrefix(base, 32, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPrefix(base, 32, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("not deterministic: %s != %s", a, b)
	}
}

func TestHashPrefix_DifferentNames(t *testing.T) {
	base := netip.MustParsePrefix("fd10::/16")
	a, _ := HashPrefix(base, 32, "host-a")
	b, _ := HashPrefix(base, 32, "host-b")
	if a == b {
		t.Fatal("different names produced same prefix")
	}
}

func TestHashPrefix_PrefixLength(t *testing.T) {
	base := netip.MustParsePrefix("fd10::/16")
	sub, _ := HashPrefix(base, 32, "test")
	if sub.Bits() != 48 {
		t.Fatalf("prefix length = %d, want 48", sub.Bits())
	}
}

// TestHashPrefix_SHA256 verifies the hash-to-prefix mapping uses SHA-256.
func TestHashPrefix_SHA256(t *testing.T) {
	name := "acme"
	h := sha256.Sum256([]byte(name))
	oh1 := fmt.Sprintf("%04x", uint16(h[0])<<8|uint16(h[1]))
	oh2 := fmt.Sprintf("%04x", uint16(h[2])<<8|uint16(h[3]))

	// 32-bit derivation from /32 base → /64.
	base := netip.MustParsePrefix("fdaa:abcd::/32")
	sub, err := HashPrefix(base, 32, name)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("fdaa:abcd:%s:%s::/64", oh1, oh2)
	if sub.String() != want {
		t.Fatalf("HashPrefix = %s, want %s", sub, want)
	}

	// 16-bit derivation from /16 base → /32.
	route, err := HashPrefix(netip.MustParsePrefix("fdaa::/16"), 16, name)
	if err != nil {
		t.Fatal(err)
	}
	wantRoute := fmt.Sprintf("fdaa:%s::/32", oh1)
	if route.String() != wantRoute {
		t.Fatalf("route HashPrefix = %s, want %s", route, wantRoute)
	}
}

func TestHashPrefix_IPv4(t *testing.T) {
	base := netip.MustParsePrefix("10.0.0.0/8")
	sub, err := HashPrefix(base, 8, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Bits() != 16 {
		t.Fatalf("prefix length = %d, want 16", sub.Bits())
	}
	if !sub.Addr().Is4() {
		t.Fatal("expected IPv4 result")
	}
}

func TestHashPrefix_InvalidNewBits(t *testing.T) {
	base := netip.MustParsePrefix("fd10::/16")
	if _, err := HashPrefix(base, 0, "x"); err == nil {
		t.Fatal("expected error for newBits=0")
	}
	if _, err := HashPrefix(base, 200, "x"); err == nil {
		t.Fatal("expected error for newBits too large")
	}
}

func TestHostAddr(t *testing.T) {
	prefix := netip.MustParsePrefix("fd10:abcd:ef01::/48")

	gw, err := HostAddr(prefix, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gw.String() != "fd10:abcd:ef01::1" {
		t.Fatalf("HostAddr(1) = %s, want fd10:abcd:ef01::1", gw)
	}

	net0, _ := HostAddr(prefix, 0)
	if net0.String() != "fd10:abcd:ef01::" {
		t.Fatalf("HostAddr(0) = %s, want fd10:abcd:ef01::", net0)
	}
}

func TestHostAddr_IPv4(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.1.0/24")
	h, err := HostAddr(prefix, 5)
	if err != nil {
		t.Fatal(err)
	}
	if h.String() != "10.0.1.5" {
		t.Fatalf("HostAddr(5) = %s, want 10.0.1.5", h)
	}
}

func TestHostAddr_NoHostBits(t *testing.T) {
	if _, err := HostAddr(netip.MustParsePrefix("fd10::1/128"), 1); err == nil {
		t.Fatal("expected error for /128 prefix")
	}
}
