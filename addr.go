// Package addr provides hash-based address derivation — deterministic prefix
// allocation from names, without centralized IPAM.
//
// Birthday-paradox collision probability reaches 50% at ~2^(newBits/2) names:
// 16 bits → ~256, 32 bits → ~65K, 48 bits → ~16M.
package addr

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net/netip"
)

// HashPrefix maps a name to a deterministic child prefix within base.
func HashPrefix(base netip.Prefix, newBits int, name string) (netip.Prefix, error) {
	maxBits := bitLen(base.Addr())
	targetBits := base.Bits() + newBits
	if newBits <= 0 || targetBits > maxBits {
		return netip.Prefix{}, fmt.Errorf("invalid newBits %d for /%d prefix (max /%d)", newBits, base.Bits(), maxBits)
	}

	h := sha256.Sum256([]byte(name))
	hashInt := new(big.Int).SetBytes(h[:])

	// Top newBits of the hash select the child prefix.
	netNum := new(big.Int).Rsh(hashInt, uint(len(h)*8-newBits))

	// Place netNum into bits [base.Bits(), targetBits).
	masked := base.Masked()
	baseInt := addrToInt(masked.Addr())
	shift := uint(maxBits - targetBits)
	baseInt.Or(baseInt, new(big.Int).Lsh(netNum, shift))

	addr := intToAddr(baseInt, base.Addr().Is6())
	return netip.PrefixFrom(addr, targetBits), nil
}

// HostAddr returns the address at offset num within prefix (0 = network, 1 = gateway).
func HostAddr(prefix netip.Prefix, num int) (netip.Addr, error) {
	maxBits := bitLen(prefix.Addr())
	hostBits := maxBits - prefix.Bits()
	if hostBits <= 0 {
		return netip.Addr{}, fmt.Errorf("no host bits in /%d prefix", prefix.Bits())
	}

	masked := prefix.Masked()
	addrInt := addrToInt(masked.Addr())
	addrInt.Add(addrInt, big.NewInt(int64(num)))

	return intToAddr(addrInt, prefix.Addr().Is6()), nil
}

func bitLen(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

func addrToInt(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func intToAddr(i *big.Int, is6 bool) netip.Addr {
	if is6 {
		var b [16]byte
		i.FillBytes(b[:])
		return netip.AddrFrom16(b)
	}
	var b [4]byte
	i.FillBytes(b[:])
	return netip.AddrFrom4(b)
}
