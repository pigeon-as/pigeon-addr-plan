# pigeon-addr-plan

Hash-based address derivation. Deterministic prefix allocation from names, no centralized IPAM.

Combines SHA-256 ([RFC 7217](https://datatracker.ietf.org/doc/html/rfc7217)), prefix-from-hash ([RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193)), and name-as-input ([RFC 7343](https://datatracker.ietf.org/doc/html/rfc7343)) with hierarchical nesting and the WireGuard routing transpose from [Fly.io's 6PN](https://fly.io/blog/ipv6-wireguard-peering/).

## Primitives

| Function | Description |
|----------|-------------|
| `HashPrefix(base, newBits, name)` | Map a name to a child prefix via SHA-256 |
| `HostAddr(prefix, num)` | Host address at offset `num` within a prefix |
| `PigeonULARange()` | Pigeon's ULA base prefix (`fdaa::/16`) |
| `IsPigeonIP(ip)` | Reports whether ip is in `fdaa::/16` |
| `TransposePigeonULA(ip)` | Exchange network/host fields for WireGuard routing |

## Pigeon Address Plan

Network first, then host:

```
fdaa::/16                                    PigeonULARange
  fdaa:NNNN:NNNN::/48                        network = HashPrefix(ULA, NetworkBits, name)
    fdaa:NNNN:NNNN:HHHH:HHHH::/80            host    = HashPrefix(net, HostBits, hostname)
      fdaa:NNNN:NNNN:HHHH:HHHH::1            addr    = HostAddr(host, 1)
```

Transpose exchanges network and host fields for WireGuard routing:

```
App view:  fdaa:[net32]:[host32]:...   → same-network VMs share /48
Wire view: fdaa:[host32]:[net32]:...   → each host owns /48 for AllowedIPs
```

## Usage

```go
import addr "github.com/pigeon-as/pigeon-addr-plan"

// Network prefix for a namespace.
net, _ := addr.HashPrefix(addr.PigeonULARange(), addr.NetworkBits, "prod")
// net = fdaa:NNNN:NNNN::/48

// Host prefix within the network.
host, _ := addr.HashPrefix(net, addr.HostBits, "worker-01")
// host = fdaa:NNNN:NNNN:HHHH:HHHH::/80

// Gateway for the host subnet.
gw, _ := addr.HostAddr(host, 1)
// gw = fdaa:NNNN:NNNN:HHHH:HHHH::1

// Transpose for WireGuard routing.
wire, ok := addr.TransposePigeonULA(gw)
// wire = fdaa:HHHH:HHHH:NNNN:NNNN::1
```

Works with any prefix family (IPv6, IPv4).