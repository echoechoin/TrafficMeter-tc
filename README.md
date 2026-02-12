# traffic_meter

A Linux traffic metering tool based on BPF TC (Traffic Control). It counts upstream and downstream bytes per IP address or CIDR prefix across all network interfaces.

## Features

- Per-IP or per-CIDR traffic statistics (upstream / downstream bytes)
- Supports both IPv4 and IPv6
- Uses TC BPF (ingress + egress) for bidirectional traffic visibility
- Self-built BPF flow table to determine traffic direction (first packet of a flow = upstream)
- Shared BPF maps across multiple interfaces — statistics are aggregated across all attached NICs
- Bridge-aware: avoids double-counting forwarded packets when interfaces are in the same bridge
- TCP SYN/SYN-ACK detection to correctly handle connection re-establishment

## Build

Requirements:
- Linux kernel 5.4+ with `CONFIG_BPF_SYSCALL` and `CONFIG_NET_CLS_ACT`
- clang/LLVM (with BPF target support)
- libbpf (development headers and library)
- json-c (development headers and library)
- Meson + Ninja

```bash
meson setup builddir
ninja -C builddir
```

## Usage

All commands require root or `CAP_BPF` + `CAP_NET_ADMIN`.

### Load BPF program onto a network interface

```bash
# Attach to eth0 (creates clsact qdisc, attaches ingress + egress TC BPF)
traffic_meter load --dev eth0 --object traffic_meter.bpf.o

# Attach to a second interface (reuses the same shared maps)
traffic_meter load --dev eth1 --object traffic_meter.bpf.o
```

### Add rules

```bash
# Single IP
traffic_meter add --ip-address 192.168.1.100

# CIDR prefix
traffic_meter add --ip-address 10.0.0.0/24

# Catch-all rule
traffic_meter add --ip-address 0.0.0.0/0

# IPv6
traffic_meter add --ip-address 2001:db8::/32
```

### Import rules from JSON

```bash
traffic_meter import --file rules.json
```

Example `rules.json`:

```json
{
  "rules": [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "2001:db8::/32"
  ]
}
```

### List current rules

```bash
traffic_meter list
```

### Show traffic statistics

```bash
# Show all rules
traffic_meter show

# Show a specific rule
traffic_meter show --ip-address 192.168.1.0/24
```

Example output:

```
  IP/CIDR                                  UPSTREAM-BYTES       DOWNSTREAM-BYTES
  0.0.0.0/0                                229347328            43688370176
  192.168.1.100                            1048576              2097152
  10.0.0.0/24                              524288               10485760
```

### Delete rules

```bash
traffic_meter del --ip-address 192.168.1.100
traffic_meter del --ip-address 10.0.0.0/24
```

### Unload BPF program

```bash
# Remove TC BPF from an interface (destroys clsact qdisc)
traffic_meter unload --dev eth0
```

## Direction logic

Traffic direction is determined by a self-built BPF flow table:

- The **first packet** of a flow establishes the "original" (upstream) direction
- Subsequent packets in the reverse direction are counted as "downstream"
- TCP SYN/SYN-ACK packets force a flow table reset to handle reconnections correctly
- Flow keys: 5-tuple for TCP/UDP, ICMP echo ID for ping, IP 2-tuple for other protocols
- The flow table uses `BPF_MAP_TYPE_LRU_HASH` with automatic eviction (default capacity: 65536 entries)

## License

GPL
