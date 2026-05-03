# netsniff-ng macOS Port — Feature Status

## ✓ Fully Working on macOS BPF
(populated as we test)

## ⚠️ Working with Caveats
(populated as we test)

## 🚫 Linux-only Features — Stubbed/Removed in macOS Port
These features depend on Linux kernel APIs without macOS equivalents.
They are explicitly excluded from this port and will print a clear
"not supported on macOS" message rather than silently doing nothing.

### Definitely Linux-only (Cannot Port)
- `-C/--fanout-group`, `-K/--fanout-type`, `-L/--fanout-opts`
  AF_PACKET fanout — Linux-specific kernel load balancing.

- `-N/--no-hwtimestamp` (and hardware timestamping in general)
  SIOCSHWTSTAMP requires Linux PHC (PTP hardware clock) infrastructure.

- `-Q/--notouch-irq` (and IRQ affinity tuning)
  /proc/irq/N/smp_affinity is Linux-specific.

- `-w/--cooked` (Linux SLL/cooked headers)
  LINKTYPE_LINUX_SLL is Linux-specific encapsulation.

- `-b/--bind-cpu` 
  sched_setaffinity is Linux-specific (macOS uses thread_policy_set).
  Could be ported to macOS thread affinity but currently no-op.

- `-H/--prio-high`
  sched_setscheduler with SCHED_FIFO — Linux real-time scheduling.

### Stub on macOS (Returns "not supported")
- `-U/--update` (GeoIP) — depends on libGeoIP C API (unmaintained)
- `--rfraw` (raw 802.11) — requires Linux mac80211 monitor mode

## 🔮 Future Work (Could be ported)
- macOS-native CPU affinity via thread_policy_set
- BPF filter compilation via libpcap (already partially works)
- BSD-style raw 802.11 via Apple80211 framework (private, fragile)


## Planned Removals — Confirmed Stubbed
| Flag | Original Function | Reason Removed | macOS Alternative? |
|------|-------------------|----------------|--------------------|
| `-U/--update` | Update GeoIP databases via libGeoIP C API | libGeoIP unmaintained, deprecated; not in Homebrew | None viable; users can use MaxMind's mmdblookup or Python geoip2 separately |





## Interface Selection on macOS — Important Note for VPN Users
On macOS, traffic from your machine may route through a VPN tunnel (typically `utun0`,
`utun1`, ..., `utun4`) rather than the visible physical interface (e.g., `en0`). When
testing or using netsniff-ng with filters, capturing on the wrong interface results in
no matching packets, which can be misdiagnosed as broken capture.

To find the correct interface for traffic to a destination:
```bash
route get <destination>     # shows "interface: utunN" or "interface: en0"
```

To find your physical en0 LAN gateway (which IS reachable via en0 BPF):
```bash
ipconfig getoption en0 router
```

Capturing local LAN traffic on `en0` with filters works correctly:
```bash
sudo ./netsniff-ng-macos -i en0 -A -q -f "icmp"
ping -c 3 $(ipconfig getoption en0 router)   # in another shell
```

VPN tunnel interfaces (`utun*`) use a different BPF DLT (e.g., `DLT_NULL`,
`DLT_LOOP`, or `DLT_RAW`) instead of `DLT_EN10MB`, so filters compiled for
ethernet headers won't match traffic on those interfaces. This is documented
BSD BPF behavior and matches `tcpdump`'s requirement to use `-i utunN` and
sometimes `-y` (link-type override) for VPN captures.
