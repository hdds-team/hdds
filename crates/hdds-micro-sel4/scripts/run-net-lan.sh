#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Boot the network image on the Raspberry Pi 4 and exchange samples with a
# Linux hdds-micro peer over the Pi's Ethernet NIC, in both directions.
# Captures the UART console and the LAN, then counts the samples on each side.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-net-lan.sh OUT_DIR
#
# Environment (required):
#   PI_POWER    power control script: "PI_POWER on|off|cycle SECONDS|status"
#   LAN_IF      Linux interface on the LAN segment the Pi is cabled to
#   PUB_IP      IPv4 of the publisher PD (as compiled into the image)
#   SUB_IP      IPv4 of the subscriber PD (as compiled into the image)
#   PI_MAC      MAC of the Pi's Ethernet port (U-Boot DHCP and TFTP traffic)
#   PI_IP       address the Pi gets from DHCP in U-Boot (capture filter)
#   HOST_TOOLS  directory holding the built hdds_pub and hdds_sub binaries
# Environment (optional):
#   UART_DEV    serial console (default /dev/ttyUSB0), 115200 8N1
#   KICK_COUNT  samples in each direction (default 100)
#   BOOT_WAIT   seconds from power-on to the first Linux transfer (default 35)
#   PI_POWER_OFF  1 (default) switches the Pi off at the end of the run
#   PD_PORT     RTPS port of both PDs (default 58650, domain 205)
#   PD_MAC_PUB, PD_MAC_SUB  PD MACs as compiled (defaults match meta_net.py)
#
# The UART reader and the capture are started before the power-on.

set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 OUT_DIR" >&2; exit 2; }
OUT="$(realpath -m "$1")"
mkdir -p "$OUT/logs"

: "${PI_POWER:?set PI_POWER to the power control script}"
: "${LAN_IF:?set LAN_IF to the LAN interface}"
: "${PUB_IP:?set PUB_IP}"
: "${SUB_IP:?set SUB_IP}"
: "${PI_MAC:?set PI_MAC}"
: "${PI_IP:?set PI_IP}"
: "${HOST_TOOLS:?set HOST_TOOLS}"
UART_DEV="${UART_DEV:-/dev/ttyUSB0}"
KICK_COUNT="${KICK_COUNT:-100}"
BOOT_WAIT="${BOOT_WAIT:-35}"
PI_POWER_OFF="${PI_POWER_OFF:-1}"
PD_PORT="${PD_PORT:-58650}"
PD_MAC_PUB="${PD_MAC_PUB:-02:00:00:00:00:17}"
PD_MAC_SUB="${PD_MAC_SUB:-02:00:00:00:00:18}"
PUB_TOOL="$HOST_TOOLS/hdds_pub/target/release/hdds_pub"
SUB_TOOL="$HOST_TOOLS/hdds_sub/target/release/hdds_sub"
for t in "$PUB_TOOL" "$SUB_TOOL"; do [[ -x "$t" ]] || { echo "missing $t" >&2; exit 1; }; done
[[ -e "$UART_DEV" ]] || { echo "missing $UART_DEV" >&2; exit 1; }

UART_LOG="$OUT/uart.raw"
LAN_PCAP="$OUT/lan.pcap"
PCAP_PID="$OUT/tcpdump.pid"
UART_PID=""

cleanup() {
    [[ -n "$UART_PID" ]] && kill "$UART_PID" 2>/dev/null || true
    if [[ -f "$PCAP_PID" ]]; then sudo -n kill "$(cat "$PCAP_PID")" 2>/dev/null || true; fi
}
trap cleanup EXIT

# 1. UART reader first, so the boot is not missed.
stty -F "$UART_DEV" 115200 cs8 -cstopb -parenb -crtscts raw -echo
timeout 600 cat "$UART_DEV" > "$UART_LOG" 2>/dev/null &
UART_PID=$!

# 2. Capture on the LAN segment, filtered on the Pi, the PDs and the peer.
sudo -n sh -c "echo \$\$ > '$PCAP_PID'; exec timeout 900 tcpdump -i '$LAN_IF' -s 0 -U -w '$LAN_PCAP' \
  'ether host $PI_MAC or ether host $PD_MAC_PUB or ether host $PD_MAC_SUB or host $PUB_IP or host $SUB_IP or host $PI_IP'" \
  > "$OUT/logs/tcpdump.log" 2>&1 &
sleep 3

# 3. Power-on, then the Linux side.
"$PI_POWER" cycle 5
sleep "$BOOT_WAIT"
"$SUB_TOOL" --kick-host "$PUB_IP" --kick-port "$PD_PORT" --count "$KICK_COUNT" \
    --timeout-secs 60 --kick-interval-ms 50 > "$OUT/logs/linux-sub.log" 2>&1 || true
"$PUB_TOOL" --dest-host "$SUB_IP" --dest-port "$PD_PORT" --count "$KICK_COUNT" \
    --interval-ms 50 > "$OUT/logs/linux-pub.log" 2>&1 || true
sleep 3

# 4. Stop the readers, power off, then count.
cleanup; UART_PID=""; trap - EXIT
sudo -n kill "$(cat "$PCAP_PID")" 2>/dev/null || true
[[ "$PI_POWER_OFF" == 1 ]] && "$PI_POWER" off >/dev/null || true
tr -d '\000' < "$UART_LOG" | sed -e 's/\r$//' > "$OUT/uart.txt"

count_seq() {  # distinct, min, max, contiguous (1..N) for a stream of "<tag> seq=N" lines
    local n min max
    n=$(grep -o "$1" "$2" | cut -d= -f2 | sort -n -u | wc -l)
    min=$(grep -o "$1" "$2" | cut -d= -f2 | sort -n | head -1)
    max=$(grep -o "$1" "$2" | cut -d= -f2 | sort -n | tail -1)
    echo "distinct=${n:-0} min=${min:-none} max=${max:-none}"
}
S_LINUX=$(count_seq '^RX seq=[0-9]*' "$OUT/logs/linux-sub.log")
S_UART=$(count_seq '^RX seq=[0-9]*' "$OUT/uart.txt")
echo "seL4 -> Linux  (Linux hdds_sub): $S_LINUX"
echo "Linux -> seL4  (UART, subscriber PD): $S_UART"
# Case-sensitive: U-Boot's USB probe line says "error", the seL4 markers say "ERROR".
bad=$(cat "$OUT/uart.txt" "$OUT/logs/linux-sub.log" | grep -c 'WARN\|decode\|VMFault\|ERROR\|FAULT' || true)
ok=1
for s in "$S_LINUX" "$S_UART"; do
    [[ "$s" == "distinct=$KICK_COUNT min=1 max=$KICK_COUNT" ]] || ok=0
done
[[ "$bad" -eq 0 ]] || ok=0
(cd "$OUT" && sha256sum uart.raw uart.txt lan.pcap logs/linux-sub.log logs/linux-pub.log > SHA256SUMS)
if [[ $ok -eq 1 ]]; then echo "VERDICT: PASS ($KICK_COUNT each way, contiguous, no warning)"; else echo "VERDICT: NOT PASS (see $OUT)"; fi
