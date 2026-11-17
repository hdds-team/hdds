# Evidence pointer

The run logs are not in this tree, which carries code and documentation
only. The maintainers keep the logs in an evidence archive and provide them
on request (open an issue on the project repository). The checksums below
identify the exact files, so a copy you receive can be verified.

## Files and checksums

SHA-256 of each archived file:

| File in the evidence archive | SHA-256 |
|---|---|
| `evidence/rpi4-inguest-20261004.log` | `9300a84e4553ef9953b9753405f787784197614ee7a87318671a3c397db48772` |
| `evidence/logs-20260901/SHA256SUMS` | `8ac4dfab139580953513c2648cf0ba7a5e3a49fb312a85d953dba0dd8ecfc9c6` |
| `evidence/sel4-microkit-20260901.md` | `59fcf8909c7ed355177a5921afd089987d384b065f537706b42cf6ca3f4b6ca6` |

The nine QEMU logs in `evidence/logs-20260901/` match their entries in
`SHA256SUMS` (checked with `sha256sum -c`).

## Counts read from the logs

Counted with `grep -o 'RX seq=[0-9]*'`, then `sort -u`. "Distinct" is the number
of unique sequence values; the minimum was 1 in every run listed.

| Run | Log (evidence archive) | RX lines | Distinct seq | Max seq |
|---|---|---|---|---|
| seL4 publisher to Linux subscriber | `logs-20260901/phase31-sub.log` | 100 | 100 | 100 |
| Linux publisher to seL4 subscriber | `logs-20260901/phase32-qemu.log` | 200 | 200 | 200 |
| Intra-guest, seal gate | `logs-20260901/phase33-seal-qemu.log` | 23085 | 23085 | 23085 |
| Intra-guest, hardened | `logs-20260901/phase33-hardened-qemu.log` | 5816 | 5816 | 5816 |
| Intra-guest, Raspberry Pi 4, loopback driver | `rpi4-inguest-20261004.log` | 102325 | 102325 | 102325 |

The Linux-to-seL4 row shows 200 distinct sequence numbers. An earlier summary
said 199/200; the log does not support that figure.

## What the evidence does not cover

- The QEMU logs and the Pi log predate the GUID prefix change in this tree
  (`PD_INSTANCE` with `MicroParticipant::with_instance`). They are provenance
  for the earlier revision, not a result for this tree.
- The Pi run used a loopback driver PD in place of a NIC. See the crate
  README, "What is NOT verified".
- The QEMU evidence document in the archive cites the Microkit SDK 2.2.0 and
  a `qemu_virt_aarch64` board. This tree was not re-run against either.
