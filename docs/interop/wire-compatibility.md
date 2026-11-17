# RTPS Wire Compatibility

HDDS implements the RTPS 2.4 wire protocol for interoperability with all compliant DDS implementations.

## Protocol Version

| Property | Value |
|----------|-------|
| RTPS Version | 2.4 |
| Magic | `RTPS` (0x52, 0x54, 0x50, 0x53) |
| Vendor ID | 0x011A (HDDS) |

## Encapsulation Formats

HDDS supports multiple CDR encapsulation formats:

| Format | ID | Description | Primary Use |
|--------|-----|-------------|-------------|
| CDR_BE | 0x0000 | Big-endian CDR v1 | Legacy |
| CDR_LE | 0x0001 | Little-endian CDR v1 | Legacy |
| PL_CDR_BE | 0x0002 | Parameter list big-endian | Big-endian peers |
| PL_CDR_LE | 0x0003 | Parameter list little-endian | HDDS default |
| CDR2_LE | 0x0007 | CDR2 little-endian (XCDR2 final types) | Modern types |
| D_CDR2_LE | 0x0009 | Delimited CDR2 (XCDR2 appendable types) | Appendable types |
| PL_CDR2_LE | 0x000B | Parameter list CDR2 (XCDR2 mutable types) | Mutable types |

## Submessage Support

These RTPS submessages are implemented (INFO_SRC and INFO_REPLY are recognised on receive but not emitted):

| Submessage | ID | Status |
|------------|----|----|
| DATA | 0x15 | Full support |
| DATA_FRAG | 0x16 | Full support |
| ACKNACK | 0x06 | Full support |
| HEARTBEAT | 0x07 | Full support |
| GAP | 0x08 | Full support |
| INFO_TS | 0x09 | Full support |
| INFO_DST | 0x0E | Full support |

## Built-in Endpoints

| Endpoint | Reader ID | Writer ID |
|----------|-----------|-----------|
| SPDP Participant | 0x000100C7 | 0x000100C2 |
| SEDP Publications | 0x000003C7 | 0x000003C2 |
| SEDP Subscriptions | 0x000004C7 | 0x000004C2 |
| P2P Messages | 0x000200C7 | 0x000200C2 |
| TypeLookup Request | 0x000300C4 | 0x000300C3 |
| TypeLookup Reply | 0x000301C4 | 0x000301C3 |

## Other Implementations

HDDS interoperates over standard RTPS with other DDS implementations, including
eProsima FastDDS, Eclipse Cyclone DDS and OCI OpenDDS. No HDDS-side
configuration is specific to one of them.

## Discovery Protocol

### SPDP (Simple Participant Discovery)

HDDS announces participants via multicast:

- **Multicast group**: 239.255.0.1
- **Port formula**: 7400 + (250 x domainId)
- **Announcement period**: 3 seconds (faster during a startup burst)
- **Lease duration**: 30 seconds (default)

### SEDP (Simple Endpoint Discovery)

Endpoints are announced via unicast after participant discovery:

- Publications (DataWriters)
- Subscriptions (DataReaders)
- Topic types (via TypeLookup service)

## QoS Wire Mapping

QoS policies are encoded in discovery announcements:

| QoS Policy | Parameter ID |
|------------|--------------|
| Reliability | 0x001A |
| Durability | 0x001D |
| History | 0x0040 |
| Deadline | 0x0023 |
| Liveliness | 0x001B |
| Ownership | 0x001F |
| Partition | 0x0029 |

## Packet Structure

```
+------------------+
| RTPS Header      |  20 bytes
| - Magic (4)      |
| - Version (2)    |
| - Vendor ID (2)  |
| - GUID Prefix(12)|
+------------------+
| Submessage 1     |
| - Header (4)     |
| - Payload (var)  |
+------------------+
| Submessage 2     |
| ...              |
+------------------+
```

## Endianness

- RTPS header: Always big-endian
- Submessage header: Endianness flag in header
- Payload: Follows submessage endianness
- HDDS default: Little-endian (x86/ARM optimized)

## Fragmentation

Payloads above 8192 bytes are automatically fragmented into DATA_FRAG
submessages; larger samples are repaired with NACK_FRAG:

| Property | Value |
|----------|-------|
| Max UDP datagram | 65,507 bytes |
| Largest unfragmented payload | 8192 bytes |
| Default fragment size | 1024 bytes |
| Max CDR payload | 16 MB |

## Interoperability Tips

### Working with Another Implementation

HDDS reads every XCDR1 and XCDR2 encapsulation listed above, whichever the
peer's data representation QoS and type extensibility select:

```bash
# No special configuration needed
./my_hdds_app
```

## Troubleshooting

### No Discovery

1. Check multicast routing: `ip route show | grep 239.255`
2. Verify the firewall allows the UDP ports of your domain (`7400 + 250 x D` to `7649 + 250 x D`)
3. Enable diagnostics: `HDDS_INTEROP_DIAGNOSTICS=1`

### Partial Discovery

1. Check domain ID matches across all participants
2. Verify QoS compatibility (esp. Reliability, Durability)
3. Check clock synchronization for timestamps

### Data Not Received

1. Verify topic name and type match exactly
2. Check QoS compatibility between writer/reader
3. Enable UDP logging: `HDDS_LOG_UDP=1`

## Next Steps

- [FastDDS Setup](../interop/fastdds/setup.md) - Interop with eProsima FastDDS
- [RTI Connext Setup](../interop/rti-connext/setup.md) - Interop with RTI Connext
