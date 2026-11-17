# HDDS Documentation

The full documentation lives in the dedicated documentation repository:

**https://docs.hdds.io/**

It includes:

- Getting Started guides (C, C++, Python, Rust, TypeScript, Java)
- API reference per language
- QoS configuration guide
- Interoperability with FastDDS / OpenDDS
- ROS 2 integration
- Troubleshooting

Built with [Docusaurus](https://docusaurus.io/).

### Status values and explicit source timestamps

C, C++ and Python expose reader and writer status getters such as
`get_subscription_matched_status()` and `get_publication_matched_status()`.
The C functions use the `hdds_reader_` or `hdds_writer_` prefix and a status
out-parameter. Each getter returns a snapshot, preserves cumulative totals,
and resets the change counters, sharing consumption with listener callbacks
(DDS 1.4 Sec.2.2.4.2.1).

`write_w_timestamp`, `dispose_w_timestamp` and
`unregister_instance_w_timestamp` take integer nanoseconds since the Unix
epoch. C++ accepts serialized byte buffers or typed samples; Python accepts
bytes, with `write_typed_w_timestamp` for CDR2-encodable messages.
`register_instance` and `register_instance_w_timestamp` return a 16-byte
instance handle. These SDK raw-byte topics are keyless, so the handle is nil
(all zeros). Registration emits no sample, and its timestamp does not carry
into a later write. Use `wait_for_acknowledgments` to wait for reliable delivery.

Data-write timestamps are observable in `HddsSampleInfo::SOURCE_TIMESTAMP_NS`
through the C condition-based take/read API. Invalid-data lifecycle transitions
currently omit source timestamps in `SampleInfo`, a limitation of the core.
