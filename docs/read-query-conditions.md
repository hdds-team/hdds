# ReadCondition and QueryCondition

What HDDS implements of DDS v1.4 Sec.2.2.2.5.8 (ReadCondition), 2.2.2.5.9
(QueryCondition), 2.2.2.5.3.10/11 (`read_w_condition` / `take_w_condition`)
and 2.2.4.5 (trigger state of a ReadCondition), in the Rust API and in the
C binding. Everything below is exercised by tests in the tree
(`crates/hdds/src/dds/reader/tests_conditions.rs`,
`crates/hdds-c/src/condition_ffi.rs`, `sdk/c/tests/test_conditions.c`).
The C++ SDK has no condition wrappers. The Python SDK defines `ReadCondition`
and `QueryCondition` classes, but its WaitSet cannot attach them and its
`QueryCondition` does not pass the type descriptor that
`hdds_create_query_condition` takes, so conditions are usable from Rust and
C only.

Several WaitSets, on different threads, may hold conditions of one
reader, and a thread may drain the reader with the ordinary `take` while
another waits on it: the reader's rings are single-consumer, and every
consumer of them (the condition accessors, that is trigger evaluation,
`take_w_condition` and `read_w_condition`, and the ordinary `take`,
`read` and instance accessors) runs its ring access under one
reader-owned consumer gate.

## Model

A ReadCondition belongs to one DataReader. Its trigger is true while the
reader holds at least one sample whose states are all in the condition's
masks:

| Mask | Values | What HDDS reports |
|------|--------|-------------------|
| sample_state | `READ`, `NOT_READ` | `NOT_READ` until a `read` variant returned the sample, `READ` afterwards. A take never marks. |
| view_state | `NEW`, `NOT_NEW` | `NEW` until this reader returned (read or take) any sample of the instance, `NOT_NEW` from then on; a reborn instance (a sample received after a NOT_ALIVE transition) is `ALIVE` and `NEW` again. |
| instance_state | `ALIVE`, `NOT_ALIVE_DISPOSED`, `NOT_ALIVE_NO_WRITERS` | Data samples are `ALIVE`. A queued dispose/unregister transition is a sample with no data and the matching NOT_ALIVE state. |

A QueryCondition is a ReadCondition whose data must additionally satisfy
the query expression. It never matches an instance-state transition, which
has no data to evaluate.

The query grammar is the subset the `hdds::filter` module parses; its
module documentation (`crates/hdds/src/dds/filter/mod.rs`, "Grammar
coverage" and "Numeric comparisons") is the reference and this page does not
restate it. `%n` parameters come from the parameter list and can be changed
with `set_query_parameters`; a list that does not fit the expression is
rejected and the previous one stays in force (Sec.2.2.2.5.9.3).

### Evaluation

The trigger is evaluated by the reader when it is asked
(`Condition::get_trigger_value`, a WaitSet, `take_w_condition`): the
reader moves whatever its rings hold into its cache and scans the cache
and its dispose queue. The value is exact at the moment of the call. After
a take that removed the last matching sample the next evaluation is false,
which is the recomputation Sec.2.2.4.5 describes for a single take
changing several conditions.

A WaitSet with a ReadCondition attached is woken on every DATA_AVAILABLE
raise of the reader, re-evaluates the condition, and returns to the
application only when a match is present. A sample that does not satisfy
a QueryCondition therefore never ends a wait on it. This wake path is
independent of the reader's StatusCondition `enabled_statuses`.

Evaluating a condition is an access to the reader's rings, serialized
with every other ring consumer of the reader (condition accessors and
the ordinary accessors alike) by a reader-owned consumer gate. The
condition accessors hold it across pump and cache access; the ordinary
`take` holds it across the pump only. In the default build the gate is
one atomic flag, acquired by a compare-and-swap and released by a store:
that is its whole cost on the intra-process take path.

The `fast-consumer-gate` Cargo feature (off by default) replaces it with
a gate in two regimes. The first thread that consumes owns it, and while
it is the only one it enters and leaves with plain stores and loads, no
locked instruction. The first time another thread consumes (a WaitSet
evaluating a condition, a second thread calling `take`), that thread
engages the gate for good: a process-wide `membarrier(2)` proves the
owner is out of any section it had entered, and from then on every
acquisition is the compare-and-swap. Where `membarrier` is unavailable
(not Linux, Miri, or refused) the gate is the compare-and-swap from the
start. The handshake rests on the `membarrier(2)` contract and on a
compiler fence acting as a compiler barrier, outside Rust's abstract
memory model (see `crates/hdds/src/dds/reader/consumer_gate/`), which is
why it is not the default. The measurements with their regime are in
[Benchmarks](guides/performance/benchmarks.md); the feature does not measure
faster than the default build there.

### DATA_AVAILABLE

`take_w_condition` is a take variant: it resets DATA_AVAILABLE when it
leaves the reader with nothing pending, with the same re-check the other
takes use; `read_w_condition` leaves it as `read()` does. Evaluating a
trigger is neither a read nor a take and never resets it. When a condition
cannot carry instance-state transitions (its instance mask has no
NOT_ALIVE bit) a take through it announces them the way `take()` does, so
they do not keep a StatusCondition raised for a consumer that cannot see
them.

Recorded divergence, shared with every accessor of the reader: DDS v1.4
Sec.2.2.4.2.2 resets DATA_AVAILABLE whenever read or take (or a variant)
is CALLED, whatever remains; HDDS resets it only once the reader is
observed empty (a level on "samples pending"), so a partial or
non-matching access leaves it raised. The conditional accessors keep the
reader's existing behaviour rather than diverge from `take()`; closing the
gap is a change to all accessors at once.

## Rust API

```rust
use hdds::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
use hdds::{QoS, WaitSet};
use std::sync::Arc;
use std::time::Duration;

let reader = Arc::new(
    participant
        .topic::<Reading>("readings")?
        .reader()
        .qos(QoS::default())
        .build()?,
);

let fresh = reader.create_readcondition(
    SampleStateMask::NOT_READ,
    ViewStateMask::ANY,
    InstanceStateMask::ALIVE,
)?;
let hot = reader.create_querycondition(
    SampleStateMask::ANY,
    ViewStateMask::ANY,
    InstanceStateMask::ANY,
    "value > %0",
    vec!["10".to_string()],
)?;

let waitset = WaitSet::new();
waitset.attach_condition(hot.clone())?;
for _ in waitset.wait(Some(Duration::from_secs(1)))? {
    for (data, info) in reader.take_w_condition(&hot, usize::MAX)? {
        // data is Some(sample) for a data sample; None with
        // info.valid_data == false for an instance-state transition
    }
}
// A list that does not fit the expression is refused with a FilterError.
if let Err(e) = hot.try_set_query_parameters(vec!["20".to_string()]) {
    eprintln!("parameters refused: {e}");
}
reader.delete_readcondition(&fresh)?;
```

- `create_readcondition`, `create_querycondition` and
  `create_querycondition_with_fields` take `self: &Arc<DataReader<T>>`: the
  condition keeps a weak link to the reader and evaluates through it. Once
  the reader is dropped the trigger is false for good.
- `take_w_condition(&cond, max_samples) -> Vec<(Option<T>, SampleInfo)>`
  returns data samples in cache order first, then the transitions the
  condition admits. `read_w_condition(&cond, max_samples) -> Vec<(Option<T>,
  SampleInfo)>` (needs `T: Clone`) returns the same samples without
  removing them and marks them READ, transitions included (read in place,
  `(None, info)`; a NOT_READ-only condition stops matching a transition
  once read, a take still returns it). An empty vector is the NO_DATA
  case. A `&QueryCondition` is accepted wherever a `&ReadCondition` is
  (`Deref`).
- A condition not attached to the reader (`delete_readcondition` ran, or
  it belongs to another reader) is refused with `Error::InvalidState`,
  the PRECONDITION_NOT_MET of Sec.2.2.2.5.3.7/10/11.
- `SampleInfo` carries `sample_state` and `view_state` for every accessor
  that returns it (`take_with_info` included). The conditional accessors
  also fill `disposed_generation_count`, `no_writers_generation_count`,
  `sample_rank`, `generation_rank` and `absolute_generation_rank`, ranks
  relative to the returned collection.
- `create_querycondition` reads a sample's fields through `DDS::get_fields`
  (generated by `#[derive(DDS)]` for primitive and `String` fields); a type
  with an empty `get_fields` never matches. `create_querycondition_with_fields`
  takes an explicit extractor for types whose schema lives elsewhere.
- `ReadCondition::new` and `QueryCondition::new` still exist, deprecated:
  they build a condition bound to no reader, whose trigger is always false.

## C API

The C reader carries an opaque payload, so a query or a content filter
needs the sample's schema: a dynamic type descriptor
(`hdds_type_builder_*`, see `sdk/c/DYNAMIC_FILTER.md`). The payload is
decoded with it and every top-level primitive, enum or string member is a
query field under its own name; nested structs, sequences, arrays and
unions are not addressable. The bytes are the XCDR2 little-endian body
`hdds_dynamic_data_encode` produces, which is what `hdds_writer_write`
sends as-is, labelled XCDR2, and what a C reader requests. A payload that does not decode is rejected by a content
filter (dropped before the reader, counted as dropped, logged at debug)
and matched by no query, whatever the expression: `1 = 1` admits every
well-formed sample and no malformed one.

```c
struct HddsReadCondition *rc = hdds_create_read_condition(
    reader, HDDS_SAMPLE_STATE_NOT_READ, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ALIVE);
const char *params[] = { "10" };
struct HddsQueryCondition *qc = hdds_create_query_condition(
    reader, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ANY,
    desc, "value > %0", params, 1);

hdds_waitset_attach_query_condition(ws, qc);
/* hdds_waitset_wait reports qc among the triggered pointers */

struct HddsSampleInfo info;
while (hdds_reader_take_w_query_condition(reader, qc, buf, sizeof buf, &len, &info) == HDDS_OK) {
    /* info.VALID_DATA, info.SAMPLE_STATE, info.VIEW_STATE, info.INSTANCE_STATE */
}
hdds_query_condition_set_parameters(qc, params, 1);   /* HDDS_INVALID_ARGUMENT if the list does not fit */
hdds_waitset_detach_condition(ws, qc);
hdds_query_condition_delete(qc);
hdds_read_condition_delete(rc);
```

- Masks are ORs of the `HddsSampleStateKind`, `HddsViewStateKind` and
  `HddsInstanceStateKind` bits.
- `hdds_reader_take_w_condition` / `hdds_reader_take_w_query_condition`
  take ONE matching sample per call (`HDDS_NOT_FOUND` is NO_DATA); a
  transition returns `HDDS_OK` with a zero length and
  `info.VALID_DATA == false`. `hdds_reader_read_w_condition` /
  `hdds_reader_read_w_query_condition` read one without removing it,
  transitions included (same zero-length, `VALID_DATA == false` shape). A
  take whose buffer is smaller than its payload returns `HDDS_OUT_OF_MEMORY`
  with the required size and removes nothing; a later take returns the head
  of the reader, normally that sample (see `hdds_reader_take`). A read with
  a too-small buffer returns the same error and does not mark the sample
  READ, so a NOT_READ read returns it on the retry.
  `HDDS_INVALID_STATE` is PRECONDITION_NOT_MET.
- `hdds_*_condition_delete` detaches the condition from its reader at
  once (a wait never returns it again) and releases the handle; a WaitSet
  keeps its own reference until `hdds_waitset_detach_condition`, for
  which the handle value stays a valid key.
- ContentFilteredTopic: `hdds_create_content_filtered_topic(participant,
  name, related_topic, desc, expression, params, count)` and
  `hdds_create_reader_filtered[_with_type]`. The filter runs before the
  sample reaches the reader, on the writer's thread for intra-process
  delivery and on the receive path for the network, so a rejected sample
  takes no room in the reader and raises no DATA_AVAILABLE.
  `hdds_content_filtered_topic_set_params` applies to readers already
  created from the topic. The plain variant announces the default
  `RawBytes` type name (the one `hdds_reader_create` announces).

## Not implemented

- Generation counters and ranks in the C binding: `HddsSampleInfo` has no
  `disposed_generation_count`, `no_writers_generation_count`, `sample_rank`,
  `generation_rank` or `absolute_generation_rank` member (the Rust
  `SampleInfo` carries them).
- A transition sample reports the state it announces, not the current
  state of its instance, when a later sample has already revived the
  instance by the time the transition is taken.
- `read_next_instance_w_condition` / `take_next_instance_w_condition`
  (Sec.2.2.2.5.3.18/19).
- The query grammar beyond what the `filter` module documents.
- Conditions in the C++ SDK, and a working QueryCondition and WaitSet
  attachment in the Python SDK.
- Recorded, not changed: a custom `WaitsetSignal::signal` implementation
  may run under the delivering entity's locks (see the trait
  documentation); the DATA_AVAILABLE reset divergence above.
