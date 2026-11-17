# Hello World in Python

You will build a temperature publisher and a subscriber that exchange typed
samples, with the type defined once in IDL.

**Prerequisites:** Python 3.9+, the **Rust toolchain** (current stable; dependencies require 1.89 or newer, this release is built with 1.90) and Git. The
Python SDK is a pure-Python `ctypes` package on top of the HDDS C library
(`libhdds_c`), which is built from source with Cargo.

:::info Network prerequisites
Discovery uses UDP multicast. If the subscriber receives nothing and nothing
reports an error, discovery is probably not happening (VPN, container,
firewall). For a single-machine test, run both programs with
`HDDS_INTERFACE=lo`. See [Network Prerequisites](https://docs.hdds.io/getting-started/network-prerequisites).
:::

## Step 1: Install HDDS

The package is not on PyPI and contains no compiled extension: build the
native library with Cargo, install the package from the repository with pip
(a plain setuptools build), and tell it where the library is.

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds

# 1. The native library: target/release/libhdds_c.so (default features only)
cargo build --release -p hdds-c

# 2. The Python package, into a virtual environment
python3 -m venv ~/.venvs/hdds
~/.venvs/hdds/bin/python -m pip install ./sdk/python

# 3. Where the native library is: the directory holding libhdds_c.so.
#    With CARGO_TARGET_DIR set, cargo puts it in $CARGO_TARGET_DIR/release.
export HDDS_LIB_PATH=${CARGO_TARGET_DIR:-$PWD/target}/release

# Check
~/.venvs/hdds/bin/python -c "import hdds; print(hdds.library_path(), hdds.version())"
```

Do not build `hdds-c` with `--all-features` for Python: that build links ROS 2
symbols and only loads inside a sourced ROS 2 environment. For an offline
install (no build backend download), see `sdk/python/README.md` in the
repository.

## Step 2: Define the Data Type in IDL

Create `temperature.idl`:

```idl
struct Temperature {
    @key unsigned long sensor_id;
    float value;
    unsigned long long timestamp;
};
```

Generate the Python type with `hddsgen` 2.0 or later. It is installed from its
own repository (see [Installing hdds_gen](../tools/hdds-gen/installation.md)):

```bash
git clone https://git.hdds.io/hdds/hdds_gen.git
cargo install --path hdds_gen     # installs `hddsgen` into ~/.cargo/bin

hddsgen gen python temperature.idl -o temperature.py
```

(The `hddsgen` release on crates.io stops at 1.0.12: do not use it.)

`temperature.py` contains a `@dataclass Temperature` with
`encode_cdr2_le()` / `decode_cdr2_le()`, the CDR2 serialization DDS puts on
the wire. This is what makes the type interoperable with the Rust, C, C++
SDKs and other DDS implementations.

## Step 3: Create the Publisher

Create `publisher.py`:

```python
#!/usr/bin/env python3
import sys
import time
import hdds
from temperature import Temperature

def main():
    hdds.logging.init(hdds.LogLevel.WARN)  # discovery problems are logged as warnings

    # No domain in the code: the participant reads HDDS_DOMAIN_ID (Step 5)
    with hdds.Participant("temperature_publisher") as participant:
        qos = hdds.QoS.reliable().history_depth(10)
        # Temperature positionally: the writer reads the generated class's
        # HDDS_EXTENSIBILITY and labels every sample with it (DDS-XTypes 1.3
        # Table 60). Omitting it would label every sample FINAL regardless
        # of the type's real extensibility (hdds_gen default: APPENDABLE).
        writer = participant.create_writer("TemperatureTopic", Temperature, qos=qos)
        print("Writer created, waiting for a subscriber...", flush=True)

        # Samples written before a reader is matched are not delivered to it
        # (VOLATILE durability), so wait for discovery first.
        if not writer.wait_for_readers(1, timeout=10.0):
            print("No subscriber found after 10 s: see the Network Prerequisites page",
                  file=sys.stderr, flush=True)
            sys.exit(1)

        for i in range(10):
            sample = Temperature(
                sensor_id=1,
                value=22.0 + i * 0.5,
                timestamp=int(time.time() * 1000),
            )
            writer.write_typed(sample)  # CDR2-encodes with the generated code
            print(f"Published: sensor={sample.sensor_id} value={sample.value:.1f}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()
```

## Step 4: Create the Subscriber

Create `subscriber.py`:

```python
#!/usr/bin/env python3
import sys
import hdds
from temperature import Temperature

EXPECTED_SAMPLES = 10
IDLE_TIMEOUT_S = 10.0

def main():
    hdds.logging.init(hdds.LogLevel.WARN)

    # No domain in the code: the participant reads HDDS_DOMAIN_ID (Step 5)
    with hdds.Participant("temperature_subscriber") as participant:
        qos = hdds.QoS.reliable().history_depth(10)
        reader = participant.create_reader("TemperatureTopic", qos=qos)

        received = 0
        with hdds.WaitSet() as waitset:
            waitset.attach_reader(reader)
            print("Waiting for data...", flush=True)
            # Stop after EXPECTED_SAMPLES samples, or after IDLE_TIMEOUT_S without data
            while received < EXPECTED_SAMPLES:
                if not waitset.wait(timeout=IDLE_TIMEOUT_S):
                    print(f"No data for {IDLE_TIMEOUT_S:.0f} s, exiting", flush=True)
                    break
                # Drain everything that is available
                while (sample := reader.take_typed(Temperature)) is not None:
                    print(f"Received: sensor={sample.sensor_id} "
                          f"value={sample.value:.1f} t={sample.timestamp}", flush=True)
                    received += 1
        print(f"Received {received} samples", flush=True)
        if received == 0:
            print("No sample received: start the publisher first, see the Network "
                  "Prerequisites page", file=sys.stderr, flush=True)
            sys.exit(1)

if __name__ == "__main__":
    main()
```

## Step 5: Run

Open two terminals, activate the environment in both, and set `HDDS_LIB_PATH`
and `HDDS_DOMAIN_ID` in both. The programs do not hard-code a domain: they read
`HDDS_DOMAIN_ID` (42 here; any value from 0 to 232, the same in both terminals).
Without it the domain is 0, see [Environment variables](../reference/environment-vars.md).

```bash
# Terminal 1 - start the subscriber first
source ~/.venvs/hdds/bin/activate
export HDDS_LIB_PATH=/path/to/hdds/target/release
export HDDS_DOMAIN_ID=42
python subscriber.py

# Terminal 2
source ~/.venvs/hdds/bin/activate
export HDDS_LIB_PATH=/path/to/hdds/target/release
export HDDS_DOMAIN_ID=42
python publisher.py
```

Expected subscriber output:

```
Waiting for data...
Received: sensor=1 value=22.0 t=...
Received: sensor=1 value=22.5 t=...
...
Received 10 samples
```

The subscriber stops after 10 samples. If it receives nothing for 10 s, it
prints a message and exits with status 1, as does the publisher when no
subscriber matches (Step 3).

## Raw Bytes

Without generated types, a writer sends `bytes` and a reader returns `bytes`
(or `None` when nothing is available):

```python
writer.write(b"hello")
data = reader.take()          # b"hello" or None
```

The library adds the RTPS encapsulation header itself: pass the serialized
payload only, never a header of your own. To talk to another DDS
implementation, the payload must be the CDR encoding of the type the other
side expects, which is what the generated `encode_cdr2_le()` produces, and the
type name announced in discovery must match:
`participant.create_writer("Topic", qos=qos, type_name="Temperature")`.

## QoS Configuration

QoS objects are built fluently and printed with every policy that differs from
the default:

```python
qos = (hdds.QoS.reliable()
       .transient_local()
       .history_depth(20)
       .deadline_ms(100)
       .resource_limits(max_samples=500))   # -1 (the default) = unlimited
print(qos)
# QoS(reliable, transient_local, depth=20, deadline=100ms, resource_limits(max_samples=500, ...))

writer = participant.create_writer("TemperatureTopic", Temperature, qos=qos)
```

An inconsistent combination (for example a history depth larger than
`max_samples_per_instance`) makes `create_writer` raise a `RuntimeError` that
names the broken rule; `qos.consistency_problems()` lists them beforehand.
XML profiles load with `hdds.QoS.from_file("profile.xml")`. See
[QoS Policies](../guides/qos-policies/overview.md) and the
[Python API Reference](../api/python.md).

:::note Listener callbacks
Instead of a `WaitSet`, a `hdds.ReaderListener` subclass installed with
`reader.set_listener()` is called back on an HDDS thread when data arrives
(`on_data_available(data)`). See [Listeners](../api/python.md#listeners) for
the threading contract.
:::

:::note Typed Python API
Topic types are generated from IDL. The SDK has no API to declare a topic type
directly in Python (`Topic` / `Key[...]` annotations): the typed calls are
`create_writer(topic, Type)`, `write_typed()` and `take_typed(Type)` on a class
generated by `hddsgen`.
:::

## Troubleshooting: the subscriber receives nothing

- **The publisher says "No subscriber found" and exits with status 1?** Discovery
  is not happening. On one machine, run both programs with `HDDS_INTERFACE=lo`.
  Full guide: [Network Prerequisites](https://docs.hdds.io/getting-started/network-prerequisites).
- **No output when redirected to a file?** Python buffers `stdout` when it is
  not a terminal; the examples pass `flush=True` (or run `python -u`).
- **`ImportError: Could not load the hdds-c native library`?** The library is
  loaded on first use (`hdds.version()`, `Participant(...)`), not by `import hdds`.
  The message lists every path tried. Check `HDDS_LIB_PATH`.

## What's Next?

- **[QoS Policies](../guides/qos-policies/overview.md)** - Fine-tune data distribution
- **[Python API Reference](../api/python.md)** - Complete Python documentation
- **[Examples](../examples/index.md)** - More complex examples
