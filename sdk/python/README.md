# HDDS Python SDK

For runtime types and local SQL-like filter evaluation through the C API, see
[the ctypes example](examples/dynamic_filter.py) and its
[API contracts](../c/DYNAMIC_FILTER.md). Dedicated Python wrapper classes for
these APIs are not yet provided.

Pure-Python `ctypes` bindings to the `hdds-c` shared library (`libhdds_c.so`),
the C ABI of [HDDS](https://hdds.io) (High-performance DDS). The package
contains no compiled extension: the wheel is `hdds-<version>-py3-none-any.whl`
and the native library is loaded at first use.

Licence: Apache-2.0 OR MIT (same as the workspace).

## Prerequisites

1. A built `libhdds_c.so` from this repository, default features:

   ```bash
   cargo build --release -p hdds-c
   # -> target/release/libhdds_c.so
   ```

   Do not use `--all-features` or the `rmw` feature for the Python SDK: that
   build links ROS 2 symbols (`rosidl_runtime_c_*`) and cannot be loaded
   outside a sourced ROS 2 environment.

2. Python >= 3.9 (`pyproject.toml` `requires-python`, proved by
   `tests/test_python_floor.py`). Python 3.13 is the only interpreter the
   SDK gate runs end to end, and the only one the classifiers claim. The
   wheel build needs `setuptools >= 77` available to it
   (`python3 -m pip install setuptools`, or the distribution package).

## Install

The package is not published on PyPI. Build the wheel from this repository
and install it; no network is needed:

```bash
cd sdk/python
python3 -m pip wheel --no-build-isolation --no-deps --no-index -w dist .
python3 -m venv ~/.venvs/hdds
~/.venvs/hdds/bin/python -m pip install --no-index dist/hdds-*-py3-none-any.whl
```

`--no-build-isolation` uses the `setuptools` already installed on the host;
drop the flag (and `--no-index`) to let pip fetch the build backend instead.
setuptools writes `build/`, `dist/` and `hdds.egg-info/` next to the sources
when the wheel is built in place; all three are gitignored, so the worktree
stays clean. The SDK gate never builds in place: it copies `sdk/python` under
the cargo target dir first (`scripts/test-sdk.sh` `build_python_wheel`).

Tell the package where the native library is, then check:

```bash
export HDDS_LIB_PATH=/path/to/hdds/target/release
~/.venvs/hdds/bin/python -c "import hdds; print(hdds.library_path(), hdds.version())"
```

`hdds.__version__` is the package version (tracks the workspace version in
the root `Cargo.toml`); `hdds.version()` is the version reported by the
loaded native library.

## Native library discovery

Verbatim from `hdds/_native.py` (`scripts/check-python-docs.sh` diffs the
two):

```
Library Discovery Order:
    1. ``HDDS_LIB_PATH`` environment variable (strict override): a directory
       containing ``libhdds_c.so`` or the full path of the library. When set,
       it is the ONLY candidate; nothing else is probed. A relative value is
       resolved against the current directory; an empty value is an error,
       never a fallback.
    2. Library bundled inside the installed package,
       ``<package>/_lib/libhdds_c.so``. Only a wheel built with the native
       library inside it ships that directory; no wheel built from this
       repository does today, so the candidate is normally absent.
    3. Repository development build, ``<repo>/target/release`` then
       ``<repo>/target/debug``. Source checkouts only: the tier exists when
       this file sits at ``<repo>/sdk/python/hdds/_native.py`` next to the
       workspace ``Cargo.toml``; an installed wheel skips it.
    4. System library directories, ``/usr/local/lib`` then ``/usr/lib``.
    5. The bare library name handed to the system dynamic linker
       (``LD_LIBRARY_PATH`` / ``ldconfig``).

Loading fails closed: when no candidate loads, ``ImportError`` lists every
path that was tried, the dynamic-linker error of every candidate that
existed but did not load, and the build command for the native library
(``cargo build --release -p hdds-c``, default features).

A candidate that exists but fails to load stops the search only when it
came from ``HDDS_LIB_PATH``: an explicit override is never silently
replaced by another library. On the implicit tiers 2-5 the error is
recorded and the next candidate is tried, so a stale or ``--all-features``
build left in ``target/release`` cannot mask a working library further
down the order; every recorded error is reported if none of them loads.
```

Tier 2 is empty for the wheel this repository builds: the pure-Python wheel
carries no `libhdds_c.so`, so the `hdds/_lib/` directory does not exist and
the candidate is skipped (`tests/test_native_discovery.py::test_bundled_wheel_tier_is_probed_second`
proves the tier is used when the directory IS populated, which is what a
bundled-library wheel would do).

Tier 3 only applies to a source checkout (`sdk/python/hdds` inside the
repository, `Cargo.toml` at the root); an installed wheel goes straight from
tier 2 to tier 4 (`tests/test_native_discovery.py::test_installed_layout_has_no_dev_tier`).
A library that exists but fails to load (for example an `--all-features`
`rmw` build, whose ROS 2 symbols are undefined outside a sourced ROS 2
environment) stops the search only when `HDDS_LIB_PATH` pointed at it: an
explicit override is never silently replaced. On the implicit tiers the
loader records the error and keeps going, and reports every recorded error
if nothing loads
(`tests/test_native_discovery.py::test_unloadable_implicit_candidate_does_not_mask_a_later_tier`,
`::test_existing_but_unloadable_override_never_falls_through`).

## Quick start

```python
import hdds

with hdds.Participant("demo", transport=hdds.TransportMode.INTRA_PROCESS) as p:
    writer = p.create_writer("hello")
    reader = p.create_reader("hello")
    writer.write(b"hello")
    print(reader.take())  # b'hello'
```

The API operates on raw bytes; use `hdds_gen` (hddsgen 2.0 or later) to
generate typed serialisation code, then `create_writer(topic, Type)` (the
class positionally, so every sample is labelled with the type's real
extensibility instead of FINAL), `writer.write_typed(sample)` and
`reader.take_typed(Type)`. Do not prepend an encapsulation header to the
payload: the library adds it. `examples/hello_world.py` is a two-process
example. Full reference: https://docs.hdds.io/api/python

Across processes, discovery uses UDP multicast and fails silently where
multicast cannot flow (VPN, container, firewall). `writer.matched_reader_count()`
and `writer.wait_for_readers(1, timeout=5.0)` tell whether a subscriber was
found; on one machine, `HDDS_INTERFACE=lo` on both sides. Guide:
https://docs.hdds.io/getting-started/network-prerequisites

## Tests and gate

```bash
# Source-tree tests (hermetic ones run without the library; the ones marked
# `native` fail closed when HDDS_LIB_PATH is set and the library does not load)
HDDS_LIB_PATH=/path/to/target/release python3 -m pytest tests/ -v

# Full SDK gate: builds hdds-c, runs pytest, builds the wheel from a copy
# under the cargo target dir, installs it in a bare venv, runs an
# installed-package smoke (intra-process round trip) and the fail-closed check
./scripts/test-sdk.sh --python
```

## Not shipped in this wheel

* A fat `manylinux` wheel bundling `libhdds_c.so`. The loader tier
  it needs already exists and is tested (tier 2, `hdds/_lib/`); the wheel
  this repository builds ships it empty.
* The typed `Topic` / `Key` / `DomainParticipant` API.
* A working `hdds.conditions` (content-filtered topics, read/query conditions). The
  module is present and its eight C symbols are exported by `libhdds_c.so`
  (`crates/hdds-c/src/condition_ffi.rs`), but the Python classes are not usable
  end to end: the WaitSet cannot attach them, and `QueryCondition` does not pass the
  type descriptor that `hdds_create_query_condition` takes. Use conditions from Rust
  or C for now (see `docs/read-query-conditions.md`).
  `tests/test_native_surface.py` checks that the symbols are exported and declared
  in `hdds.h`.
