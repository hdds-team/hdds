# tools/docker-ros2 - pinned ROS 2 images for the rmw_hdds gate

`scripts/ros2/gate-ros2.sh` builds and tests the `rmw_hdds` ament package
against **this** tree, inside a per-distro container, for Humble, Iron and
Jazzy. This directory holds the image recipe and everything that runs inside
the container.

## Why an image at all

`rmw_hdds` is an `ament_cmake` package: building it needs a full ROS 2
installation, and testing it needs `rmw_implementation`, the demo nodes and the
`ros2` CLI. None of that is on this box outside a container. Before this gate
existed, nothing in the release process ever built the package - the only
evidence on record was one Humble bench batch from February 2026.

## Hermeticity

Everything that needs the network happens at IMAGE BUILD time: `apt`, `rustup`,
the `performance_test` checkout. At GATE time:

* the base image is pinned **by digest** (`build-image.sh`), not by tag - osrf
  rebuilds the `-desktop` tags and a tag-only `FROM` would silently change the
  toolchain under a gate that is supposed to be reproducible;
* containers run on a private bridge or `--network none`;
* the HDDS tree is bind-mounted **read only**, so a container build cannot
  write into the worktree (`git status` stays clean - that is one of the gate's
  own checks);
* `cargo` runs `--locked --offline` against a vendored source tree that
  `scripts/ros2/gate-ros2-build.sh --prepare` produced once;
* build artefacts live in a per-distro named docker volume, never in the tree.

No credentials, no cloud, no host multicast: `ROS_DOMAIN_ID` is 39 (HDDS's own
domain id) and the traffic stays on the run's own bridge.

## Files

| path | role |
|---|---|
| `Dockerfile` | one image per distro: pinned Rust, comparator middlewares, demo nodes, optional `performance_test` |
| `build-image.sh` | builds `hdds-ros2:<distro>` from the pinned base digest |
| `extract-required-symbols.sh` | refreshes `symbols/<distro>.txt` from `ros2/rmw_implementation` (needs network; run deliberately) |
| `symbols/<distro>.txt` | the rmw entry points `rmw_implementation` resolves on that distro - the symbol gate's reference |
| `in-container/build-rmw.sh` | cargo + colcon build, then the symbol set difference |
| `in-container/run-case.sh` | one pub/sub, CLI, graph or service case |
| `in-container/bench.sh` | one `performance_test` round |
| `in-container/summarize.py` | rounds -> `summary.json` (min/median/max, `rounds_failed`) |
| `render-status.py` | gate JSON -> the per-distro status table |

## Why the symbol list and not "the talker works"

`rmw_implementation` resolves every entry point by name out of the loaded
middleware and stores a `nullptr` for the ones it cannot find; the failure only
surfaces when something calls that function. A passing talker therefore proves
nothing about the entry points that talker never touches. The gate compares the
**whole** committed list.

## Base image digests

| distro | tag at pin time | digest |
|---|---|---|
| humble | `osrf/ros:humble-desktop` | `sha256:b2b520a8b42d868ed498a8c062ae8d555d3fa671e698641d4a53558badb8fc0c` |
| iron | `osrf/ros:iron-desktop` | `sha256:c82d8b91b11291a2c86fad704534d15662ae1a8ad80a84346c54f756a48f5d40` |
| jazzy | `osrf/ros:jazzy-desktop` | `sha256:e1c05248ece3bc328386d0509a041a97a5de872a5606418118748875c539c66f` |

Iron is end-of-life upstream (last osrf image 2025-06-08). It is built and
gated here all the same; only the label differs.

## Usage

```sh
tools/docker-ros2/build-image.sh --distro humble        # once per distro
scripts/ros2/gate-ros2-build.sh --distro humble --prepare
scripts/ros2/gate-ros2.sh --distro humble
```
