#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# ---------------------------------------------------------------------------
# bench_rmw.sh -- Benchmark rmw_hdds vs rmw_cyclonedds vs rmw_fastrtps
#
# Runs in an osrf/ros:humble-desktop Docker container.
# Mounts the repository as a volume and builds rmw_hdds from source.
#
# Usage :
#   ./bench_rmw.sh              # full run
#   ./bench_rmw.sh --quick      # Array1k only, 10 s
#   ./bench_rmw.sh --help
#
# Requirements:
#   - Docker, with the osrf/ros:humble-desktop image pulled
#   - a readable checkout of this repository
#
# Results land in: rmw_hdds/bench_results/<timestamp>/
# ---------------------------------------------------------------------------
set -eo pipefail

# Repository root: the directory this script lives two levels under, or $HDDS_ROOT.
HDDS_ROOT="${HDDS_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESULTS_DIR="${HDDS_ROOT}/rmw_hdds/bench_results"
DOCKER_IMAGE="osrf/ros:humble-desktop"

# -- Parse args -------------------------------------------------------------

QUICK=false
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) QUICK=true; shift ;;
        --help)
            echo "Usage: $0 [--quick] [--help]"
            echo "  --quick   Array1k only, 10s per test"
            exit 0
            ;;
        *) EXTRA_ARGS="$EXTRA_ARGS $1"; shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="${RESULTS_DIR}/${TIMESTAMP}"
mkdir -p "$RUN_DIR"

echo "[BENCH] results in: $RUN_DIR"
echo "[BENCH] Docker image : $DOCKER_IMAGE"

if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
    echo "[ERR] Docker image not found. Pull it with: docker pull $DOCKER_IMAGE"
    exit 1
fi

# -- Inner script, runs inside the container -------------------------------

INNER_SCRIPT=$(cat <<'DOCKER_INNER'
#!/bin/bash
set -eo pipefail

QUICK="$1"

echo "=== [DOCKER] ROS 2 Humble ==="
source /opt/ros/humble/setup.bash
echo "default RMW: $RMW_IMPLEMENTATION"

# -- Config ---------------------------------------------------------------

RMWS=(rmw_cyclonedds_cpp rmw_fastrtps_cpp)
if [ "$QUICK" = "true" ]; then
    MSGS=(Array1k)
    RUNTIME=10
else
    MSGS=(Array1k Array4k Array16k Array64k Array256k)
    RUNTIME=30
fi
RATE=1000
RESULTS="/bench_results"

# -- Install Rust dans le container ----------------------------------------

# -- Upgrade CMake (LINK_LIBRARY:WHOLE_ARCHIVE needs >= 3.24) ----------------

echo "=== [DOCKER] Upgrade CMake... ==="
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq python3-pip git ros-humble-rmw-cyclonedds-cpp > /dev/null 2>&1
pip3 install --quiet cmake 2>&1 | tail -1
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
echo "CMake: $(cmake --version | head -1)"

echo "=== [DOCKER] Installation Rust... ==="
export RUSTUP_HOME=/tmp/rustup
export CARGO_HOME=/tmp/cargo
curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal 2>&1 | tail -3
source /tmp/cargo/env
echo "Cargo: $(cargo --version)"

# -- Build rmw_hdds --------------------------------------------------------

echo "=== [DOCKER] Build rmw_hdds... ==="
cd /hdds

# Build Rust libs
cargo build -p rmw-hdds -p hdds-c --release 2>&1 | tail -5
echo "[OK] Cargo build"

# Build le .so
BUILD_DIR="/tmp/rmw_hdds_build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake /hdds/rmw_hdds \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/ros/humble \
    -DHDDS_PROJECT_ROOT=/hdds \
    2>&1 | tail -5

make -j$(nproc) 2>&1 | tail -5
echo "[OK] CMake build"

# Installer dans le prefix ROS 2
cp -f "$BUILD_DIR/librmw_hdds.so" /opt/ros/humble/lib/
mkdir -p /opt/ros/humble/share/rmw_hdds
cp -f /hdds/rmw_hdds/package.xml /opt/ros/humble/share/rmw_hdds/

# ament_index markers
AMENT_IDX="/opt/ros/humble/share/ament_index/resource_index"
mkdir -p "${AMENT_IDX}/packages"
mkdir -p "${AMENT_IDX}/rmw_typesupport"
echo "" > "${AMENT_IDX}/packages/rmw_hdds"
echo "c:rosidl_typesupport_c:rosidl_typesupport_introspection_c;cpp:rosidl_typesupport_cpp:rosidl_typesupport_introspection_cpp" \
    > "${AMENT_IDX}/rmw_typesupport/rmw_hdds"

# Re-source apres install
source /opt/ros/humble/setup.bash

# Test rapide : est-ce que le .so se charge ?
if python3 -c "
import ctypes, os
lib = ctypes.CDLL('/opt/ros/humble/lib/librmw_hdds.so')
print('[OK] librmw_hdds.so charge')
" 2>/dev/null; then
    RMWS=(rmw_hdds rmw_cyclonedds_cpp rmw_fastrtps_cpp)
    echo "[OK] rmw_hdds ajoute au benchmark"
else
    echo "[WARN] librmw_hdds.so ne charge pas, on benchmark sans"
    echo "[WARN] Erreur probable : symbols manquants"
    # On tente quand meme mais on note l'erreur
    RMWS=(rmw_hdds rmw_cyclonedds_cpp rmw_fastrtps_cpp)
fi

# -- Build performance_test ------------------------------------------------

echo "=== [DOCKER] Build performance_test... ==="

PERF_WS="/tmp/perf_ws"
mkdir -p "$PERF_WS/src"
cd "$PERF_WS/src"
git clone --depth 1 https://gitlab.com/ApexAI/performance_test.git 2>&1 | tail -2

cd "$PERF_WS"
source /opt/ros/humble/setup.bash
colcon build \
    --cmake-args -DCMAKE_BUILD_TYPE=Release -DPERFORMANCE_TEST_PLUGIN=ROS2 \
    2>&1 | tail -10
source "$PERF_WS/install/setup.bash"
echo "[OK] performance_test build"

# Check if introspection type support is available for performance_test messages
echo "=== [DOCKER] Introspection type support check ==="
find "$PERF_WS/install" -name "*introspection*" -type f 2>/dev/null | head -5 || echo "(none found)"
echo "LD_LIBRARY_PATH (first 200 chars): ${LD_LIBRARY_PATH:0:200}"

# -- Run benchmarks --------------------------------------------------------

echo ""
echo "=== [DOCKER] Lancement des benchmarks ==="
echo "RMWs : ${RMWS[*]}"
echo "Messages : ${MSGS[*]}"
echo "Rate : ${RATE} msg/s, Runtime : ${RUNTIME}s"
echo ""

TOTAL=$(( ${#RMWS[@]} * ${#MSGS[@]} ))
CURRENT=0

for msg in "${MSGS[@]}"; do
    for rmw in "${RMWS[@]}"; do
        CURRENT=$((CURRENT + 1))
        LOGFILE="${RESULTS}/${rmw}_${msg}.csv"

        echo "[${CURRENT}/${TOTAL}] ${rmw} / ${msg} (${RUNTIME}s)..."

        export RMW_IMPLEMENTATION="$rmw"

        unset HDDS_TRANSPORT

        STDERR_LOG="${RESULTS}/${rmw}_${msg}.stderr"
        if timeout $((RUNTIME + 60)) ros2 run performance_test perf_test \
            -c rclcpp-single-threaded-executor \
            --msg "$msg" \
            --rate "$RATE" \
            --max-runtime "$RUNTIME" \
            --logfile "$LOGFILE" \
            2>"$STDERR_LOG" | tail -2; then
            echo "  [OK] -> $(basename $LOGFILE)"
            # Show diagnostic logs from rmw_hdds
            if [ "$rmw" = "rmw_hdds" ]; then
                grep -E "PUB-CREATE|SUB-CREATE|hdds_c|binding|Publish fallback|introspection" "$STDERR_LOG" | head -30 || true
            fi
        else
            echo "  [WARN] ECHEC ou timeout pour ${rmw}/${msg}"
            echo "FAILED" > "$LOGFILE"
        fi

        sleep 2
    done
done

# -- Generer le resume -----------------------------------------------------

echo ""
echo "=== [DOCKER] Generation du resume ==="

SUMMARY="${RESULTS}/summary.txt"
cat > "$SUMMARY" <<EOF
# Benchmark RMW Comparison
# Date : $(date -Iseconds)
# Machine : $(uname -n) ($(nproc) cores, $(uname -m))
# Kernel : $(uname -r)
# ROS 2 : Humble (Docker osrf/ros:humble-desktop)
# Outil : Apex.AI performance_test (ROS2 plugin, rclcpp-single-threaded-executor)
# Config : rate=${RATE} msg/s, runtime=${RUNTIME}s, 1 pub + 1 sub, intra-process
# ---------------------------------------------------------------

EOF

# Parse les CSV pour extraire les stats
echo "Parsing results..."
python3 <<'PYEOF'
import csv, os, sys

results_dir = os.environ.get("RESULTS", "/bench_results")
summary_path = os.path.join(results_dir, "summary.txt")

data = []

for fname in sorted(os.listdir(results_dir)):
    if not fname.endswith(".csv"):
        continue
    fpath = os.path.join(results_dir, fname)
    with open(fpath) as f:
        first = f.readline().strip()
        if first == "FAILED":
            parts = fname.replace(".csv","").split("_", 1)
            # rmw_hdds_Array1k -> rmw=rmw_hdds, msg=Array1k
            # rmw_cyclonedds_cpp_Array1k -> need smarter split
            data.append({"file": fname, "failed": True})
            continue

    # Read CSV (Apex.AI format: tab-separated with trailing commas, double-tabs in data)
    try:
        with open(fpath) as f:
            content = f.read()
        if "---EXPERIMENT-START---" not in content:
            continue
        section = content.split("---EXPERIMENT-START---")[1].strip()
        lines = [l.strip() for l in section.split("\n") if l.strip()]
        if len(lines) < 2:
            continue

        # Parse header: split by tab, strip commas
        headers = [h.strip().rstrip(",") for h in lines[0].split("\t") if h.strip()]

        # Parse data rows (values separated by tabs, with trailing commas)
        rows = []
        for line in lines[1:]:
            vals = [v.strip().rstrip(",") for v in line.split("\t") if v.strip()]
            if len(vals) == len(headers):
                rows.append(dict(zip(headers, vals)))

        if not rows:
            continue

        # Steady state: every row after the first two seconds (startup). A run of two rows
        # or fewer has no steady window to cut, so it falls back to every row.
        steady = rows[2:] if len(rows) > 2 else rows

        def safe_float(v):
            try:
                f = float(v)
                if f != f or abs(f) > 1e10:  # NaN or sentinel
                    return None
                return f
            except (ValueError, TypeError):
                return None

        def get_col(pattern):
            return [h for h in headers if pattern in h.lower()]

        is_ms = any("(ms)" in h for h in headers)
        unit_factor = 1000.0 if is_ms else 1.0  # convert to us

        lat_mean_col = get_col("latency_mean")
        lat_max_col = get_col("latency_max")

        lat_means = [safe_float(r.get(lat_mean_col[0], "")) for r in steady] if lat_mean_col else []
        lat_means = [v for v in lat_means if v is not None]
        lat_maxes = [safe_float(r.get(lat_max_col[0], "")) for r in steady] if lat_max_col else []
        lat_maxes = [v for v in lat_maxes if v is not None]
        # Whole run as well as steady state. Reporting only the steady window invites a reader
        # to quote it as the worst sample of the run, which it is not: the startup seconds hold
        # the largest spikes on some stacks.
        all_maxes = [safe_float(r.get(lat_max_col[0], "")) for r in rows] if lat_max_col else []
        all_maxes = [v for v in all_maxes if v is not None]
        all_means = [safe_float(r.get(lat_mean_col[0], "")) for r in rows] if lat_mean_col else []
        all_means = [v for v in all_means if v is not None]
        recvs = [safe_float(r.get("received", "")) for r in steady]
        recvs = [v for v in recvs if v is not None]
        sents = [safe_float(r.get("sent", "")) for r in steady]
        sents = [v for v in sents if v is not None]

        data.append({
            "file": fname,
            "failed": False,
            "lat_mean_us": (sum(lat_means)/len(lat_means)*unit_factor) if lat_means else 0,
            "lat_max_us": (max(lat_maxes)*unit_factor) if lat_maxes else 0,
            "run_mean_us": (sum(all_means)/len(all_means)*unit_factor) if all_means else 0,
            "run_max_us": (max(all_maxes)*unit_factor) if all_maxes else 0,
            "steady_rows": len(steady),
            "run_rows": len(rows),
            "recv_per_s": sum(recvs)/len(recvs) if recvs else 0,
            "sent_per_s": sum(sents)/len(sents) if sents else 0,
            "columns": headers,
        })
    except Exception as e:
        data.append({"file": fname, "failed": True, "error": str(e)})

# Write summary
with open(summary_path, "a") as f:
    f.write("# Two windows per file. STEADY = every second after the first two seconds;\n")
    f.write("# RUN = every second of the run, startup included. Quote the one you mean.\n")
    f.write(f"{'File':<45} {'Steady Mean':>12} {'Steady Max':>12} {'Run Mean':>12} {'Run Max':>12} {'Sent/s':>10} {'Recv/s':>10}\n")
    f.write(f"{'-'*45} {'-'*12} {'-'*12} {'-'*12} {'-'*12} {'-'*10} {'-'*10}\n")
    for d in data:
        if d.get("failed"):
            f.write(f"{d['file']:<45} {'FAILED':>12}\n")
        else:
            f.write(f"{d['file']:<45} {d['lat_mean_us']:>12.1f} {d['lat_max_us']:>12.1f} "
                    f"{d['run_mean_us']:>12.1f} {d['run_max_us']:>12.1f} "
                    f"{d['sent_per_s']:>10.0f} {d['recv_per_s']:>10.0f}\n")
    if data and not data[0].get("failed"):
        f.write(f"\n# windows: steady = {data[0].get('steady_rows')} rows, run = {data[0].get('run_rows')} rows\n")

    # Available columns for debug
    if data and not data[0].get("failed"):
        f.write(f"\n# CSV columns: {data[0].get('columns', 'N/A')}\n")

# Also print to stdout
with open(summary_path) as f:
    print(f.read())

PYEOF

echo ""
echo "=== [DOCKER] Benchmark termine ! ==="
echo "Results in: ${RESULTS}/"
ls -la "${RESULTS}/"

DOCKER_INNER
)

# -- Lancer dans Docker -----------------------------------------------------

echo "[BENCH] Lancement du container Docker..."
echo "[BENCH] Quick mode: $QUICK"

docker run --rm \
    --network host \
    --name "rmw_bench_${TIMESTAMP}" \
    -v "${HDDS_ROOT}:/hdds:rw" \
    -v "${RUN_DIR}:/bench_results:rw" \
    -e "RESULTS=/bench_results" \
    "$DOCKER_IMAGE" \
    bash -c "$INNER_SCRIPT" -- "$QUICK"

EXIT_CODE=$?

echo ""
echo "[BENCH] Container termine (exit code: $EXIT_CODE)"
echo "[BENCH] results: ${RUN_DIR}/"

if [[ -f "${RUN_DIR}/summary.txt" ]]; then
    echo ""
    cat "${RUN_DIR}/summary.txt"
fi
