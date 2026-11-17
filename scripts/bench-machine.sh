#!/usr/bin/env bash
# Run the HDDS latency benchmarks on ONE machine and emit a result that says
# what was measured, on what, and under which conditions.
#
# WHY THIS EXISTS IN THIS SHAPE
#
# Every rule below exists because a wrong number was once produced without it:
#
# * NO SOLO RUNS. One run is an anecdote. The script refuses fewer than
#   MIN_REPS and reports the median WITH the spread, because a median whose
#   spread nobody printed is a number nobody can challenge.
# * THE LIBC IS PART OF THE MEASUREMENT, not a build detail. On an aarch64
#   industrial gateway the same source can differ by a factor of two between
#   a glibc build and a musl-static build, from the allocator alone. A result that does not name its libc is not comparable
#   with any other result.
# * THE GOVERNOR IS PART OF THE MEASUREMENT. A powersave or ondemand run is
#   allowed - some machines have no root - but it is recorded as such and the
#   script says so loudly, because `ondemand` on a 4-core box with one busy
#   core stays at the LOW operating point and quietly costs a third of the
#   clock.
# * SO IS THE PINNING. A cross-thread figure taken across two hyperthread
#   siblings is not the same measurement as one across two physical cores.
# * SO IS THE BUILD RECIPE. The workspace release profile has no LTO; the
#   crown A/B recipe does. Same source, ~22 ns apart on x86.
#
# Usage:
#   bench-machine.sh <crown-binary> [xthread-binary] [writer_cpu] [reader_cpu]
# Environment:
#   HDDS_BENCH_REPS       repetitions per figure (default 7, minimum 5)
#   HDDS_BENCH_ALLOW_GOV  set to 1 to run without the performance governor
#   HDDS_BENCH_LIBC       label for the build's libc (else guessed from ldd)
#   HDDS_BENCH_OUT        output file (default ./bench-<host>-<libc>.json)
set -uo pipefail

CROWN="${1:?usage: bench-machine.sh <crown-binary> [xthread-binary] [wcpu] [rcpu]}"
XTHREAD="${2:-}"
WCPU="${3:-0}"
RCPU="${4:-1}"
REPS="${HDDS_BENCH_REPS:-7}"
MIN_REPS=5

die() { printf 'REFUSING: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[[ -x "$CROWN" ]] || die "crown binary not executable: $CROWN"
[[ "$REPS" =~ ^[0-9]+$ ]] || die "HDDS_BENCH_REPS must be a number"
(( REPS >= MIN_REPS )) || die "a benchmark is not a single run: REPS=$REPS, minimum $MIN_REPS"
have taskset || die "taskset is required (pinning is part of the measurement)"

# ---------------------------------------------------------------- environment
HOST="$(hostname -s)"
ARCH="$(uname -m)"
KERNEL="$(uname -r)"
OS="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
CPU="$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
[[ -z "$CPU" ]] && CPU="$(grep -m1 -E '^(Model|Hardware|CPU part)' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
[[ -z "$CPU" ]] && CPU="unknown"
NCPU="$(nproc)"
LOAD1="$(awk '{print $1}' /proc/loadavg)"

gov_of()  { cat "/sys/devices/system/cpu/cpu$1/cpufreq/scaling_governor" 2>/dev/null || echo none; }
freq_of() { cat "/sys/devices/system/cpu/cpu$1/cpufreq/scaling_cur_freq" 2>/dev/null || echo NA; }
maxfreq_of() { cat "/sys/devices/system/cpu/cpu$1/cpufreq/scaling_max_freq" 2>/dev/null || echo NA; }
siblings_of() { cat "/sys/devices/system/cpu/cpu$1/topology/thread_siblings_list" 2>/dev/null || echo "$1"; }
# Concatenated disable flags of every idle state past C1, so a half-configured
# machine is visible in the record rather than silently averaged in.
idle_of() {
    local f flags=""
    for f in /sys/devices/system/cpu/cpu"$1"/cpuidle/state*/disable; do
        case "$f" in */state0/*|*/state1/*) continue ;; esac
        [[ -r "$f" ]] && flags+="$(cat "$f")"
    done
    printf '%s' "${flags:-none}"
}

GOV="$(gov_of "$WCPU")"
if [[ "$GOV" != performance && "${HDDS_BENCH_ALLOW_GOV:-0}" != 1 ]]; then
    die "governor on cpu$WCPU is '$GOV', not performance (set it, or HDDS_BENCH_ALLOW_GOV=1 to record a non-performance run)"
fi

# The libc a binary was built against changes the result by a factor of two on
# some targets, so it is recorded, and guessed only if the caller did not say.
guess_libc() {
    local bin="$1"
    if have ldd && ldd "$bin" 2>/dev/null | grep -q 'libc\.so'; then
        local v; v="$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$')"
        echo "glibc${v:+ $v} (dynamic)"
    elif have file && file "$bin" 2>/dev/null | grep -q 'statically linked'; then
        echo "static (musl assumed)"
    else
        echo "unknown"
    fi
}
LIBC="${HDDS_BENCH_LIBC:-$(guess_libc "$CROWN")}"
OUT="${HDDS_BENCH_OUT:-./bench-${HOST}-$(echo "$LIBC" | tr -c 'A-Za-z0-9' '-' | cut -c1-12).json}"

sha_of() { if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else echo unknown; fi; }

printf 'host       %s (%s, %s)\n' "$HOST" "$ARCH" "$OS"
printf 'kernel     %s\n' "$KERNEL"
printf 'cpu        %s, %s logical\n' "$CPU" "$NCPU"
printf 'governor   cpu%s=%s cpu%s=%s  freq=%s (max %s)\n' \
    "$WCPU" "$(gov_of "$WCPU")" "$RCPU" "$(gov_of "$RCPU")" "$(freq_of "$WCPU")" "$(maxfreq_of "$WCPU")"
printf 'idle>C1    cpu%s=[%s] cpu%s=[%s]  (1 = disabled)\n' \
    "$WCPU" "$(idle_of "$WCPU")" "$RCPU" "$(idle_of "$RCPU")"
printf 'pinning    writer=cpu%s (siblings %s), reader=cpu%s (siblings %s)\n' \
    "$WCPU" "$(siblings_of "$WCPU")" "$RCPU" "$(siblings_of "$RCPU")"
printf 'libc       %s\n' "$LIBC"
printf 'load1      %s   reps %s\n\n' "$LOAD1" "$REPS"

if [[ "$(siblings_of "$WCPU")" == "$(siblings_of "$RCPU")" && -n "$XTHREAD" ]]; then
    echo "WARNING: cpu$WCPU and cpu$RCPU are hyperthread siblings; the cross-thread"
    echo "         figure will be a same-physical-core figure. Recorded as such."
fi

# ------------------------------------------------------------------ measuring
# median and range, so nobody quotes the middle without the spread
stats() { sort -n | awk '{v[NR]=$1} END{ if (NR==0) {print "NA NA NA 0"; exit} printf "%d %d %d %d", v[int((NR+1)/2)], v[1], v[NR], NR }'; }

CROWN_P50=(); CROWN_P99=(); CROWN_MIN=()
echo "--- crown (single thread, cpu$WCPU), $REPS reps"
for ((r = 1; r <= REPS; r++)); do
    out="$(taskset -c "$WCPU" "$CROWN" 2>/dev/null)" || die "crown run $r failed"
    CROWN_P50+=("$(awk '/^p50 latency:/{print $3; exit}' <<<"$out")")
    CROWN_P99+=("$(awk '/^p99 latency:/{print $3; exit}' <<<"$out")")
    CROWN_MIN+=("$(awk '/^Min latency:/{print $3; exit}' <<<"$out")")
    printf '  rep%-2d p50=%s p99=%s min=%s\n' "$r" "${CROWN_P50[-1]}" "${CROWN_P99[-1]}" "${CROWN_MIN[-1]}"
done
read -r c50 c50lo c50hi c50n <<<"$(printf '%s\n' "${CROWN_P50[@]}" | stats)"
read -r c99 c99lo c99hi _ <<<"$(printf '%s\n' "${CROWN_P99[@]}" | stats)"
read -r cmin cminlo _ _ <<<"$(printf '%s\n' "${CROWN_MIN[@]}" | stats)"
printf '  MEDIAN p50=%s ns (range %s-%s, n=%s)  p99=%s ns  min=%s ns\n\n' \
    "$c50" "$c50lo" "$c50hi" "$c50n" "$c99" "$cminlo"

SPIN_P50=(); WAIT_P50=(); SPIN_MISS=(); WAIT_MISS=()
if [[ -n "$XTHREAD" && -x "$XTHREAD" ]]; then
    echo "--- cross-thread (cpu$WCPU -> cpu$RCPU), $REPS reps, KeepLast(4)"
    for ((r = 1; r <= REPS; r++)); do
        out="$(HDDS_XBENCH_WRITER_CPU="$WCPU" HDDS_XBENCH_READER_CPU="$RCPU" \
               HDDS_XBENCH_HISTORY=4 "$XTHREAD" 2>/dev/null)" || die "cross-thread run $r failed"
        SPIN_P50+=("$(awk '/^spin_p50_ns:/{print $2; exit}' <<<"$out")")
        WAIT_P50+=("$(awk '/^waitset_p50_ns:/{print $2; exit}' <<<"$out")")
        SPIN_MISS+=("$(awk '/^spin_missed:/{print $2; exit}' <<<"$out")")
        WAIT_MISS+=("$(awk '/^waitset_missed:/{print $2; exit}' <<<"$out")")
        printf '  rep%-2d spin=%s (lost %s)  waitset=%s (lost %s)\n' \
            "$r" "${SPIN_P50[-1]}" "${SPIN_MISS[-1]}" "${WAIT_P50[-1]}" "${WAIT_MISS[-1]}"
    done
    read -r s50 s50lo s50hi _ <<<"$(printf '%s\n' "${SPIN_P50[@]}" | stats)"
    read -r w50 w50lo w50hi _ <<<"$(printf '%s\n' "${WAIT_P50[@]}" | stats)"
    printf '  MEDIAN spin=%s ns (range %s-%s)  waitset=%s ns (range %s-%s)\n\n' \
        "$s50" "$s50lo" "$s50hi" "$w50" "$w50lo" "$w50hi"
else
    s50=NA; s50lo=NA; s50hi=NA; w50=NA; w50lo=NA; w50hi=NA
fi

join_csv() { local IFS=,; echo "$*"; }
cat > "$OUT" <<JSON
{
  "schema": "hdds-machine-bench/1",
  "host": { "name": "$HOST", "arch": "$ARCH", "os": "$OS", "kernel": "$KERNEL",
            "cpu": "$CPU", "logical_cpus": $NCPU, "load1_at_start": $LOAD1 },
  "conditions": {
    "libc": "$LIBC",
    "governor_writer": "$(gov_of "$WCPU")", "governor_reader": "$(gov_of "$RCPU")",
    "governor_forced": ${HDDS_BENCH_ALLOW_GOV:-0},
    "freq_khz": "$(freq_of "$WCPU")", "freq_max_khz": "$(maxfreq_of "$WCPU")",
    "idle_states_past_c1_disabled_writer": "$(idle_of "$WCPU")",
    "idle_states_past_c1_disabled_reader": "$(idle_of "$RCPU")",
    "writer_cpu": $WCPU, "reader_cpu": $RCPU,
    "writer_siblings": "$(siblings_of "$WCPU")", "reader_siblings": "$(siblings_of "$RCPU")",
    "same_physical_core": $([[ "$(siblings_of "$WCPU")" == "$(siblings_of "$RCPU")" ]] && echo true || echo false),
    "reps": $REPS
  },
  "binaries": {
    "crown": { "path": "$CROWN", "sha256": "$(sha_of "$CROWN")" },
    "xthread": { "path": "${XTHREAD:-none}", "sha256": "$([[ -n "$XTHREAD" && -x "$XTHREAD" ]] && sha_of "$XTHREAD" || echo none)" }
  },
  "crown": { "p50_ns_median": $c50, "p50_ns_min": $c50lo, "p50_ns_max": $c50hi,
             "p99_ns_median": $c99, "min_ns_min": $cminlo,
             "p50_all": [$(join_csv "${CROWN_P50[@]}")] },
  "cross_thread": { "spin_p50_ns_median": ${s50:-null}, "spin_p50_ns_min": ${s50lo:-null}, "spin_p50_ns_max": ${s50hi:-null},
                    "waitset_p50_ns_median": ${w50:-null}, "waitset_p50_ns_min": ${w50lo:-null}, "waitset_p50_ns_max": ${w50hi:-null},
                    "spin_p50_all": [$(join_csv "${SPIN_P50[@]:-}")],
                    "waitset_p50_all": [$(join_csv "${WAIT_P50[@]:-}")] },
  "note": "A figure from this file is only comparable with another that names the same libc, governor, idle policy and pinning."
}
JSON
echo "written: $OUT"
