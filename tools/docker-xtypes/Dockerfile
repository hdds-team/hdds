# Fat image for OMG dds-xtypes interoperability testing.
# Bundles the HDDS xtypes driver + vendor test_main binaries + the OMG Python
# harness (incl. its types/ data/ resource/ asset dirs) so a pair runs
# identically to the official CI but inside an isolated container/network.
#
# Sibling of tools/docker-interop (dds-rtps). DIFFERENCES vs that one:
#   - runner is interoperability_report.py from the dds-xtypes repo, which needs
#     3 sibling modules + the types/ data/ resource/ dirs (test_suite.py loads
#     type/data XML via RELATIVE paths -> the runner MUST execute from
#     /opt/dds-xtypes, which is the WORKDIR).
#   - the 4 test dimensions are (-x {1,2}) x (--type-object-version {1,2}), not a
#     single -x like rtps.
#   - a junitparser control-byte sanitizer wrapper (run_xtypes.py) is the
#     entrypoint; without it one flaky test's stdout aborts the whole XML.
#   - extra pip dep: lxml (junitparser serializer backend used by this harness).
#
# glibc: the HDDS xtypes driver may be built against
# GLIBC_2.39 (verified via ldd inside the image), so ubuntu:22.04's glibc-2.35 is
# NOT enough -- we use ubuntu:24.04 (glibc-2.39). The vendor test_main binaries
# need only up to GLIBC_2.34 and run fine on 2.39 (glibc is backward-compatible).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        ca-certificates \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Harness deps. lxml is required here (the xtypes report relies on the lxml
# backend for junitparser); pexpect drives the pub/sub processes.
# --break-system-packages: ubuntu:24.04 marks the system python PEP 668
# externally-managed; this image is single-purpose so installing globally is fine.
RUN pip3 install --no-cache-dir --break-system-packages pexpect junitparser lxml

WORKDIR /opt/dds-xtypes

# Harness sources + asset dirs. The runner loads types/*.xml and data/*.xml via
# relative paths, so these MUST sit under the WORKDIR.
COPY harness/ /opt/dds-xtypes/

# Test binaries under ./bin (referenced as --pub-exe ./bin/<name>).
COPY binaries/ /opt/dds-xtypes/bin/
RUN chmod +x /opt/dds-xtypes/bin/*

# Entry = the sanitizing wrapper; forwards all args to interoperability_report.py.
ENTRYPOINT ["python3", "/opt/dds-xtypes/run_xtypes.py"]
