# Fat image for OMG dds-rtps interoperability testing.
# Bundles ALL vendor shape_main binaries + the OMG Python harness so a pair
# runs identically to the official CI (same binaries, same harness) but inside
# an isolated container/network.
#
# glibc requirement: vendor binaries need up to GLIBC_2.34 -> ubuntu:22.04
# ships glibc-2.35, which covers it.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        ca-certificates \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Harness deps (pinned light; the harness only uses pexpect + junitparser).
RUN pip3 install --no-cache-dir pexpect junitparser

WORKDIR /opt/dds-rtps

# Harness (4 self-contained .py files: no external resource/ dependency).
COPY harness/ /opt/dds-rtps/

# Vendor shape_main binaries under ./bin (referenced as -P ./bin/<name>).
COPY binaries/ /opt/dds-rtps/bin/
RUN chmod +x /opt/dds-rtps/bin/*

# The harness itself spawns BOTH the publisher and subscriber processes, so a
# single container = one fully co-located pub/sub pair.
ENTRYPOINT ["python3", "interoperability_report.py"]
