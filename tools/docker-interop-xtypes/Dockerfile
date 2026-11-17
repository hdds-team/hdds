# Fat image for OMG dds-xtypes interoperability testing (DATA matrix).
# Bundles the OMG dds-xtypes Python harness + its type/data resource tree +
# every engine's shape_main/test_main binary, so a pair runs identically to a
# host run but inside an isolated container/network.
#
# glibc: the HDDS xtypes driver (native build on this host) needs GLIBC_2.39;
# the vendor test_main binaries need only GLIBC_2.34. ubuntu:24.04 ships
# glibc-2.39 -> covers BOTH. (22.04's 2.35 is too old for HDDS.)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        ca-certificates \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Harness deps. --break-system-packages: 24.04 is PEP-668 externally-managed;
# this is a throwaway CI image so global installs are fine.
RUN pip3 install --no-cache-dir --break-system-packages pexpect junitparser

WORKDIR /opt/dds-xtypes

# The OMG dds-xtypes harness + its RELATIVE resource tree (types/, data/,
# resource/) + the DATA test suite(s). Copied verbatim from the working host
# checkout so the harness's relative `--type-folder types --data-folder data`
# spawns resolve exactly as they do on the host.
COPY harness/ /opt/dds-xtypes/

# Engine binaries under ./bin (referenced as --pub-exe ./bin/<name>).
# 4 vendor test_main + hdds_off + hdds_on (feature OFF/ON of the same commit).
COPY binaries/ /opt/dds-xtypes/bin/
RUN chmod +x /opt/dds-xtypes/bin/*

# The harness spawns BOTH publisher and subscriber, so one container = one
# fully co-located pub/sub pair.
ENTRYPOINT ["python3", "interoperability_report.py"]
