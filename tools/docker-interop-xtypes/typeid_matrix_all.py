#!/usr/bin/env python3
"""Offline TypeId cross-vendor matrix for the OMG dds-xtypes engine set.

TypeId scoring is NOT a live interop: each engine computes its own
TypeIdentifiers independently (shape_main --print-typeid per type), then the
score is a pairwise string compare -- OK iff pub_val == sub_val and value is not
'not found' (mirrors interoperability_report.add_type_id_results_to_suite /
typeid_matrix.py). So no container isolation is needed; this runs on the host.

Only HDDS changes between the OFF and ON feature builds; the 4 vendor typeid
maps are identical across variants.

Usage:  typeid_matrix_all.py <on|off> [type_object_version=2] [suite=test_suite_iso70]
Run needs the harness checkout ($XT_SRC, default /opt/dds-xtypes) on sys.path
(print_ids + the suite + types/).
"""
import sys
import os

XT = os.environ.get("XT_SRC", "/opt/dds-xtypes")
sys.path.insert(0, XT)
os.chdir(XT)  # relative --type-folder types --data-folder data
import print_ids

variant = sys.argv[1] if len(sys.argv) > 1 else "on"
tov = sys.argv[2] if len(sys.argv) > 2 else "2"
suite = sys.argv[3] if len(sys.argv) > 3 else "test_suite_iso70"

HDDS = {
    "on": os.environ.get("HDDS_ON", "/tmp/hdds_xt_ON8"),
    "off": os.environ.get("HDDS_OFF", "/tmp/hdds_xt_OFF8"),
}[variant]
V = os.environ.get("VENDOR_DIR", "/tmp/xtypes_vendors")
ENGINES = {
    "hdds":    HDDS,
    "connext": f"{V}/connext_dds-7.7.0_test_main_linux/connext_dds-7.7.0_test_main_linux",
    "cyclone": f"{V}/eclipse_cyclone-11.0.1_test_main_linux/eclipse_cyclone-11.0.1_test_main_linux",
    "coredx":  f"{V}/toc_coredx_dds-6.14.1_test_main_linux/toc_coredx_dds-6.14.1_test_main_linux",
    "opendds": f"{V}/opendds-3.35.0-dev_test_main_linux",
}

print(f"# TypeId matrix  hdds={variant}  TO=v{tov}  suite={suite}")
maps = {}
for name, exe in ENGINES.items():
    ids = print_ids.get_type_ids(exe=exe, test_suite=suite, type_object_version=tov)
    maps[name] = {(e["name"], e["kind"]): e["value"] for e in ids}
    print(f"  {name:8s}: {len(maps[name])} typeids")

names = list(ENGINES)


def score(pub, sub):
    pm, sm = maps[pub], maps[sub]
    keys = set(pm) | set(sm)
    ok = sum(1 for k in keys
             if pm.get(k, "missing") == sm.get(k, "missing") and pm.get(k) != "not found")
    return ok, len(keys)


print(f"\nTypeId matrix (hdds={variant}, TO=v{tov})  cell = OK/total")
print("pub\\sub   " + "".join(f"{n:>11}" for n in names))
grand_ok = grand_tot = 0
hdds_ok = hdds_tot = 0
for pub in names:
    row = f"{pub:9s}"
    for sub in names:
        ok, tot = score(pub, sub)
        row += f"{f'{ok}/{tot}':>11}"
        grand_ok += ok
        grand_tot += tot
        if pub == "hdds" or sub == "hdds":
            hdds_ok += ok
            hdds_tot += tot
    print(row)
print(f"\nTOTAL TypeId (hdds={variant}) full 5x5 : {grand_ok}/{grand_tot}")
print(f"HDDS-involving cells (9)          : {hdds_ok}/{hdds_tot}")
