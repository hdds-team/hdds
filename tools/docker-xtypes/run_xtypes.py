#!/usr/bin/env python3
"""junitparser-sanitizing wrapper around the OMG dds-xtypes interoperability
runner.

The xtypes harness writes the raw stdout of the test applications into the
JUnit XML (Failure/Error messages + attributes). A single control byte in a
test app's output makes lxml/junitparser abort serialization of the WHOLE
report -> one flaky case nukes the entire run's XML. We monkeypatch junitparser
to strip XML-illegal control bytes before they ever reach the serializer, then
hand control to interoperability_report.py unchanged.

This is the same sanitization approach as the xtypes night-run tooling,
generalized to a transparent passthrough: every CLI arg after the script name is forwarded
verbatim to interoperability_report.py.

Usage (identical to interoperability_report.py):
    run_xtypes.py --pub-exe ./bin/PUB --sub-exe ./bin/SUB \\
                  -x {1|2} --type-object-version {1|2} -o out.xml [-t case...]
"""
import re
import runpy
import sys

SUITE_DIR = "/opt/dds-xtypes"
sys.path.insert(0, SUITE_DIR)
REPORT = SUITE_DIR + "/interoperability_report.py"

# XML 1.0 forbids these control chars (everything < 0x20 except \t \n \r).
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _clean(v):
    return _CTRL.sub("?", v) if isinstance(v, str) else v


import junitparser.junitparser as jp  # noqa: E402

_orig_attr_set = jp.Attr.__set__


def _safe_attr_set(self, instance, value):
    return _orig_attr_set(self, instance, _clean(value))


jp.Attr.__set__ = _safe_attr_set

for _cls_name in ("Failure", "Error", "Skipped"):
    _cls = getattr(jp, _cls_name, None)
    if _cls is None:
        continue
    _orig_init = _cls.__init__

    def _make_init(orig):
        def _init(self, message=None, type_=None, *a, **kw):
            return orig(self, _clean(message), type_, *a, **kw)
        return _init

    _cls.__init__ = _make_init(_orig_init)

# Forward every arg verbatim to the real runner.
sys.argv = [REPORT] + sys.argv[1:]
runpy.run_path(REPORT, run_name="__main__")
