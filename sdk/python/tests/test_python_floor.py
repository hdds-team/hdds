# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""The declared interpreter floor is proved, not asserted.

``requires-python`` says which interpreters may INSTALL the wheel;
the ``Programming Language :: Python :: 3.N`` classifiers say which
interpreters the SDK gate actually RUNS (scripts/test-sdk.sh Layer 1b
fails on a claimed version it cannot execute). The two are different
claims and drift apart silently, so this module pins both ends:

* every module of the package parses under the floor
  (``ast.parse(..., feature_version=floor)`` rejects newer syntax) and
  keeps its annotations as strings (``from __future__ import
  annotations``), so no PEP 585/604 annotation is evaluated at import
  time on an old interpreter;
* the floor is not above any claimed classifier, i.e. the wheel never
  refuses to install on an interpreter the gate claims to support.

Hermetic: no native library, no network, no second interpreter.
"""

import ast
import re
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = SDK_ROOT / "pyproject.toml"
HDDS_PKG = SDK_ROOT / "hdds"

REQUIRES_PYTHON = re.compile(r'^requires-python\s*=\s*"\s*>=\s*(\d+)\.(\d+)\s*"', re.M)
CLASSIFIER = re.compile(r'"Programming Language :: Python :: (\d+)\.(\d+)"')


def declared_floor() -> tuple:
    match = REQUIRES_PYTHON.search(PYPROJECT.read_text())
    assert match, "requires-python must be a simple '>=X.Y' floor"
    return (int(match.group(1)), int(match.group(2)))


def claimed_classifiers() -> list:
    found = [(int(a), int(b)) for a, b in CLASSIFIER.findall(PYPROJECT.read_text())]
    assert found, "pyproject.toml claims no 'Programming Language :: Python :: 3.N' classifier"
    return sorted(found)


def package_modules() -> list:
    modules = sorted(HDDS_PKG.rglob("*.py"))
    assert modules, HDDS_PKG
    return modules


def test_floor_is_not_above_any_claimed_interpreter():
    """A classifier below the floor would claim an interpreter pip refuses."""
    floor = declared_floor()
    below = [c for c in claimed_classifiers() if c < floor]
    assert not below, (
        "classifiers claim %s but requires-python is >=%d.%d"
        % (["%d.%d" % c for c in below], floor[0], floor[1])
    )


def test_floor_is_at_most_the_running_interpreter():
    """Sanity: the interpreter running the suite satisfies the declared floor."""
    assert declared_floor() <= sys.version_info[:2]


@pytest.mark.parametrize("module", package_modules(), ids=lambda p: p.name)
def test_module_parses_at_the_declared_floor(module: Path):
    floor = declared_floor()
    source = module.read_text()
    try:
        ast.parse(source, filename=str(module), feature_version=floor)
    except SyntaxError as e:
        pytest.fail(
            "%s does not parse on python %d.%d (the declared requires-python "
            "floor): %s" % (module.name, floor[0], floor[1], e),
            pytrace=False,
        )


@pytest.mark.parametrize("module", package_modules(), ids=lambda p: p.name)
def test_module_annotations_are_never_evaluated_at_import(module: Path):
    """PEP 563 everywhere, so a 3.9 interpreter never evaluates ``dict[str, int]``.

    ``feature_version`` only rejects new SYNTAX; a subscripted builtin or a
    ``X | Y`` union in an annotation is valid syntax on 3.9 and raises
    ``TypeError`` at import there. ``from __future__ import annotations``
    makes every annotation a string, which removes the whole class.
    """
    tree = ast.parse(module.read_text(), filename=str(module))
    has_future = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    if has_future:
        return
    annotated = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AnnAssign, ast.arg)) and node.annotation is not None
    ] + [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None
    ]
    assert not annotated, (
        "%s carries annotations without 'from __future__ import annotations'; "
        "add it or the annotations are evaluated at import time on python %d.%d"
        % (module.name, declared_floor()[0], declared_floor()[1])
    )
