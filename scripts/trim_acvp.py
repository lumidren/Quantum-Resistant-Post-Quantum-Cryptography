#!/usr/bin/env python3
"""Trim official NIST ACVP vector files into the compact KAT files used by every test suite.

Usage:
    python -I scripts/trim_acvp.py <dir with ACVP internalProjection json files> tests/kat/vectors

Input files are the ``internalProjection.json`` files from
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files for
ML-KEM-keyGen-FIPS203, ML-KEM-encapDecap-FIPS203, ML-DSA-keyGen-FIPS204, ML-DSA-sigGen-FIPS204,
ML-DSA-sigVer-FIPS204, SLH-DSA-keyGen-FIPS205, SLH-DSA-sigGen-FIPS205, SLH-DSA-sigVer-FIPS205.

The script never modifies a vector; it only selects a deterministic subset (first N test cases of
each group, with pass and fail cases balanced where a ``testPassed`` flag exists) and flattens the
group attributes into each test case so that consumers do not need the ACVP group structure.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

PQ_PARAM_SETS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
}

GROUP_FIELDS = (
    "parameterSet", "testType", "function", "deterministic", "signatureInterface",
    "preHash", "externalMu",
)


def load(d: str, name: str) -> dict[str, Any]:
    with open(os.path.join(d, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def flatten(group: dict[str, Any], test: dict[str, Any]) -> dict[str, Any]:
    out = {k: group[k] for k in GROUP_FIELDS if k in group}
    for k, v in test.items():
        if k == "deferred":
            continue
        out[k] = v
    return out


def pick(tests: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    """Pick up to n tests; when a testPassed flag exists, balance pass and fail cases."""
    if not tests or "testPassed" not in tests[0]:
        return tests[:n]
    passed = [t for t in tests if t["testPassed"]]
    failed = [t for t in tests if not t["testPassed"]]
    half = max(1, n // 2)
    chosen = passed[:half] + failed[: n - min(len(passed), half)]
    chosen.sort(key=lambda t: t["tcId"])
    return chosen[:n]


def select(data: dict[str, Any], want, per_group: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in data["testGroups"]:
        if g.get("parameterSet") not in PQ_PARAM_SETS:
            continue
        if not want(g):
            continue
        for t in pick(g["tests"], per_group):
            out.append(flatten(g, t))
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    os.makedirs(dst, exist_ok=True)

    files: dict[str, list[dict[str, Any]]] = {}

    kg = load(src, "ML-KEM-keyGen-FIPS203")
    files["ml-kem-keygen"] = select(kg, lambda g: g["testType"] == "AFT", 5)

    ed = load(src, "ML-KEM-encapDecap-FIPS203")
    files["ml-kem-encaps"] = select(ed, lambda g: g.get("function") == "encapsulation", 5)
    files["ml-kem-decaps"] = select(ed, lambda g: g.get("function") == "decapsulation", 10)
    files["ml-kem-keycheck"] = select(
        ed, lambda g: g.get("function") in ("encapsulationKeyCheck", "decapsulationKeyCheck"), 4
    )

    dkg = load(src, "ML-DSA-keyGen-FIPS204")
    files["ml-dsa-keygen"] = select(dkg, lambda g: g["testType"] == "AFT", 3)

    dsg = load(src, "ML-DSA-sigGen-FIPS204")
    files["ml-dsa-siggen"] = (
        select(dsg, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure" and g["deterministic"], 3)
        + select(dsg, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure" and not g["deterministic"], 3)
        + select(dsg, lambda g: g["signatureInterface"] == "internal" and not g["externalMu"], 2)
    )

    dsv = load(src, "ML-DSA-sigVer-FIPS204")
    files["ml-dsa-sigver"] = (
        select(dsv, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure", 8)
        + select(dsv, lambda g: g["signatureInterface"] == "internal" and not g["externalMu"], 4)
    )

    skg = load(src, "SLH-DSA-keyGen-FIPS205")
    files["slh-dsa-keygen"] = select(skg, lambda g: g["testType"] == "AFT", 10)

    ssg = load(src, "SLH-DSA-sigGen-FIPS205")
    files["slh-dsa-siggen"] = (
        select(ssg, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure" and g["deterministic"], 3)
        + select(ssg, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure" and not g["deterministic"], 2)
        + select(ssg, lambda g: g["signatureInterface"] == "internal", 2)
    )

    ssv = load(src, "SLH-DSA-sigVer-FIPS205")
    files["slh-dsa-sigver"] = (
        select(ssv, lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure", 8)
        + select(ssv, lambda g: g["signatureInterface"] == "internal", 4)
    )

    total = 0
    for name, tests in files.items():
        path = os.path.join(dst, f"{name}.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"source": "usnistgov/ACVP-Server gen-val/json-files (internalProjection)",
                       "file": name, "count": len(tests), "tests": tests}, f, indent=1)
            f.write("\n")
        total += len(tests)
        print(f"{name:20s} {len(tests):4d} tests  {os.path.getsize(path)/1024:8.1f} KiB")
    print(f"total {total} tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
