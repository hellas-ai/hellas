"""Per-crate line-coverage ratchet for the `unit` check.

usage: coverage-ratchet.py SUMMARY_JSON FLOORS_JSON MEASURED_JSON

SUMMARY_JSON is `cargo llvm-cov report --json --summary-only`. Only production
files under `crates/<name>/` count: test files, test-support modules, benches
and examples are left out. The check fails when a crate falls more than SLACK
points below its floor in FLOORS_JSON, so a gain in one crate cannot hide a
loss in another. MEASURED_JSON receives the floors this run would record; copy
it over FLOORS_JSON when a change raises coverage and commit the result.
"""

import json
import math
import os
import re
import sys

# Retries, races and timeouts take slightly different paths from run to run.
SLACK = 0.5
NOT_PRODUCTION = re.compile(r"/(tests|test_support|benches|examples)(/|\.rs$)|tests\.rs$")


def measure(summary):
    root = os.path.join(os.getcwd(), "crates") + os.sep
    totals = {}
    with open(summary) as file:
        for entry in json.load(file)["data"][0]["files"]:
            name = entry["filename"]
            if not name.startswith(root) or NOT_PRODUCTION.search(name):
                continue
            crate = name[len(root) :].split(os.sep, 1)[0]
            lines = entry["summary"]["lines"]
            covered, count = totals.get(crate, (0, 0))
            totals[crate] = (covered + lines["covered"], count + lines["count"])
    return {crate: 100 * c / n for crate, (c, n) in sorted(totals.items()) if n}


def main(summary, floors, recorded):
    measured = measure(summary)
    with open(recorded, "w") as file:
        rounded = {crate: math.floor(percent * 10) / 10 for crate, percent in measured.items()}
        json.dump(rounded, file, indent=2, sort_keys=True)
        file.write("\n")
    with open(floors) as file:
        floor = json.load(file)
    failed = []
    for crate in sorted(floor.keys() | measured.keys()):
        got, minimum = measured.get(crate), floor.get(crate)
        if minimum is None:
            print(f"{crate:16} {got:6.2f}%  no floor yet")
        elif got is None:
            print(f"{crate:16}   gone  floor {minimum:5.1f}%")
            failed.append(crate)
        else:
            mark = "FAIL" if got < minimum - SLACK else ("raise floor" if got >= minimum + 1 else "")
            print(f"{crate:16} {got:6.2f}%  floor {minimum:5.1f}%  {mark}")
            if mark == "FAIL":
                failed.append(crate)
    if failed:
        print(f"line coverage fell more than {SLACK} points below the floor: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
