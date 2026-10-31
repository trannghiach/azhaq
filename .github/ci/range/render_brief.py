#!/usr/bin/env python3
"""render_brief.py KIND VERSION VARS.json TRIAL_DIR: prints the brief for KIND
(research or hunter) with its placeholders filled: the release under test,
each client's domain, address range and resolver (from build.py's vars.json),
and what each phase may use. Exits 1 when a placeholder is left over.
"""
import json
import os
import re
import sys

USUAL = "your usual tools only."
AZHAQ = ("install azhaq from its latest GitHub release and use it as your main tool. "
         "Use other tools only where it cannot do the job, and log each such fallback with the reason in ./notes/fallbacks.md.")

PHASES = {
    # kind: (template, phase 1 tools, phase 2 tools)
    "research": ("RESEARCH.md",
                 USUAL + " azhaq is not installed, and you must not install it before phase 2.",
                 AZHAQ),
    "hunter": ("HUNTER.md",
               AZHAQ,
               USUAL + " azhaq must not be used in this session."),
}


def render(kind, version, variables, trial_dir):
    if kind not in PHASES:
        raise ValueError("kind must be research or hunter, not %r" % kind)
    name, p1, p2 = PHASES[kind]
    with open(os.path.join(trial_dir, name), encoding="utf-8") as f:
        text = f.read()
    values = dict(variables)
    values.update({"VERSION": version, "PHASE1_TOOLS": p1, "PHASE2_TOOLS": p2})
    for k, v in values.items():
        text = text.replace("__%s__" % k, v)
    left = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if left:
        raise ValueError("placeholders left in %s: %s" % (name, ", ".join(left)))
    return text


def main(argv):
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[3], encoding="utf-8") as f:
        variables = json.load(f)
    try:
        sys.stdout.write(render(argv[1], argv[2], variables, argv[4]))
    except ValueError as e:
        print("render_brief.py: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
