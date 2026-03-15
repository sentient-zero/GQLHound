#!/usr/bin/env bash
# ============================================================
# gql_diff.sh - Compare two GQL Hound export files
# Reports items in OLD that are missing from NEW.
#
# Usage: ./gql_diff.sh <old_export.json> <new_export.json>
# ============================================================

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <old_export.json> <new_export.json>"
    exit 1
fi

OLD="$1"
NEW="$2"

if [ ! -f "$OLD" ]; then echo "File not found: $OLD"; exit 1; fi
if [ ! -f "$NEW" ]; then echo "File not found: $NEW"; exit 1; fi

# Check for python3 or python
if command -v python3 &>/dev/null; then
    PY=python3
elif command -v python &>/dev/null; then
    PY=python
else
    echo "Error: python3 or python required"
    exit 1
fi

$PY - "$OLD" "$NEW" <<'PYEOF'
import json
import sys

def load(path):
    with open(path) as f:
        return json.load(f)

old = load(sys.argv[1])
new = load(sys.argv[2])

old_label = sys.argv[1]
new_label = sys.argv[2]

found_diff = False

# --- Operations ---
old_ops = {op["name"]: op for op in old.get("operations", [])}
new_ops = {op["name"]: op for op in new.get("operations", [])}

missing_ops = set(old_ops) - set(new_ops)
if missing_ops:
    found_diff = True
    print("=" * 60)
    print("OPERATIONS in OLD but missing from NEW: %d" % len(missing_ops))
    print("=" * 60)
    for name in sorted(missing_ops):
        op = old_ops[name]
        print("  - %s  [%s]  status=%s  count=%s  host=%s" % (
            name, op.get("type", "?"), op.get("status", "?"),
            op.get("count", "?"), op.get("host", "?")))
    print()

# Status changes
common_ops = set(old_ops) & set(new_ops)
status_changes = []
for name in sorted(common_ops):
    old_s = old_ops[name].get("status", "New")
    new_s = new_ops[name].get("status", "New")
    if old_s != new_s:
        status_changes.append((name, old_s, new_s))

if status_changes:
    found_diff = True
    print("=" * 60)
    print("STATUS CHANGES: %d" % len(status_changes))
    print("=" * 60)
    for name, old_s, new_s in status_changes:
        print("  - %s:  %s -> %s" % (name, old_s, new_s))
    print()

# --- Variables ---
old_vars = old.get("variables", {})
new_vars = new.get("variables", {})

missing_var_ops = set(old_vars) - set(new_vars)
missing_var_paths = []
for op_name in sorted(set(old_vars) & set(new_vars)):
    old_paths = set(old_vars[op_name].keys())
    new_paths = set(new_vars[op_name].keys())
    gone = old_paths - new_paths
    if gone:
        for p in sorted(gone):
            missing_var_paths.append((op_name, p, old_vars[op_name][p]))

if missing_var_ops or missing_var_paths:
    found_diff = True
    print("=" * 60)
    print("VARIABLE PATHS in OLD but missing from NEW")
    print("=" * 60)
    if missing_var_ops:
        print("  Entire operations missing (all vars lost):")
        for name in sorted(missing_var_ops):
            n = len(old_vars[name])
            print("    - %s  (%d paths)" % (name, n))
    if missing_var_paths:
        print("  Individual paths missing:")
        for op, path, entry in missing_var_paths:
            samples = ", ".join(entry.get("samples", []))
            print("    - %s -> %s  (seen %dx, samples: %s)" % (
                op, path, entry.get("count", 0), samples or "none"))
    print()

# --- Request shapes ---
old_reqs = old.get("requests", {})
new_reqs = new.get("requests", {})

missing_req_ops = set(old_reqs) - set(new_reqs)
missing_shapes = []

for op_name in sorted(set(old_reqs) & set(new_reqs)):
    # Build signature sets for comparison
    old_sigs = set()
    old_by_sig = {}
    for shape in old_reqs[op_name]:
        sig = frozenset(shape.get("keys", []))
        old_sigs.add(sig)
        old_by_sig[sig] = shape

    new_sigs = set()
    for shape in new_reqs[op_name]:
        sig = frozenset(shape.get("keys", []))
        new_sigs.add(sig)

    gone = old_sigs - new_sigs
    for sig in gone:
        shape = old_by_sig[sig]
        missing_shapes.append((op_name, shape))

if missing_req_ops or missing_shapes:
    found_diff = True
    print("=" * 60)
    print("REQUEST SHAPES in OLD but missing from NEW")
    print("=" * 60)
    if missing_req_ops:
        print("  Entire operations missing (all shapes lost):")
        for name in sorted(missing_req_ops):
            n = len(old_reqs[name])
            print("    - %s  (%d shapes)" % (name, n))
    if missing_shapes:
        print("  Individual shapes missing:")
        for op, shape in missing_shapes:
            keys = shape.get("keys", [])
            n = len(keys)
            preview = ", ".join(keys[:5])
            if n > 5:
                preview += ", ... +%d more" % (n - 5)
            print("    - %s  [%d vars: %s]  (seen %dx)" % (
                op, n, preview, shape.get("count", 0)))
    print()

# --- Summary ---
print("=" * 60)
print("SUMMARY")
print("=" * 60)
print("  OLD: %s" % old_label)
print("    %d operations, %d variable mappings, %d request groups" % (
    len(old_ops), sum(len(v) for v in old_vars.values()),
    sum(len(v) for v in old_reqs.values())))
print("  NEW: %s" % new_label)
print("    %d operations, %d variable mappings, %d request groups" % (
    len(new_ops), sum(len(v) for v in new_vars.values()),
    sum(len(v) for v in new_reqs.values())))
print()
if not found_diff:
    print("  No differences found - NEW is a superset of OLD.")
else:
    print("  Differences detected - review above.")
PYEOF
