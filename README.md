# GQL Hound

A Burp Suite extension for passive discovery, triage, and fuzzing of GraphQL operations observed in proxy traffic.

## The Problem

GraphQL APIs funnel everything through a single endpoint, making traditional Burp workflow (browse, review proxy history, send to Intruder) painful. You can't sort by operation, you can't see which variable shapes exist, and you lose everything when Burp restarts.

## What This Does

- **Passively monitors** proxy traffic and extracts GraphQL operation names and types (query/mutation/subscription)
- **Catalogs unique operations** in a sortable table with request count, variable shapes observed, and host
- **Tracks distinct variable signatures** per operation with sample values, so you know exactly what to fuzz
- **Stores original captured requests** grouped by operation name and variable shape
- **Annotates proxy history** with `GQL:OperationName` comments for filtering/sorting
- **Highlights** new operations (cyan) and batched mutations (orange) in proxy history
- **Right-click to Intruder** with auto-marked payload positions on all variable values
- **Right-click to Repeater** with the original request context (headers, cookies, auth)
- **Handles batched requests** -- extracts individual operations from JSON arrays before sending
- **Status tracking** -- mark operations as New / In Progress / Postponed / Done / Ignored via dropdown
- **Export/Import** full state to JSON for session persistence across Burp restarts or team sharing

## Installation

1. Ensure Jython is configured in Burp: Extender > Options > Python Environment
2. Extender > Extensions > Add
3. Extension type: **Python**
4. Select `gql_hound.py`

## Usage

### Discovery

Browse the target application with Burp proxying. The extension passively captures every GraphQL operation and populates the **GQL Hound** tab.

Click any operation in the upper table to see all observed variable paths in the lower table, with sample values and frequency counts.

### Triage

Use the **Status** dropdown on each operation to track testing progress. Sort by the Status column to focus your work.

### Fuzzing

**Right-click an operation** to see submenus listing each observed variable shape (e.g., "3 vars: name, email, role (12x)"):

- **Send to Repeater** -- sends the original captured request as-is
- **Send to Intruder** -- re-serializes the body and auto-marks every variable value as an Intruder position
- **Merged** -- combines all observed variables into one request with `FUZZ` placeholders for parameter pollution testing

**Right-click variable rows** in the lower table to send only selected variables as Intruder positions.

### Session Persistence

- **Export** -- saves operations, variables, statuses, and full raw requests (base64) to JSON
- **Import** -- restores everything including right-click-to-Intruder on imported requests

Use `gql_diff.sh` to compare two export files and find missing operations, status changes, or lost request shapes.

## Repo Contents

```
gql_hound.py   # Burp Suite extension
gql_diff.sh    # Export comparison script
```

## Known Jython Gotchas

- **Non-ASCII in source**: Jython 2.7 requires `# -*- coding: utf-8 -*-` header. Keep comments ASCII-only.
- **List to Java List**: `sendToIntruder()` needs `java.util.ArrayList`, not a Python list, for offset pairs.
- **`analyzeRequest()` body offset**: Use the two-arg overload with `IHttpService`. The single-arg version miscalculates without service context.
- **Intruder position order**: Positions must be in ascending byte offset order. Sorting by path name breaks when `columns[10]` sorts before `columns[1]`.
- **Batched JSON arrays**: Any method touching request bodies must check for `isinstance(data, list)` and extract the target operation before calling dict methods.

## Credits

Built for manual testers who got tired of grepping JSON blobs for operation names.

---

**sentient-zero** | [GitHub](https://github.com/sentient-zero) | Your GraphQL ops have a hound now

## License

MIT
