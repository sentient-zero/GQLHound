# GQL Hound

A Burp Suite extension for passive discovery, triage, and fuzzing of GraphQL operations observed in proxy traffic.

Built with the **Montoya API** for bApp Store compatibility. Java 21.

## Why

GraphQL APIs funnel everything through a single endpoint. Traditional Burp workflow falls apart — you can't sort proxy history by operation, you can't see which variable shapes exist, and you lose your entire mapping when Burp restarts. GQL Hound fixes all of that.

## Features

### Passive Operation Discovery
- Monitors proxy and/or repeater traffic for GraphQL requests
- Extracts operation names and types (query, mutation, subscription) from JSON bodies
- Handles both **parameterized variables** (`"variables": {"id": "123"}`) and **inline arguments** (`user(id: "123")`)
- Detects operations in batched JSON arrays
- Annotates proxy history with `GQL:OperationName` comments for sorting/filtering
- Highlights new operations in **cyan** and batched mutations in **orange**

### Operation Cataloging
- Sortable table showing each unique operation with type, request count, variable shape count, and last seen host
- **Status tracking** with dropdown: New, In Progress, Postponed, Done, Ignored
- Click any operation to see all observed variable paths in the detail table with sample values and frequency counts

### Variable Shape Tracking
- Tracks distinct variable key signatures per operation
- Each unique combination of variable keys is a separate "shape"
- Stores the most recent original request per shape — headers, cookies, auth tokens, everything
- Lower table shows flattened dot-notation paths (e.g., `input.user.email`) with up to 5 sample values per path

### Send to Intruder
- Right-click any operation to send to Intruder with **auto-marked payload positions** on every variable value
- Select from observed variable shapes — each one sends the real captured request, not a synthetic reconstruction
- **Merged** option combines all observed variables into one request with `FUZZ` placeholders for missing fields
- Positions are marked inside JSON string quotes to keep payloads structurally valid
- Positions sorted by byte offset ascending (Burp requirement)

### Send to Repeater
- Right-click to send original captured requests to Repeater
- Batched array requests are automatically extracted to single-operation bodies
- **Merged** option available with all observed variables combined

### Inline / Parameterized Style Conversion
- Every Send to Intruder and Send to Repeater option offers three styles:
  - **Original** — send as captured
  - **as Inline** — converts parameterized `$variable` references to inline argument values in the query string
  - **as Parameterized** — converts inline arguments to a proper `variables` JSON object with `$variable` declarations
- Tests different server-side code paths: the GraphQL query parser (inline) vs. the variable coercion layer (parameterized) handle validation, type checking, and escaping differently
- Style conversion is available on individual shapes, merged requests, and variable-level sends

### Configurable Capture Sources
- Toggle checkboxes in the header: **Proxy** and **Repeater**
- Both enabled by default, toggle live without restart
- Repeater capture is useful when manually crafting and replaying GraphQL requests

### Session Persistence
- **Export** saves full state to JSON: operations, statuses, variable samples, and raw requests (base64-encoded)
- **Import** restores everything — right-click to Intruder/Repeater works immediately on imported data
- Export format is backward-compatible with the Python/Jython version of GQL Hound
- Use `gql_diff.sh` to compare two export files and find missing operations, status changes, or lost request shapes

### Right-Click on Variables
- Multi-select variable rows in the lower table
- Right-click to send only those selected variables as Intruder positions
- Extension finds the stored request whose variable keys best cover your selection
- Style conversion available here too

## Building

Requires Java 21 and Gradle 8+.

```bash
gradle wrapper --gradle-version 8.12
./gradlew jar
```

Output: `build/libs/gql-hound-2.0.1.jar`

## Installation

1. Build the JAR or download from releases
2. Burp: Extensions > Installed > Add
3. Extension type: **Java**
4. Select `gql-hound-2.0.1.jar`

No external dependencies — Gson is bundled in the fat JAR.

## Usage

### Quick Start

1. Load the extension
2. Browse the target with Burp proxying
3. Open the **GQL Hound** tab — operations populate automatically
4. Click an operation to see its variables
5. Right-click an operation to send to Intruder or Repeater

### Context Menu Structure

```
Send to Repeater >
  3 vars: productId, quantity, metadata (5x) >
    Original
    as Inline
    as Parameterized
  ---
  Merged (all 5 observed vars) >
    Original
    as Inline
    as Parameterized

Send to Intruder >
  3 vars: productId, quantity, metadata (5x) >
    Original
    as Inline
    as Parameterized
  ---
  Merged (all 5 observed vars) >
    Original
    as Inline
    as Parameterized
```

### Why Test Both Inline and Parameterized

Parameterized variables go through the GraphQL engine's variable coercion layer before reaching the resolver — types are enforced, mismatches rejected. Inline arguments are parsed by the query parser and may reach resolvers with less sanitization. This matters for:

- **SQL/NoSQL injection** — inline values may bypass type coercion that would sanitize parameterized inputs
- **Type confusion** — different parsers handle edge cases (unicode, null bytes, nested quotes) differently
- **WAF bypass** — some WAFs only inspect the `variables` object, missing inline values entirely
- **Persisted query bypass** — inline queries change the query hash on every request, potentially circumventing allowlists

### Export Comparison

```bash
./gql_diff.sh yesterday.json today.json
```

Reports missing operations, status changes, lost variable paths, and missing request shapes with a summary.

## Project Structure

```
src/main/java/io/github/sentientzero/gqlhound/
  GqlHound.java                   # BurpExtension entry point, proxy handler, unload handler
  model/
    GraphQlOperation.java         # Operation data (thread-safe atomics)
    VariableShape.java            # Variable signature + stored request reference
    OperationStatus.java          # Status enum (New, In Progress, Postponed, Done, Ignored)
    ExtractedOperation.java       # Extraction result record
    QueryStyle.java               # Style enum (Original, Inline, Parameterized)
  extraction/
    OperationExtractor.java       # JSON + regex operation extraction, batch handling, inline arg parsing
    VariableFlattener.java        # Dot-notation path flattening for nested JSON
    JsonPositionWriter.java       # Position-tracking JSON serializer for Intruder
    QueryStyleConverter.java      # Bidirectional inline <-> parameterized conversion
  store/
    OperationStore.java           # Thread-safe central store (operations, variables, request shapes)
    ExportImporter.java           # JSON export/import with base64 request encoding
  ui/
    GqlHoundTab.java              # Split-pane tab with capture source toggles
    OperationTableModel.java      # Upper table (sortable, status-editable)
    VariableTableModel.java       # Lower table (sortable)
    StatusCellEditor.java         # JComboBox cell editor for status column
    ContextMenuFactory.java       # Right-click menus with style sub-options
  intruder/
    IntruderSender.java           # Intruder send with Range-based positions, style conversion
    RepeaterSender.java           # Repeater send with batch extraction, merge, style conversion
```

## bApp Store Compliance

- **Montoya API only** (Java 21) — no legacy Extender API
- **Fat JAR** with Gson bundled — one-click install, zero external dependencies
- **Thread safety** — ConcurrentHashMap, ReadWriteLock, AtomicReference, CopyOnWriteArrayList
- **EDT compliance** — UI updates via SwingUtilities.invokeLater, no slow operations on EDT
- **Unload handler** — registered via Extension.registerUnloadingHandler()
- **No outbound requests** — passive monitoring only, no network calls from the extension
- **Background exception handling** — all handler logic wrapped in try/catch with errors to extension error stream
- **BappManifest.bmf** included with build command

## Credits

Built for manual testers who got tired of grepping JSON blobs for operation names.

---

**sentient-zero** | [GitHub](https://github.com/sentient-zero) | Your GraphQL ops have a hound now

## License

MIT
