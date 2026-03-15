# -*- coding: utf-8 -*-
"""
GQL Hound - BurpSuite Extension

Passively discovers, catalogs, and enables fuzzing of GraphQL
operations observed in proxy traffic. Tracks variable shapes,
stores original requests, and integrates with Intruder and Repeater.
Batched mutations are highlighted in orange.
"""

from burp import IBurpExtender, IHttpListener, ITab
from burp import IHttpRequestResponse, IHttpService
from javax.swing import (
    JPanel, JScrollPane, JTable, JLabel, JButton,
    JSplitPane, BorderFactory, Box, ListSelectionModel,
    JPopupMenu, JMenuItem, JMenu, SwingUtilities,
    JFileChooser, JComboBox, DefaultCellEditor
)
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel, TableRowSorter
from java.awt import BorderLayout, FlowLayout, Font
from java.awt.event import MouseAdapter
from java.lang import Integer, String
from java.util import ArrayList
from java.io import File as JavaFile
from jarray import array as jarray
from collections import OrderedDict
import json
import re
import base64
from threading import Lock


# ==================================================================
# Lightweight wrappers for imported/stored request data
# ==================================================================
class StoredHttpService(IHttpService):
    """Minimal IHttpService for deserialized requests."""
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class StoredRequestResponse(IHttpRequestResponse):
    """Minimal IHttpRequestResponse for deserialized requests."""
    def __init__(self, request_bytes, service):
        self._request = request_bytes
        self._service = service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return None

    def getComment(self):
        return None

    def getHighlight(self):
        return None

    def getHttpService(self):
        return self._service

    def setRequest(self, message):
        self._request = message

    def setResponse(self, message):
        pass

    def setComment(self, comment):
        pass

    def setHighlight(self, color):
        pass

    def setHttpService(self, service):
        self._service = service


# ==================================================================
# Position-tracking JSON serializer
# ==================================================================
class JsonWriter(object):
    """
    Serializes a Python object to JSON while recording byte offsets
    of variable values so they can be marked as Intruder positions.
    """

    def __init__(self, mark_paths=None):
        """
        Args:
            mark_paths: set of variable paths to track (e.g. {"input.name"}).
                        None means track ALL leaf values under "variables".
        """
        self._mark = mark_paths
        self._parts = []
        self._pos = 0
        self.positions = {}  # var_path -> (start, end)

    def result(self):
        return "".join(self._parts)

    def _write(self, s):
        self._parts.append(s)
        self._pos += len(s)

    def serialize(self, obj, path=""):
        if isinstance(obj, dict):
            self._write("{")
            first = True
            for key in obj:
                if not first:
                    self._write(", ")
                first = False
                self._write(json.dumps(key))
                self._write(": ")
                child = "%s.%s" % (path, key) if path else key
                self.serialize(obj[key], child)
            self._write("}")
        elif isinstance(obj, list):
            self._write("[")
            for i, item in enumerate(obj):
                if i > 0:
                    self._write(", ")
                child = "%s[%d]" % (path, i)
                self.serialize(item, child)
            self._write("]")
        else:
            # Leaf value -- check if we should mark it
            var_path = None
            if path.startswith("variables."):
                var_path = path[len("variables."):]

            should_mark = False
            if var_path is not None:
                if self._mark is None:
                    should_mark = True
                elif var_path in self._mark:
                    should_mark = True

            val_str = json.dumps(obj)
            # Detect string values by their JSON representation
            is_str = val_str.startswith('"') and val_str.endswith('"')

            if should_mark and is_str and len(val_str) > 2:
                # Mark inside quotes so Intruder replaces the value,
                # not the surrounding quotes (keeps JSON valid)
                self._write('"')
                start = self._pos
                self._write(val_str[1:-1])  # escaped content
                end = self._pos
                self._write('"')
                self.positions[var_path] = (start, end)
            elif should_mark:
                start = self._pos
                self._write(val_str)
                end = self._pos
                self.positions[var_path] = (start, end)
            else:
                self._write(val_str)


# ==================================================================
# Upper table model: unique operations
# ==================================================================
class OperationTableModel(AbstractTableModel):
    COLUMNS = [
        "#", "Operation Name", "Type", "Status",
        "Count", "Var Shapes", "Last Host",
    ]
    STATUSES = ["New", "In Progress", "Postponed", "Done", "Ignored"]

    def __init__(self):
        self._lock = Lock()
        # (name, op_type, status, count, shape_count, host)
        self._rows = []
        self._op_index = {}

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getColumnClass(self, col):
        if col in (0, 4, 5):
            return Integer
        return String

    def isCellEditable(self, row, col):
        return col == 3  # Status column

    def setValueAt(self, value, row, col):
        if col != 3:
            return
        if row >= len(self._rows):
            return
        with self._lock:
            name, op_type, _, count, shapes, host = self._rows[row]
            self._rows[row] = (name, op_type, value, count, shapes, host)
            self.fireTableCellUpdated(row, col)

    def getValueAt(self, row, col):
        if row >= len(self._rows):
            return ""
        name, op_type, status, count, shapes, host = self._rows[row]
        return [row + 1, name, op_type, status, count, shapes, host][col]

    def get_op_name(self, row):
        if 0 <= row < len(self._rows):
            return self._rows[row][0]
        return None

    def get_status(self, row):
        if 0 <= row < len(self._rows):
            return self._rows[row][2]
        return "New"

    def track(self, op_name, op_type, host, shape_count):
        with self._lock:
            if op_name in self._op_index:
                idx = self._op_index[op_name]
                n, t, status, count, _, _ = self._rows[idx]
                self._rows[idx] = (
                    n, t, status, count + 1, shape_count, host
                )
                self.fireTableRowsUpdated(idx, idx)
                return False
            else:
                idx = len(self._rows)
                self._op_index[op_name] = idx
                self._rows.append(
                    (op_name, op_type, "New", 1, shape_count, host)
                )
                self.fireTableRowsInserted(idx, idx)
                return True

    def update_shape_count(self, op_name, shape_count):
        with self._lock:
            if op_name in self._op_index:
                idx = self._op_index[op_name]
                n, t, status, count, _, host = self._rows[idx]
                self._rows[idx] = (n, t, status, count, shape_count, host)
                self.fireTableRowsUpdated(idx, idx)

    def clear(self):
        with self._lock:
            count = len(self._rows)
            self._rows = []
            self._op_index = {}
            if count > 0:
                self.fireTableRowsDeleted(0, count - 1)


# ==================================================================
# Lower table model: variable paths for selected operation
# ==================================================================
class VariableTableModel(AbstractTableModel):
    COLUMNS = ["Variable Path", "Sample Values", "Times Seen"]

    def __init__(self):
        self._rows = []

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getColumnClass(self, col):
        if col == 2:
            return Integer
        return String

    def getValueAt(self, row, col):
        if row >= len(self._rows):
            return ""
        return self._rows[row][col]

    def get_path(self, row):
        if 0 <= row < len(self._rows):
            return self._rows[row][0]
        return None

    def load(self, rows):
        self._rows = rows
        self.fireTableDataChanged()


# ==================================================================
# Variable store: sample values per operation per path
# ==================================================================
MAX_SAMPLES = 5


class VariableStore(object):

    def __init__(self):
        self._lock = Lock()
        self._data = {}

    def record(self, op_name, variables):
        if not variables or not isinstance(variables, dict):
            return
        flat = self._flatten(variables)
        with self._lock:
            op_store = self._data.setdefault(op_name, {})
            for path, value in flat:
                entry = op_store.setdefault(
                    path, {"count": 0, "samples": set()}
                )
                entry["count"] += 1
                if len(entry["samples"]) < MAX_SAMPLES:
                    entry["samples"].add(self._truncate(value))

    def get_rows(self, op_name):
        with self._lock:
            op_store = self._data.get(op_name, {})
            rows = []
            for path in sorted(op_store):
                e = op_store[path]
                samples = " | ".join(sorted(e["samples"]))
                rows.append((path, samples, e["count"]))
            return rows

    def get_all_paths(self, op_name):
        with self._lock:
            return set(self._data.get(op_name, {}).keys())

    def clear(self):
        with self._lock:
            self._data.clear()

    def to_dict(self):
        """Serialize to a JSON-safe dict."""
        with self._lock:
            out = {}
            for op_name, op_store in self._data.items():
                out[op_name] = {}
                for path, entry in op_store.items():
                    out[op_name][path] = {
                        "count": entry["count"],
                        "samples": sorted(entry["samples"]),
                    }
            return out

    def from_dict(self, data):
        """Restore from a deserialized dict."""
        with self._lock:
            self._data.clear()
            for op_name, paths in data.items():
                op_store = {}
                for path, entry in paths.items():
                    op_store[path] = {
                        "count": entry["count"],
                        "samples": set(entry["samples"]),
                    }
                self._data[op_name] = op_store

    @staticmethod
    def _flatten(obj, prefix=""):
        items = []
        if isinstance(obj, dict):
            for key, val in obj.items():
                p = "%s.%s" % (prefix, key) if prefix else key
                if isinstance(val, (dict, list)):
                    items.extend(VariableStore._flatten(val, p))
                else:
                    items.append((p, val))
        elif isinstance(obj, list):
            for i, val in enumerate(obj):
                p = "%s[%d]" % (prefix, i) if prefix else "[%d]" % i
                if isinstance(val, (dict, list)):
                    items.extend(VariableStore._flatten(val, p))
                else:
                    items.append((p, val))
        return items

    @staticmethod
    def _truncate(value, max_len=60):
        s = str(value) if value is not None else "null"
        return s[:max_len - 3] + "..." if len(s) > max_len else s


# ==================================================================
# Request store: keeps original messageInfo per (op, var_signature)
# ==================================================================
class RequestStore(object):
    """
    Stores the most recent messageInfo for each unique combination of
    operation name and variable key signature (frozenset of var paths).
    """

    def __init__(self):
        self._lock = Lock()
        # op_name -> { sig: {"info": messageInfo, "keys": sorted_keys,
        #                     "count": N} }
        self._data = {}

    def store(self, op_name, variables, messageInfo):
        if not variables or not isinstance(variables, dict):
            sig = frozenset()
            keys = []
        else:
            flat_keys = [
                p for p, _ in VariableStore._flatten(variables)
            ]
            sig = frozenset(flat_keys)
            keys = sorted(flat_keys)

        with self._lock:
            op_store = self._data.setdefault(op_name, OrderedDict())
            if sig in op_store:
                op_store[sig]["info"] = messageInfo
                op_store[sig]["count"] += 1
            else:
                op_store[sig] = {
                    "info": messageInfo,
                    "keys": keys,
                    "count": 1,
                }

    def get_shapes(self, op_name):
        """
        Return list of dicts describing each variable shape:
        [{"sig": frozenset, "keys": [...], "count": N, "info": msgInfo}]
        Sorted by number of keys descending (richest shapes first).
        """
        with self._lock:
            op_store = self._data.get(op_name, {})
            shapes = []
            for sig, entry in op_store.items():
                shapes.append({
                    "sig": sig,
                    "keys": entry["keys"],
                    "count": entry["count"],
                    "info": entry["info"],
                })
            shapes.sort(key=lambda s: len(s["keys"]), reverse=True)
            return shapes

    def shape_count(self, op_name):
        with self._lock:
            return len(self._data.get(op_name, {}))

    def get_best_request_for_paths(self, op_name, paths):
        """
        Find the stored request whose variable keys best cover the
        requested paths. Returns (messageInfo, covered_paths) or None.
        """
        target = set(paths)
        with self._lock:
            op_store = self._data.get(op_name, {})
            best = None
            best_overlap = -1
            for sig, entry in op_store.items():
                overlap = len(target & sig)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best = entry
            if best:
                covered = target & frozenset(best["keys"])
                return best["info"], covered
            return None

    def build_merged_request(self, op_name, helpers):
        """
        Take the richest stored request and merge in any variable keys
        from other shapes, using placeholder values. Returns
        (messageInfo_base, merged_variables_dict) or None.
        """
        with self._lock:
            op_store = self._data.get(op_name, {})
            if not op_store:
                return None

            # Start with the shape that has the most keys
            shapes = sorted(
                op_store.values(),
                key=lambda e: len(e["keys"]),
                reverse=True,
            )
            base = shapes[0]
            base_info = base["info"]

        # Parse the base request body to get its variables
        req = base_info.getRequest()
        analyzed = helpers.analyzeRequest(req)
        body = helpers.bytesToString(req[analyzed.getBodyOffset():])
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return None

        # If batched array, extract the matching operation
        if isinstance(data, list):
            target = None
            for item in data:
                if not isinstance(item, dict):
                    continue
                item_name = item.get("operationName")
                if not item_name:
                    q = item.get("query", "")
                    m = re.search(
                        r'(?:query|mutation|subscription)\s+(\w+)', q
                    )
                    if m:
                        item_name = m.group(1)
                if item_name == op_name:
                    target = item
                    break
            if target is None:
                return None
            data = target

        variables = data.get("variables")
        if not variables or not isinstance(variables, dict):
            variables = OrderedDict()

        # Collect all keys from all shapes and add missing ones
        all_keys = set()
        for entry in shapes:
            all_keys.update(entry["keys"])

        existing_keys = set(
            p for p, _ in VariableStore._flatten(variables)
        )
        missing = all_keys - existing_keys

        for path in sorted(missing):
            self._inject_path(variables, path, "FUZZ")

        data["variables"] = variables
        return base_info, data

    @staticmethod
    def _inject_path(obj, path, value):
        """Inject a dotted path into a nested dict, creating parents."""
        parts = []
        remainder = path
        while remainder:
            m = re.match(r'^([^.\[]+)', remainder)
            if m:
                parts.append(m.group(1))
                remainder = remainder[m.end():]
            m2 = re.match(r'^\[(\d+)\]', remainder)
            if m2:
                parts.append(int(m2.group(1)))
                remainder = remainder[m2.end():]
            if remainder.startswith("."):
                remainder = remainder[1:]
            if not m and not m2:
                break

        current = obj
        for i, part in enumerate(parts[:-1]):
            next_part = parts[i + 1]
            if isinstance(part, int):
                while len(current) <= part:
                    current.append(
                        OrderedDict() if isinstance(next_part, str)
                        else []
                    )
                current = current[part]
            else:
                if part not in current:
                    current[part] = (
                        OrderedDict() if isinstance(next_part, str)
                        else []
                    )
                current = current[part]

        last = parts[-1]
        if isinstance(last, int):
            while len(current) <= last:
                current.append(None)
            current[last] = value
        else:
            current[last] = value

    def clear(self):
        with self._lock:
            self._data.clear()

    def to_dict(self, helpers):
        """
        Serialize to a JSON-safe dict. Request bytes are base64-encoded.
        """
        with self._lock:
            out = {}
            for op_name, op_store in self._data.items():
                shapes_list = []
                for sig, entry in op_store.items():
                    info = entry["info"]
                    service = info.getHttpService()
                    req_bytes = info.getRequest()
                    req_b64 = base64.b64encode(
                        helpers.bytesToString(req_bytes)
                    )
                    shapes_list.append({
                        "keys": entry["keys"],
                        "count": entry["count"],
                        "host": service.getHost(),
                        "port": service.getPort(),
                        "protocol": service.getProtocol(),
                        "request_b64": req_b64,
                    })
                out[op_name] = shapes_list
            return out

    def from_dict(self, data, helpers):
        """
        Restore from a deserialized dict. Recreates lightweight
        IHttpRequestResponse wrappers for each stored shape.
        """
        with self._lock:
            self._data.clear()
            for op_name, shapes_list in data.items():
                op_store = OrderedDict()
                for shape in shapes_list:
                    keys = shape["keys"]
                    sig = frozenset(keys)

                    req_str = base64.b64decode(shape["request_b64"])
                    req_bytes = helpers.stringToBytes(req_str)
                    service = StoredHttpService(
                        shape["host"],
                        shape["port"],
                        shape["protocol"],
                    )
                    info = StoredRequestResponse(req_bytes, service)

                    op_store[sig] = {
                        "info": info,
                        "keys": keys,
                        "count": shape["count"],
                    }
                self._data[op_name] = op_store


# ==================================================================
# Swing helpers
# ==================================================================
def _shape_label(keys, count):
    """Build a readable submenu label for a variable shape."""
    n = len(keys)
    if n == 0:
        return "no variables (%dx)" % count
    preview = keys[:4]
    label = ", ".join(preview)
    if n > 4:
        label += ", ... +%d more" % (n - 4)
    return "%d vars: %s (%dx)" % (n, label, count)


# ==================================================================
# Extension entry point
# ==================================================================
class BurpExtender(IBurpExtender, IHttpListener, ITab):
    EXTENSION_NAME = "GQL Hound"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerHttpListener(self)

        self._op_model = OperationTableModel()
        self._var_model = VariableTableModel()
        self._var_store = VariableStore()
        self._req_store = RequestStore()

        self._selected_op = None  # currently selected operation name

        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("[+] %s loaded." % self.EXTENSION_NAME)

    # -- ITab --------------------------------------------------

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._panel

    # -- UI ----------------------------------------------------

    def _build_ui(self):
        self._panel = JPanel(BorderLayout(0, 6))
        self._panel.setBorder(
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        )

        # -- Header
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("Unique GraphQL Operations")
        title.setFont(Font("Dialog", Font.BOLD, 14))
        header.add(title)
        clear_btn = JButton("Clear", actionPerformed=self._on_clear)
        header.add(Box.createHorizontalStrut(12))
        header.add(clear_btn)

        export_btn = JButton("Export", actionPerformed=self._on_export)
        header.add(Box.createHorizontalStrut(8))
        header.add(export_btn)

        import_btn = JButton("Import", actionPerformed=self._on_import)
        header.add(Box.createHorizontalStrut(8))
        header.add(import_btn)

        self._panel.add(header, BorderLayout.NORTH)

        # -- Upper table: operations (sortable)
        self._op_table = JTable(self._op_model)
        self._op_table.setSelectionMode(
            ListSelectionModel.SINGLE_SELECTION
        )
        self._op_table.setAutoCreateRowSorter(True)
        cm = self._op_table.getColumnModel()
        cm.getColumn(0).setMaxWidth(50)   # #
        cm.getColumn(2).setMaxWidth(100)  # Type
        cm.getColumn(4).setMaxWidth(80)   # Count
        cm.getColumn(5).setMaxWidth(90)   # Var Shapes

        # Status dropdown editor
        status_combo = JComboBox(OperationTableModel.STATUSES)
        cm.getColumn(3).setCellEditor(DefaultCellEditor(status_combo))
        cm.getColumn(3).setMaxWidth(110)

        op_scroll = JScrollPane(self._op_table)

        # Selection listener
        self._op_table.getSelectionModel().addListSelectionListener(
            _OpSelectionListener(self)
        )
        # Right-click on operations
        self._op_table.addMouseListener(_OpMouseListener(self))

        # -- Lower table: variables (sortable)
        var_panel = JPanel(BorderLayout(0, 4))
        var_label = JLabel("Variables for selected operation:")
        var_label.setFont(Font("Dialog", Font.BOLD, 12))
        var_panel.add(var_label, BorderLayout.NORTH)

        self._var_table = JTable(self._var_model)
        self._var_table.setAutoCreateRowSorter(True)
        self._var_table.getColumnModel().getColumn(2).setMaxWidth(100)
        var_scroll = JScrollPane(self._var_table)
        var_panel.add(var_scroll, BorderLayout.CENTER)

        # Right-click on variables
        self._var_table.addMouseListener(_VarMouseListener(self))

        # -- Split pane
        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT, op_scroll, var_panel
        )
        split.setResizeWeight(0.5)
        split.setDividerLocation(250)
        self._panel.add(split, BorderLayout.CENTER)

    def _on_clear(self, event):
        self._op_model.clear()
        self._var_store.clear()
        self._var_model.load([])
        self._req_store.clear()
        self._selected_op = None

    def _on_export(self, event):
        """Export all state to a JSON file."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Export GQL Hound Data")
        chooser.setFileFilter(
            FileNameExtensionFilter("JSON files", ["json"])
        )
        chooser.setSelectedFile(
            JavaFile("gql_hound_export.json")
        )
        result = chooser.showSaveDialog(self._panel)
        if result != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.endswith(".json"):
            path += ".json"

        try:
            # Serialize operation table rows
            ops = []
            for row in self._op_model._rows:
                name, op_type, status, count, shapes, host = row
                ops.append({
                    "name": name,
                    "type": op_type,
                    "status": status,
                    "count": count,
                    "host": host,
                })

            state = {
                "version": 1,
                "operations": ops,
                "variables": self._var_store.to_dict(),
                "requests": self._req_store.to_dict(self._helpers),
            }

            f = open(path, "w")
            try:
                json.dump(state, f, indent=2)
            finally:
                f.close()

            n_ops = len(ops)
            n_shapes = sum(
                len(v) for v in state["requests"].values()
            )
            self._callbacks.printOutput(
                "[+] Exported %d operations, %d request shapes to %s"
                % (n_ops, n_shapes, path)
            )
        except Exception as ex:
            self._callbacks.printError(
                "[!] Export failed: %s" % str(ex)
            )

    def _on_import(self, event):
        """Import state from a JSON file, merging with existing data."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Import GQL Hound Data")
        chooser.setFileFilter(
            FileNameExtensionFilter("JSON files", ["json"])
        )
        result = chooser.showOpenDialog(self._panel)
        if result != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()

        try:
            f = open(path, "r")
            try:
                state = json.load(f)
            finally:
                f.close()

            version = state.get("version", 0)
            if version != 1:
                self._callbacks.printError(
                    "[!] Unsupported file version: %s" % version
                )
                return

            # Clear current state
            self._op_model.clear()
            self._var_store.clear()
            self._var_model.load([])
            self._req_store.clear()
            self._selected_op = None

            # Restore variable store
            self._var_store.from_dict(state.get("variables", {}))

            # Restore request store
            self._req_store.from_dict(
                state.get("requests", {}), self._helpers
            )

            # Restore operation table
            for op in state.get("operations", []):
                name = op["name"]
                op_type = op["type"]
                status = op.get("status", "New")
                count = op["count"]
                host = op["host"]
                sc = self._req_store.shape_count(name)

                # Add to model and override count + status
                self._op_model.track(name, op_type, host, sc)
                idx = self._op_model._op_index.get(name)
                if idx is not None:
                    self._op_model._rows[idx] = (
                        name, op_type, status, count, sc, host
                    )
                    self._op_model.fireTableRowsUpdated(idx, idx)

            n_ops = len(state.get("operations", []))
            n_shapes = sum(
                len(v) for v in state.get("requests", {}).values()
            )
            self._callbacks.printOutput(
                "[+] Imported %d operations, %d request shapes from %s"
                % (n_ops, n_shapes, path)
            )
        except Exception as ex:
            self._callbacks.printError(
                "[!] Import failed: %s" % str(ex)
            )

    # -- IHttpListener ------------------------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self._callbacks.TOOL_PROXY:
            return
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo)
        body_offset = analyzed.getBodyOffset()
        body = self._helpers.bytesToString(
            request[body_offset:]
        ).strip()

        if not body:
            return

        operations = self._extract_operations(body)
        if not operations:
            return

        host = (
            analyzed.getUrl().getHost()
            if analyzed.getUrl() else "unknown"
        )

        is_batched = len(operations) > 1
        mut_count = sum(1 for _, t, _ in operations if t == "mutation")
        has_batched_muts = is_batched and mut_count > 1

        existing = messageInfo.getComment() or ""
        tags = []
        any_new = False

        for op_name, op_type, variables in operations:
            tag = "GQL:%s" % op_name
            if tag not in existing:
                tags.append(tag)

            # Record variable samples
            self._var_store.record(op_name, variables)

            # Store original request by variable shape
            self._req_store.store(op_name, variables, messageInfo)
            sc = self._req_store.shape_count(op_name)

            is_new = self._op_model.track(
                op_name, op_type, host, sc
            )
            if not is_new:
                self._op_model.update_shape_count(op_name, sc)
            if is_new:
                any_new = True
                self._callbacks.printOutput(
                    "[*] New %s: %s  (%s)" % (op_type, op_name, host)
                )

        if tags:
            new_part = " | ".join(tags)
            comment = (
                "%s | %s" % (existing, new_part) if existing
                else new_part
            )
            messageInfo.setComment(comment)

        if has_batched_muts:
            messageInfo.setHighlight("orange")
            self._callbacks.printOutput(
                "[!] Batched mutations (%d): %s  (%s)"
                % (
                    mut_count,
                    ", ".join(
                        n for n, t, _ in operations
                        if t == "mutation"
                    ),
                    host,
                )
            )
        elif any_new:
            messageInfo.setHighlight("cyan")

    # -- Send helpers -------------------------------------------

    def _send_to_repeater(self, messageInfo, tab_name):
        req = self._extract_single_op_request(messageInfo, tab_name)
        service = messageInfo.getHttpService()
        self._callbacks.sendToRepeater(
            service.getHost(),
            service.getPort(),
            service.getProtocol() == "https",
            req,
            tab_name,
        )
        self._callbacks.printOutput(
            "[>] Sent to Repeater: %s" % tab_name
        )

    def _extract_single_op_request(self, messageInfo, op_name):
        """
        If the request body is a batched array, extract the dict
        matching op_name and rebuild as a single-operation request.
        Returns the original request bytes if not batched.
        """
        req = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo)
        headers = list(analyzed.getHeaders())
        body_str = self._helpers.bytesToString(
            req[analyzed.getBodyOffset():]
        )

        try:
            data = json.loads(body_str)
        except (ValueError, TypeError):
            return req

        if not isinstance(data, list):
            return req

        target = None
        for item in data:
            if not isinstance(item, dict):
                continue
            item_name = item.get("operationName")
            if not item_name:
                q = item.get("query", "")
                m = re.search(
                    r'(?:query|mutation|subscription)\s+(\w+)', q
                )
                if m:
                    item_name = m.group(1)
            if item_name == op_name:
                target = item
                break

        if target is None:
            return req

        self._callbacks.printOutput(
            "[d] Extracted '%s' from batch for Repeater" % op_name
        )
        new_body = json.dumps(target)
        return self._helpers.buildHttpMessage(
            headers, self._helpers.stringToBytes(new_body)
        )

    def _send_to_intruder(self, messageInfo, op_name, mark_paths=None):
        """
        Re-serialize the request body, calculate byte offsets for
        variable values, and send to Intruder with marked positions.
        If the body is a batched array, extract the matching operation.
        """
        req = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo)
        headers = list(analyzed.getHeaders())
        body_bytes = req[analyzed.getBodyOffset():]
        body_str = self._helpers.bytesToString(body_bytes)

        try:
            data = json.loads(body_str)
        except (ValueError, TypeError) as ex:
            self._callbacks.printError(
                "[!] Intruder: failed to parse body: %s" % str(ex)
            )
            return

        # If batched array, extract the dict matching this op_name
        if isinstance(data, list):
            target = None
            for item in data:
                if not isinstance(item, dict):
                    continue
                item_name = item.get("operationName")
                if not item_name:
                    q = item.get("query", "")
                    m = re.search(
                        r'(?:query|mutation|subscription)\s+(\w+)', q
                    )
                    if m:
                        item_name = m.group(1)
                if item_name == op_name:
                    target = item
                    break
            if target is None:
                self._callbacks.printError(
                    "[!] Intruder: could not find op '%s' in batch"
                    % op_name
                )
                return
            data = target
            self._callbacks.printOutput(
                "[d] Extracted '%s' from batched request" % op_name
            )
        elif not isinstance(data, dict):
            self._callbacks.printError(
                "[!] Intruder: unexpected body type: %s"
                % type(data).__name__
            )
            return

        writer = JsonWriter(mark_paths=mark_paths)
        writer.serialize(data)
        new_body = writer.result()

        self._callbacks.printOutput(
            "[d] JsonWriter found %d position(s): %s"
            % (len(writer.positions),
               ", ".join(
                   "%s@[%d:%d]" % (p, s, e)
                   for p, (s, e) in sorted(writer.positions.items())
               ))
        )

        new_body_bytes = self._helpers.stringToBytes(new_body)
        new_req = self._helpers.buildHttpMessage(headers, new_body_bytes)

        # Calculate body offset in the rebuilt request
        new_analyzed = self._helpers.analyzeRequest(messageInfo.getHttpService(), new_req)
        new_offset = new_analyzed.getBodyOffset()

        self._callbacks.printOutput(
            "[d] Body offset in new request: %d" % new_offset
        )

        # Build Java ArrayList of int[] offset pairs, sorted by byte offset
        java_offsets = ArrayList()
        sorted_positions = sorted(
            writer.positions.items(), key=lambda item: item[1][0]
        )
        for path, (start, end) in sorted_positions:
            abs_start = new_offset + start
            abs_end = new_offset + end
            java_offsets.add(jarray([abs_start, abs_end], 'i'))
            self._callbacks.printOutput(
                "[d]   Position: %s -> [%d, %d]"
                % (path, abs_start, abs_end)
            )

        service = messageInfo.getHttpService()
        self._callbacks.sendToIntruder(
            service.getHost(),
            service.getPort(),
            service.getProtocol() == "https",
            new_req,
            java_offsets if java_offsets.size() > 0 else None,
        )

        self._callbacks.printOutput(
            "[>] Sent to Intruder with %d position(s)"
            % java_offsets.size()
        )

    def _send_merged_to_intruder(self, op_name):
        """Build a merged request with all observed variables."""
        result = self._req_store.build_merged_request(
            op_name, self._helpers
        )
        if not result:
            self._callbacks.printError(
                "[!] No stored requests for %s" % op_name
            )
            return

        base_info, merged_data = result
        req = base_info.getRequest()
        analyzed = self._helpers.analyzeRequest(base_info)
        headers = list(analyzed.getHeaders())

        writer = JsonWriter(mark_paths=None)
        writer.serialize(merged_data)
        new_body = writer.result()

        new_body_bytes = self._helpers.stringToBytes(new_body)
        new_req = self._helpers.buildHttpMessage(headers, new_body_bytes)
        new_offset = self._helpers.analyzeRequest(
            base_info.getHttpService(), new_req
        ).getBodyOffset()

        java_offsets = ArrayList()
        sorted_positions = sorted(
            writer.positions.items(), key=lambda item: item[1][0]
        )
        for path, (start, end) in sorted_positions:
            java_offsets.add(
                jarray([new_offset + start, new_offset + end], 'i')
            )

        service = base_info.getHttpService()
        self._callbacks.sendToIntruder(
            service.getHost(),
            service.getPort(),
            service.getProtocol() == "https",
            new_req,
            java_offsets if java_offsets.size() > 0 else None,
        )

        self._callbacks.printOutput(
            "[>] Sent MERGED to Intruder with %d position(s)"
            % java_offsets.size()
        )

    # -- Extraction ---------------------------------------------

    def _extract_operations(self, body):
        try:
            data = json.loads(body)
            if isinstance(data, list):
                results = []
                for item in data:
                    if isinstance(item, dict):
                        parsed = self._op_from_dict(item)
                        if parsed:
                            results.append(parsed)
                return results if results else None
            elif isinstance(data, dict):
                parsed = self._op_from_dict(data)
                return [parsed] if parsed else None
        except (ValueError, TypeError):
            pass

        matches = re.findall(
            r'(query|mutation|subscription)\s+(\w+)', body
        )
        if matches:
            return [
                (name, op_type, None)
                for op_type, name in matches
            ]
        return None

    @staticmethod
    def _op_from_dict(d):
        query = d.get("query", "")
        name = d.get("operationName")
        variables = d.get("variables")
        op_type = "query"

        m = re.search(
            r'(query|mutation|subscription)\s+(\w+)', query
        )
        if m:
            op_type = m.group(1)
            if not name:
                name = m.group(2)

        if not name:
            return None
        return (
            name,
            op_type,
            variables if isinstance(variables, dict) else None,
        )


# ==================================================================
# Swing listeners (defined outside BurpExtender for Jython compat)
# ==================================================================
class _OpSelectionListener(ListSelectionListener):
    def __init__(self, ext):
        self._ext = ext

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        table = self._ext._op_table
        view_row = table.getSelectedRow()
        if view_row < 0:
            self._ext._selected_op = None
            self._ext._var_model.load([])
            return
        model_row = table.convertRowIndexToModel(view_row)
        op_name = self._ext._op_model.get_op_name(model_row)
        self._ext._selected_op = op_name
        if op_name:
            rows = self._ext._var_store.get_rows(op_name)
            self._ext._var_model.load(rows)
        else:
            self._ext._var_model.load([])


class _OpMouseListener(MouseAdapter):
    def __init__(self, ext):
        self._ext = ext

    def mousePressed(self, event):
        self._handle(event)

    def mouseReleased(self, event):
        self._handle(event)

    def _handle(self, event):
        if not event.isPopupTrigger():
            return
        table = self._ext._op_table
        row = table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        table.setRowSelectionInterval(row, row)
        model_row = table.convertRowIndexToModel(row)
        op_name = self._ext._op_model.get_op_name(model_row)
        if not op_name:
            return

        shapes = self._ext._req_store.get_shapes(op_name)
        if not shapes:
            return

        menu = JPopupMenu()

        # -- Send to Repeater submenu
        rep_menu = JMenu("Send to Repeater")
        for shape in shapes:
            label = _shape_label(shape["keys"], shape["count"])
            info = shape["info"]
            item = JMenuItem(label)
            item.addActionListener(
                _action(
                    lambda e, i=info, n=op_name:
                        self._ext._send_to_repeater(i, n)
                )
            )
            rep_menu.add(item)
        menu.add(rep_menu)

        # -- Send to Intruder submenu
        int_menu = JMenu("Send to Intruder")
        for shape in shapes:
            label = _shape_label(shape["keys"], shape["count"])
            info = shape["info"]
            item = JMenuItem(label)
            item.addActionListener(
                _action(
                    lambda e, i=info, n=op_name:
                        self._ext._send_to_intruder(i, n, mark_paths=None)
                )
            )
            int_menu.add(item)

        if len(shapes) > 1:
            int_menu.addSeparator()
            merge_item = JMenuItem(
                "Merged (all %d observed vars)"
                % len(self._ext._var_store.get_all_paths(op_name))
            )
            merge_item.addActionListener(
                _action(
                    lambda e, n=op_name:
                        self._ext._send_merged_to_intruder(n)
                )
            )
            int_menu.add(merge_item)
        menu.add(int_menu)

        menu.show(event.getComponent(), event.getX(), event.getY())


class _VarMouseListener(MouseAdapter):
    def __init__(self, ext):
        self._ext = ext

    def mousePressed(self, event):
        self._handle(event)

    def mouseReleased(self, event):
        self._handle(event)

    def _handle(self, event):
        if not event.isPopupTrigger():
            return

        table = self._ext._var_table
        selected = table.getSelectedRows()
        if not selected or len(selected) == 0:
            return

        op_name = self._ext._selected_op
        if not op_name:
            return

        # Collect selected variable paths
        paths = set()
        for view_row in selected:
            model_row = table.convertRowIndexToModel(view_row)
            path = self._ext._var_model.get_path(model_row)
            if path:
                paths.add(path)

        if not paths:
            return

        menu = JPopupMenu()

        # Find best matching stored request for these paths
        result = self._ext._req_store.get_best_request_for_paths(
            op_name, paths
        )
        if result:
            info, covered = result
            n_covered = len(covered)
            n_total = len(paths)

            int_label = "Send %d selected var(s) to Intruder" % n_total
            if n_covered < n_total:
                int_label += " (%d covered)" % n_covered
            int_item = JMenuItem(int_label)
            int_item.addActionListener(
                _action(
                    lambda e, i=info, p=paths, n=op_name:
                        self._ext._send_to_intruder(i, n, mark_paths=p)
                )
            )
            menu.add(int_item)

            rep_item = JMenuItem(
                "Send to Repeater (%d var request)" % n_covered
            )
            rep_item.addActionListener(
                _action(
                    lambda e, i=info, n=op_name:
                        self._ext._send_to_repeater(i, n)
                )
            )
            menu.add(rep_item)

        menu.show(event.getComponent(), event.getX(), event.getY())


# Jython-safe action listener wrapper
def _action(callback):
    from java.awt.event import ActionListener

    class _AL(ActionListener):
        def actionPerformed(self, event):
            callback(event)

    return _AL()
