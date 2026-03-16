package io.github.sentientzero.gqlhound.store;

import io.github.sentientzero.gqlhound.extraction.VariableFlattener;
import io.github.sentientzero.gqlhound.model.*;
import com.google.gson.JsonObject;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe central store for all extension state:
 * - Operations (name, type, status, counts)
 * - Variable samples per operation per path
 * - Request shapes (original requests grouped by variable signature)
 */
public class OperationStore {

    private static final int MAX_SAMPLES = 5;

    // Operations: ordered list + lookup index
    private final CopyOnWriteArrayList<GraphQlOperation> operations = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, GraphQlOperation> opIndex = new ConcurrentHashMap<>();

    // Variables: opName -> { path -> { count, samples } }
    private final ConcurrentHashMap<String, Map<String, VarEntry>> variableStore = new ConcurrentHashMap<>();
    private final ReadWriteLock varLock = new ReentrantReadWriteLock();

    // Request shapes: opName -> list of VariableShape
    private final ConcurrentHashMap<String, List<VariableShape>> requestStore = new ConcurrentHashMap<>();
    private final ReadWriteLock reqLock = new ReentrantReadWriteLock();

    // Callback for UI updates
    private volatile OperationStoreListener listener;
    private volatile boolean suppressEvents = false;

    /**
     * Lightweight holder for variable sample data.
     */
    public static class VarEntry {
        public int count;
        public final Set<String> samples = new LinkedHashSet<>();

        public VarEntry() {
            this.count = 0;
        }
    }

    public void setListener(OperationStoreListener listener) {
        this.listener = listener;
    }

    public void setSuppressEvents(boolean suppress) {
        this.suppressEvents = suppress;
    }

    // ---- Operations ----

    /**
     * Track an operation. Returns true if newly seen.
     */
    public boolean trackOperation(String opName, String opType, String host) {
        GraphQlOperation existing = opIndex.get(opName);
        if (existing != null) {
            existing.incrementRequestCount();
            existing.setLastHost(host);
            int idx = operations.indexOf(existing);
            if (listener != null && !suppressEvents && idx >= 0) {
                listener.operationUpdated(idx);
            }
            return false;
        }

        GraphQlOperation op = new GraphQlOperation(opName, opType, host);
        opIndex.put(opName, op);
        operations.add(op);
        int idx = operations.size() - 1;
        if (listener != null && !suppressEvents) {
            listener.operationAdded(idx);
        }
        return true;
    }

    public GraphQlOperation getOperation(int index) {
        if (index >= 0 && index < operations.size()) {
            return operations.get(index);
        }
        return null;
    }

    public GraphQlOperation getOperationByName(String name) {
        return opIndex.get(name);
    }

    public int getOperationCount() {
        return operations.size();
    }

    public List<GraphQlOperation> getOperations() {
        return Collections.unmodifiableList(operations);
    }

    public void updateShapeCount(String opName) {
        GraphQlOperation op = opIndex.get(opName);
        if (op != null) {
            op.setShapeCount(getShapeCount(opName));
            int idx = operations.indexOf(op);
            if (listener != null && !suppressEvents && idx >= 0) {
                listener.operationUpdated(idx);
            }
        }
    }

    // ---- Variables ----

    /**
     * Record variable paths and sample values for an operation.
     */
    public void recordVariables(String opName, JsonObject variables) {
        if (variables == null) return;

        List<Map.Entry<String, String>> flat = VariableFlattener.flatten(variables);
        varLock.writeLock().lock();
        try {
            Map<String, VarEntry> opVars = variableStore
                    .computeIfAbsent(opName, k -> new LinkedHashMap<>());
            for (Map.Entry<String, String> entry : flat) {
                VarEntry ve = opVars.computeIfAbsent(entry.getKey(), k -> new VarEntry());
                ve.count++;
                if (ve.samples.size() < MAX_SAMPLES) {
                    ve.samples.add(entry.getValue());
                }
            }
        } finally {
            varLock.writeLock().unlock();
        }
    }

    /**
     * Get variable rows for the UI table: (path, samples_string, count)
     */
    public List<Object[]> getVariableRows(String opName) {
        varLock.readLock().lock();
        try {
            Map<String, VarEntry> opVars = variableStore.get(opName);
            if (opVars == null) return Collections.emptyList();

            List<Object[]> rows = new ArrayList<>();
            opVars.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> {
                        String samples = String.join(" | ",
                                e.getValue().samples.stream().sorted().toList());
                        rows.add(new Object[]{
                                e.getKey(), samples, e.getValue().count
                        });
                    });
            return rows;
        } finally {
            varLock.readLock().unlock();
        }
    }

    public Set<String> getAllVariablePaths(String opName) {
        varLock.readLock().lock();
        try {
            Map<String, VarEntry> opVars = variableStore.get(opName);
            return opVars != null
                    ? new HashSet<>(opVars.keySet())
                    : Collections.emptySet();
        } finally {
            varLock.readLock().unlock();
        }
    }

    // ---- Request Shapes ----

    /**
     * Store a request by its variable shape signature.
     */
    public void storeRequest(String opName, JsonObject variables,
                             HttpRequest request, HttpService service) {
        Set<String> sig;
        List<String> keys;
        if (variables != null) {
            keys = VariableFlattener.flattenKeys(variables);
            sig = new TreeSet<>(keys);
        } else {
            keys = Collections.emptyList();
            sig = Collections.emptySet();
        }

        reqLock.writeLock().lock();
        try {
            List<VariableShape> shapes = requestStore
                    .computeIfAbsent(opName, k -> new ArrayList<>());

            for (VariableShape shape : shapes) {
                if (shape.getSignature().equals(sig)) {
                    shape.updateRequest(request, service);
                    shape.incrementCount();
                    return;
                }
            }

            // New shape
            shapes.add(new VariableShape(sig, keys, request, service));
        } finally {
            reqLock.writeLock().unlock();
        }
    }

    /**
     * Get all shapes for an operation, sorted by key count descending.
     */
    public List<VariableShape> getShapes(String opName) {
        reqLock.readLock().lock();
        try {
            List<VariableShape> shapes = requestStore.get(opName);
            if (shapes == null) return Collections.emptyList();
            List<VariableShape> sorted = new ArrayList<>(shapes);
            sorted.sort((a, b) -> Integer.compare(
                    b.getSortedKeys().size(), a.getSortedKeys().size()));
            return sorted;
        } finally {
            reqLock.readLock().unlock();
        }
    }

    public int getShapeCount(String opName) {
        reqLock.readLock().lock();
        try {
            List<VariableShape> shapes = requestStore.get(opName);
            return shapes != null ? shapes.size() : 0;
        } finally {
            reqLock.readLock().unlock();
        }
    }

    /**
     * Find the stored shape whose keys best cover the requested paths.
     */
    public VariableShape getBestShapeForPaths(String opName, Set<String> paths) {
        reqLock.readLock().lock();
        try {
            List<VariableShape> shapes = requestStore.get(opName);
            if (shapes == null) return null;

            VariableShape best = null;
            int bestOverlap = -1;
            for (VariableShape shape : shapes) {
                Set<String> overlap = new HashSet<>(paths);
                overlap.retainAll(shape.getSignature());
                if (overlap.size() > bestOverlap) {
                    bestOverlap = overlap.size();
                    best = shape;
                }
            }
            return best;
        } finally {
            reqLock.readLock().unlock();
        }
    }

    // ---- Raw access for export/import ----

    public Map<String, Map<String, VarEntry>> getVariableStoreSnapshot() {
        varLock.readLock().lock();
        try {
            Map<String, Map<String, VarEntry>> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, VarEntry>> e : variableStore.entrySet()) {
                copy.put(e.getKey(), new LinkedHashMap<>(e.getValue()));
            }
            return copy;
        } finally {
            varLock.readLock().unlock();
        }
    }

    public Map<String, List<VariableShape>> getRequestStoreSnapshot() {
        reqLock.readLock().lock();
        try {
            Map<String, List<VariableShape>> copy = new LinkedHashMap<>();
            for (Map.Entry<String, List<VariableShape>> e : requestStore.entrySet()) {
                copy.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            return copy;
        } finally {
            reqLock.readLock().unlock();
        }
    }

    // ---- Clear ----

    public void clear() {
        operations.clear();
        opIndex.clear();
        varLock.writeLock().lock();
        try {
            variableStore.clear();
        } finally {
            varLock.writeLock().unlock();
        }
        reqLock.writeLock().lock();
        try {
            requestStore.clear();
        } finally {
            reqLock.writeLock().unlock();
        }
    }

    // ---- Import helpers ----

    /**
     * Directly add a pre-built VariableShape (used during import).
     */
    public void addImportedShape(String opName, VariableShape shape) {
        reqLock.writeLock().lock();
        try {
            requestStore.computeIfAbsent(opName, k -> new ArrayList<>())
                    .add(shape);
        } finally {
            reqLock.writeLock().unlock();
        }
    }

    /**
     * Directly add variable sample data (used during import).
     */
    public void addImportedVariable(String opName, String path,
                                    int count, List<String> samples) {
        varLock.writeLock().lock();
        try {
            Map<String, VarEntry> opVars = variableStore
                    .computeIfAbsent(opName, k -> new LinkedHashMap<>());
            VarEntry ve = new VarEntry();
            ve.count = count;
            ve.samples.addAll(samples);
            opVars.put(path, ve);
        } finally {
            varLock.writeLock().unlock();
        }
    }

    /**
     * Listener interface for UI updates.
     */
    public interface OperationStoreListener {
        void operationAdded(int index);
        void operationUpdated(int index);
    }
}
