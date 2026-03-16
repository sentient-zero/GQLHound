package io.github.sentientzero.gqlhound.store;

import io.github.sentientzero.gqlhound.extraction.OperationExtractor;
import io.github.sentientzero.gqlhound.extraction.VariableFlattener;
import io.github.sentientzero.gqlhound.model.*;
import com.google.gson.*;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.api.montoya.http.HttpService.httpService;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;

/**
 * Handles export and import of the full OperationStore state to/from JSON.
 * Export format version 1, backward-compatible with Python GQL Hound exports.
 */
public final class ExportImporter {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private ExportImporter() {}

    /**
     * Export the full store state to a JSON file.
     */
    public static void exportToFile(OperationStore store, File file)
            throws IOException {
        JsonObject root = new JsonObject();
        root.addProperty("version", 1);

        // Operations
        JsonArray opsArray = new JsonArray();
        for (GraphQlOperation op : store.getOperations()) {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", op.getName());
            obj.addProperty("type", op.getOperationType());
            obj.addProperty("status", op.getStatus().getLabel());
            obj.addProperty("count", op.getRequestCount());
            obj.addProperty("host", op.getLastHost());
            opsArray.add(obj);
        }
        root.add("operations", opsArray);

        // Variables
        JsonObject varsObj = new JsonObject();
        Map<String, Map<String, OperationStore.VarEntry>> varSnapshot =
                store.getVariableStoreSnapshot();
        for (Map.Entry<String, Map<String, OperationStore.VarEntry>> opEntry :
                varSnapshot.entrySet()) {
            JsonObject pathsObj = new JsonObject();
            for (Map.Entry<String, OperationStore.VarEntry> pathEntry :
                    opEntry.getValue().entrySet()) {
                JsonObject entryObj = new JsonObject();
                entryObj.addProperty("count", pathEntry.getValue().count);
                JsonArray samplesArr = new JsonArray();
                pathEntry.getValue().samples.stream().sorted()
                        .forEach(samplesArr::add);
                entryObj.add("samples", samplesArr);
                pathsObj.add(pathEntry.getKey(), entryObj);
            }
            varsObj.add(opEntry.getKey(), pathsObj);
        }
        root.add("variables", varsObj);

        // Requests
        JsonObject reqsObj = new JsonObject();
        Map<String, List<VariableShape>> reqSnapshot =
                store.getRequestStoreSnapshot();
        for (Map.Entry<String, List<VariableShape>> opEntry :
                reqSnapshot.entrySet()) {
            JsonArray shapesArr = new JsonArray();
            for (VariableShape shape : opEntry.getValue()) {
                JsonObject shapeObj = new JsonObject();

                JsonArray keysArr = new JsonArray();
                shape.getSortedKeys().forEach(keysArr::add);
                shapeObj.add("keys", keysArr);
                shapeObj.addProperty("count", shape.getCount());

                HttpService svc = shape.getStoredService();
                shapeObj.addProperty("host", svc.host());
                shapeObj.addProperty("port", svc.port());
                shapeObj.addProperty("protocol",
                        svc.secure() ? "https" : "http");

                HttpRequest req = shape.getStoredRequest();
                String reqB64 = Base64.getEncoder().encodeToString(
                        req.toByteArray().getBytes());
                shapeObj.addProperty("request_b64", reqB64);

                shapesArr.add(shapeObj);
            }
            reqsObj.add(opEntry.getKey(), shapesArr);
        }
        root.add("requests", reqsObj);

        try (Writer writer = new BufferedWriter(
                new FileWriter(file, StandardCharsets.UTF_8))) {
            GSON.toJson(root, writer);
        }
    }

    /**
     * Import state from a JSON file, replacing current store contents.
     * Events are suppressed during import — caller must call
     * store.setSuppressEvents(true) before and handle the UI refresh after.
     */
    public static ImportResult importFromFile(OperationStore store, File file)
            throws IOException {
        store.clear();

        JsonObject root;
        try (Reader reader = new BufferedReader(
                new FileReader(file, StandardCharsets.UTF_8))) {
            root = JsonParser.parseReader(reader).getAsJsonObject();
        }

        int version = root.has("version") ? root.get("version").getAsInt() : 0;
        if (version != 1) {
            throw new IOException("Unsupported file version: " + version);
        }

        // 1. Restore request shapes
        if (root.has("requests")) {
            JsonObject reqsObj = root.getAsJsonObject("requests");
            for (Map.Entry<String, JsonElement> opEntry : reqsObj.entrySet()) {
                String opName = opEntry.getKey();
                for (JsonElement shapeEl : opEntry.getValue().getAsJsonArray()) {
                    JsonObject shapeObj = shapeEl.getAsJsonObject();

                    List<String> keys = new ArrayList<>();
                    if (shapeObj.has("keys")) {
                        shapeObj.getAsJsonArray("keys")
                                .forEach(e -> keys.add(e.getAsString()));
                    }

                    String host = shapeObj.get("host").getAsString();
                    int port = shapeObj.get("port").getAsInt();
                    String protocol = shapeObj.has("protocol")
                            ? shapeObj.get("protocol").getAsString()
                            : "https";
                    boolean secure = "https".equalsIgnoreCase(protocol);

                    byte[] reqBytes = Base64.getDecoder().decode(
                            shapeObj.get("request_b64").getAsString());

                    HttpService svc = httpService(host, port, secure);
                    HttpRequest req = httpRequest(svc,
                            burp.api.montoya.core.ByteArray.byteArray(reqBytes));

                    // If keys are empty, attempt to re-extract from the
                    // stored request body (handles imports from older
                    // versions that didn't extract inline arguments)
                    List<String> finalKeys = keys;
                    if (keys.isEmpty()) {
                        finalKeys = reExtractKeys(req);
                    }

                    Set<String> sig = new TreeSet<>(finalKeys);
                    VariableShape shape = new VariableShape(
                            sig, finalKeys, req, svc);
                    int count = shapeObj.has("count")
                            ? shapeObj.get("count").getAsInt() : 1;
                    shape.setCount(count);

                    store.addImportedShape(opName, shape);
                }
            }
        }

        // 2. Restore variable samples
        if (root.has("variables")) {
            JsonObject varsObj = root.getAsJsonObject("variables");
            for (Map.Entry<String, JsonElement> opEntry : varsObj.entrySet()) {
                String opName = opEntry.getKey();
                JsonObject pathsObj = opEntry.getValue().getAsJsonObject();
                for (Map.Entry<String, JsonElement> pathEntry :
                        pathsObj.entrySet()) {
                    JsonObject entryObj = pathEntry.getValue().getAsJsonObject();
                    int count = entryObj.get("count").getAsInt();
                    List<String> samples = new ArrayList<>();
                    entryObj.getAsJsonArray("samples")
                            .forEach(e -> samples.add(e.getAsString()));
                    store.addImportedVariable(opName, pathEntry.getKey(),
                            count, samples);
                }
            }
        }

        // 3. If variable section was empty/missing for some operations
        //    (e.g. Python export without inline extraction), re-extract
        //    variables from stored request bodies
        reExtractMissingVariables(store);

        // 4. Restore operations (after requests so shape counts are correct)
        int opCount = 0;
        if (root.has("operations")) {
            for (JsonElement opEl : root.getAsJsonArray("operations")) {
                JsonObject opObj = opEl.getAsJsonObject();
                String name = opObj.get("name").getAsString();
                String type = opObj.get("type").getAsString();
                String status = opObj.has("status")
                        ? opObj.get("status").getAsString() : "New";
                int count = opObj.get("count").getAsInt();
                String host = opObj.get("host").getAsString();

                store.trackOperation(name, type, host);
                GraphQlOperation op = store.getOperationByName(name);
                if (op != null) {
                    op.setRequestCount(count);
                    op.setStatus(OperationStatus.fromLabel(status));
                    op.setShapeCount(store.getShapeCount(name));
                }
                opCount++;
            }
        }

        // Count shapes
        int shapeCount = 0;
        for (List<VariableShape> shapes :
                store.getRequestStoreSnapshot().values()) {
            shapeCount += shapes.size();
        }

        return new ImportResult(opCount, shapeCount);
    }

    /**
     * Attempt to extract variable keys from a stored request's body.
     * Handles both parameterized (variables object) and inline arguments.
     */
    private static List<String> reExtractKeys(HttpRequest request) {
        try {
            String body = request.bodyToString();
            if (body == null || body.isBlank()) {
                return Collections.emptyList();
            }
            List<ExtractedOperation> ops = OperationExtractor.extract(body);
            if (ops.isEmpty()) {
                return Collections.emptyList();
            }
            // Use the first operation's variables
            ExtractedOperation op = ops.get(0);
            if (op.variables() != null && !op.variables().isEmpty()) {
                return VariableFlattener.flattenKeys(op.variables());
            }
        } catch (Exception ignored) {
            // Best effort
        }
        return Collections.emptyList();
    }

    /**
     * For operations that have stored requests but no variable samples,
     * re-extract variables from the stored request bodies.
     */
    private static void reExtractMissingVariables(OperationStore store) {
        Map<String, List<VariableShape>> reqSnapshot =
                store.getRequestStoreSnapshot();
        for (Map.Entry<String, List<VariableShape>> entry :
                reqSnapshot.entrySet()) {
            String opName = entry.getKey();
            Set<String> existingPaths = store.getAllVariablePaths(opName);
            if (!existingPaths.isEmpty()) {
                continue; // Already has variable data
            }

            // Try to extract from stored requests
            for (VariableShape shape : entry.getValue()) {
                try {
                    String body = shape.getStoredRequest().bodyToString();
                    List<ExtractedOperation> ops =
                            OperationExtractor.extract(body);
                    for (ExtractedOperation op : ops) {
                        if (op.variables() != null) {
                            store.recordVariables(opName, op.variables());
                        }
                    }
                } catch (Exception ignored) {
                    // Best effort
                }
            }
        }
    }

    public record ImportResult(int operationCount, int shapeCount) {}
}
