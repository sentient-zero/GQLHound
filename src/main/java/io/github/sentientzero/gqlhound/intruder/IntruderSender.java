package io.github.sentientzero.gqlhound.intruder;

import io.github.sentientzero.gqlhound.extraction.JsonPositionWriter;
import io.github.sentientzero.gqlhound.extraction.OperationExtractor;
import io.github.sentientzero.gqlhound.extraction.QueryStyleConverter;
import io.github.sentientzero.gqlhound.extraction.VariableFlattener;
import io.github.sentientzero.gqlhound.model.QueryStyle;
import io.github.sentientzero.gqlhound.model.VariableShape;
import io.github.sentientzero.gqlhound.store.OperationStore;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.Range.range;
import static burp.api.montoya.intruder.HttpRequestTemplate.httpRequestTemplate;

/**
 * Sends requests to Intruder with auto-marked payload positions.
 * Supports original, inline, and parameterized variable styles.
 * For parameterized: positions are marked on variables object values.
 * For inline: positions are marked on argument values in the query string.
 */
public class IntruderSender {

    private final MontoyaApi api;
    private final OperationStore store;

    public IntruderSender(MontoyaApi api, OperationStore store) {
        this.api = api;
        this.store = store;
    }

    public void sendShape(VariableShape shape, String opName) {
        sendShape(shape, opName, null, QueryStyle.ORIGINAL);
    }

    public void sendShape(VariableShape shape, String opName, Set<String> markPaths) {
        sendShape(shape, opName, markPaths, QueryStyle.ORIGINAL);
    }

    /**
     * Send to Intruder with style conversion and position marking.
     */
    public void sendShape(VariableShape shape, String opName,
                          Set<String> markPaths, QueryStyle style) {
        try {
            HttpRequest request = shape.getStoredRequest();
            String body = request.bodyToString();

            JsonObject opData = OperationExtractor.extractSingleFromBatch(
                    body, opName);
            if (opData == null) {
                api.logging().logToError(
                        "[GQL Hound] Could not find op '%s' in body"
                                .formatted(opName));
                return;
            }

            // Apply style conversion
            JsonObject converted = switch (style) {
                case INLINE -> QueryStyleConverter.toInline(opData);
                case PARAMETERIZED -> QueryStyleConverter.toParameterized(opData);
                default -> opData;
            };

            // Choose position marking strategy based on effective style
            boolean hasVariablesObj = converted.has("variables")
                    && converted.get("variables").isJsonObject()
                    && !converted.getAsJsonObject("variables").isEmpty();

            if (hasVariablesObj) {
                sendWithVariablePositions(request, shape, opName, converted,
                        markPaths, style);
            } else {
                sendWithInlinePositions(request, shape, opName, converted,
                        style);
            }

        } catch (Exception e) {
            api.logging().logToError(
                    "[GQL Hound] Intruder send failed: " + e.getMessage());
        }
    }

    /**
     * Mark positions on the variables object (parameterized style).
     * Uses JsonPositionWriter which tracks positions under "variables.*".
     */
    private void sendWithVariablePositions(
            HttpRequest request, VariableShape shape, String opName,
            JsonObject body, Set<String> markPaths, QueryStyle style) {

        JsonPositionWriter writer = new JsonPositionWriter(markPaths);
        writer.serialize(body);
        String newBody = writer.getResult();

        HttpRequest newRequest = request.withBody(newBody);

        if (writer.getPositionCount() == 0) {
            api.intruder().sendToIntruder(newRequest);
            api.logging().logToOutput(
                    "[GQL Hound] Sent to Intruder (%s, no positions): %s"
                            .formatted(style.getLabel(), opName));
            return;
        }

        int bodyOffset = newRequest.bodyOffset();
        List<Range> ranges = new ArrayList<>();
        for (Map.Entry<String, int[]> entry : writer.getSortedPositions()) {
            int start = bodyOffset + entry.getValue()[0];
            int end = bodyOffset + entry.getValue()[1];
            ranges.add(range(start, end));
            api.logging().logToOutput(
                    "[GQL Hound]   Position: %s -> [%d, %d]"
                            .formatted(entry.getKey(), start, end));
        }

        HttpRequestTemplate template = httpRequestTemplate(newRequest, ranges);
        api.intruder().sendToIntruder(shape.getStoredService(), template);
        api.logging().logToOutput(
                "[GQL Hound] Sent to Intruder (%s) with %d position(s): %s"
                        .formatted(style.getLabel(), ranges.size(), opName));
    }

    /**
     * Mark positions on inline argument values within the query string.
     * Searches for "argName: \"value\"" and "argName: 123" patterns in
     * the serialized body and marks the value portions.
     */
    private void sendWithInlinePositions(
            HttpRequest request, VariableShape shape, String opName,
            JsonObject body, QueryStyle style) {

        String serialized = body.toString();
        HttpRequest newRequest = request.withBody(serialized);
        int bodyOffset = newRequest.bodyOffset();

        // Extract the inline arguments we know about
        String query = body.has("query")
                ? body.get("query").getAsString() : "";
        JsonObject inlineVars = OperationExtractor.extractInlineVariables(query);

        if (inlineVars == null || inlineVars.isEmpty()) {
            api.intruder().sendToIntruder(newRequest);
            api.logging().logToOutput(
                    "[GQL Hound] Sent to Intruder (%s, no positions): %s"
                            .formatted(style.getLabel(), opName));
            return;
        }

        // Find positions of each inline arg value in the serialized body
        List<Range> ranges = new ArrayList<>();
        for (Map.Entry<String, JsonElement> entry : inlineVars.entrySet()) {
            String argName = entry.getKey();
            JsonElement val = entry.getValue();

            int[] pos = findInlineArgPosition(serialized, argName, val);
            if (pos != null) {
                ranges.add(range(bodyOffset + pos[0], bodyOffset + pos[1]));
                api.logging().logToOutput(
                        "[GQL Hound]   Inline position: %s -> [%d, %d]"
                                .formatted(argName,
                                        bodyOffset + pos[0],
                                        bodyOffset + pos[1]));
            }
        }

        // Sort by offset ascending (required by Burp)
        ranges.sort(Comparator.comparingInt(Range::startIndexInclusive));

        if (ranges.isEmpty()) {
            api.intruder().sendToIntruder(newRequest);
        } else {
            HttpRequestTemplate template = httpRequestTemplate(
                    newRequest, ranges);
            api.intruder().sendToIntruder(shape.getStoredService(), template);
        }

        api.logging().logToOutput(
                "[GQL Hound] Sent to Intruder (%s) with %d position(s): %s"
                        .formatted(style.getLabel(), ranges.size(), opName));
    }

    /**
     * Find the byte offset of an inline argument value in the serialized body.
     * The serialized body contains the query inside a JSON string, so quotes
     * are escaped as \".
     *
     * For string values: searches for argName: \"value\" and marks just value
     * For numeric/bool: searches for argName: 123 and marks just 123
     */
    private int[] findInlineArgPosition(String serialized, String argName,
                                        JsonElement value) {
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            // String value: in the serialized JSON, the query string has
            // escaped quotes, so "PROD123" appears as \\\"PROD123\\\"
            // (actually in Java string: \\\"PROD123\\\")
            String escaped = value.getAsString()
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"");
            String pattern = argName + ": \\\\\"" + Pattern.quote(escaped)
                    + "\\\\\"";
            // In the serialized body it looks like: argName: \"value\"
            // which in Java string is: argName: \\\"value\\\"
            String searchStr = argName + ": \\\"" + escaped + "\\\"";
            int idx = serialized.indexOf(searchStr);
            if (idx >= 0) {
                // Mark just the value between the escaped quotes
                int valStart = idx + argName.length() + 4; // skip ": \\"
                int valEnd = valStart + escaped.length();
                return new int[]{valStart, valEnd};
            }
        } else {
            // Number, boolean, null, enum
            String valStr = value.isJsonNull() ? "null"
                    : value.getAsJsonPrimitive().isBoolean()
                    ? String.valueOf(value.getAsBoolean())
                    : value.getAsNumber().toString();
            // Handle long vs double representation
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                Number num = value.getAsNumber();
                if (num.doubleValue() == num.longValue()) {
                    valStr = String.valueOf(num.longValue());
                }
            }
            String searchStr = argName + ": " + valStr;
            int idx = serialized.indexOf(searchStr);
            if (idx >= 0) {
                int valStart = idx + argName.length() + 2; // skip ": "
                int valEnd = valStart + valStr.length();
                return new int[]{valStart, valEnd};
            }
        }
        return null;
    }

    /**
     * Send a merged request with all observed variables to Intruder.
     */
    public void sendMerged(String opName) {
        sendMerged(opName, QueryStyle.ORIGINAL);
    }

    public void sendMerged(String opName, QueryStyle style) {
        try {
            List<VariableShape> shapes = store.getShapes(opName);
            if (shapes.isEmpty()) {
                api.logging().logToError(
                        "[GQL Hound] No stored shapes for: " + opName);
                return;
            }

            VariableShape base = shapes.get(0);
            HttpRequest request = base.getStoredRequest();
            String body = request.bodyToString();

            JsonObject opData = OperationExtractor.extractSingleFromBatch(
                    body, opName);
            if (opData == null) {
                api.logging().logToError(
                        "[GQL Hound] Could not extract '%s' for merge"
                                .formatted(opName));
                return;
            }

            // Ensure parameterized form for merging
            JsonObject parameterized = QueryStyleConverter.toParameterized(opData);

            JsonObject variables = parameterized.has("variables")
                    && parameterized.get("variables").isJsonObject()
                    ? parameterized.getAsJsonObject("variables")
                    : new JsonObject();

            // Collect all keys from all shapes
            Set<String> allKeys = new HashSet<>();
            for (VariableShape shape : shapes) {
                allKeys.addAll(shape.getSortedKeys());
            }

            Set<String> existingKeys = new HashSet<>(
                    VariableFlattener.flattenKeys(variables));
            Set<String> missing = new HashSet<>(allKeys);
            missing.removeAll(existingKeys);
            for (String path : missing) {
                injectPath(variables, path, "FUZZ");
            }

            parameterized.add("variables", variables);

            // Apply final style conversion if requested
            JsonObject finalBody = switch (style) {
                case INLINE -> QueryStyleConverter.toInline(parameterized);
                default -> parameterized;
            };

            // Send using appropriate position strategy
            boolean hasVarsObj = finalBody.has("variables")
                    && finalBody.get("variables").isJsonObject()
                    && !finalBody.getAsJsonObject("variables").isEmpty();

            if (hasVarsObj) {
                sendWithVariablePositions(request, base, opName, finalBody,
                        null, style);
            } else {
                sendWithInlinePositions(request, base, opName, finalBody,
                        style);
            }

            api.logging().logToOutput(
                    "[GQL Hound] Sent MERGED (%s) to Intruder: %s"
                            .formatted(style.getLabel(), opName));

        } catch (Exception e) {
            api.logging().logToError(
                    "[GQL Hound] Merged send failed: " + e.getMessage());
        }
    }

    private static void injectPath(JsonObject root, String path, String value) {
        String[] parts = path.split("\\.");
        JsonObject current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            if (!current.has(part) || !current.get(part).isJsonObject()) {
                current.add(part, new JsonObject());
            }
            current = current.getAsJsonObject(part);
        }
        current.addProperty(parts[parts.length - 1], value);
    }
}
