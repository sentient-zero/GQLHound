package io.github.sentientzero.gqlhound.intruder;

import io.github.sentientzero.gqlhound.extraction.OperationExtractor;
import io.github.sentientzero.gqlhound.extraction.QueryStyleConverter;
import io.github.sentientzero.gqlhound.extraction.VariableFlattener;
import io.github.sentientzero.gqlhound.model.QueryStyle;
import io.github.sentientzero.gqlhound.model.VariableShape;
import io.github.sentientzero.gqlhound.store.OperationStore;
import com.google.gson.JsonObject;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Sends requests to Repeater, with optional style conversion between
 * inline and parameterized GraphQL variable styles.
 */
public class RepeaterSender {

    private final MontoyaApi api;
    private final OperationStore store;

    public RepeaterSender(MontoyaApi api, OperationStore store) {
        this.api = api;
        this.store = store;
    }

    public void send(VariableShape shape, String opName) {
        send(shape, opName, QueryStyle.ORIGINAL);
    }

    public void send(VariableShape shape, String opName, QueryStyle style) {
        try {
            HttpRequest request = shape.getStoredRequest();
            String body = request.bodyToString();

            JsonObject opData = OperationExtractor.extractSingleFromBatch(
                    body, opName);
            if (opData == null) {
                api.repeater().sendToRepeater(request, opName);
                api.logging().logToOutput(
                        "[GQL Hound] Sent to Repeater (raw): " + opName);
                return;
            }

            // Rebuild from single op if batch
            if (!body.strip().startsWith("{")) {
                api.logging().logToOutput(
                        "[GQL Hound] Extracted '%s' from batch"
                                .formatted(opName));
            }

            // Apply style conversion
            JsonObject converted = switch (style) {
                case INLINE -> QueryStyleConverter.toInline(opData);
                case PARAMETERIZED -> QueryStyleConverter.toParameterized(opData);
                default -> opData;
            };

            String tabName = style == QueryStyle.ORIGINAL
                    ? opName
                    : opName + " [" + style.getLabel() + "]";

            request = request.withBody(converted.toString());
            api.repeater().sendToRepeater(request, tabName);

            api.logging().logToOutput(
                    "[GQL Hound] Sent to Repeater (%s): %s"
                            .formatted(style.getLabel(), opName));

        } catch (Exception e) {
            api.logging().logToError(
                    "[GQL Hound] Repeater send failed: " + e.getMessage());
        }
    }

    /**
     * Send a merged request with all observed variables to Repeater.
     */
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

            // Ensure parameterized for merging
            JsonObject parameterized =
                    QueryStyleConverter.toParameterized(opData);

            JsonObject variables = parameterized.has("variables")
                    && parameterized.get("variables").isJsonObject()
                    ? parameterized.getAsJsonObject("variables")
                    : new JsonObject();

            Set<String> allKeys = new HashSet<>();
            for (VariableShape shape : shapes) {
                allKeys.addAll(shape.getSortedKeys());
            }
            Set<String> existing = new HashSet<>(
                    VariableFlattener.flattenKeys(variables));
            for (String path : allKeys) {
                if (!existing.contains(path)) {
                    injectPath(variables, path, "FUZZ");
                }
            }
            parameterized.add("variables", variables);

            JsonObject finalBody = switch (style) {
                case INLINE -> QueryStyleConverter.toInline(parameterized);
                default -> parameterized;
            };

            String tabName = opName + " [Merged"
                    + (style == QueryStyle.ORIGINAL ? "" : " " + style.getLabel())
                    + "]";

            request = request.withBody(finalBody.toString());
            api.repeater().sendToRepeater(request, tabName);

            api.logging().logToOutput(
                    "[GQL Hound] Sent MERGED to Repeater (%s): %s"
                            .formatted(style.getLabel(), opName));

        } catch (Exception e) {
            api.logging().logToError(
                    "[GQL Hound] Merged Repeater send failed: "
                            + e.getMessage());
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
