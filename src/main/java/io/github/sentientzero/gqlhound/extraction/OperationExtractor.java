package io.github.sentientzero.gqlhound.extraction;

import io.github.sentientzero.gqlhound.model.ExtractedOperation;
import com.google.gson.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts GraphQL operation names, types, and variables from request bodies.
 * Handles single objects, batched arrays, and regex fallback for non-JSON.
 */
public final class OperationExtractor {

    private static final Pattern OP_PATTERN =
            Pattern.compile("(query|mutation|subscription)\\s+(\\w+)");

    /**
     * Pattern to match a field call with inline arguments:
     *   fieldName(arg1: val1, arg2: val2)
     * Captures the arguments substring between the parens.
     */
    private static final Pattern INLINE_ARGS_PATTERN =
            Pattern.compile("\\w+\\s*\\(([^)]+)\\)\\s*\\{");

    /**
     * Pattern to match individual key: value pairs in inline arguments.
     * Handles strings (with escaped quotes), numbers, booleans, null.
     */
    private static final Pattern ARG_PAIR_PATTERN =
            Pattern.compile(
                    "(\\w+)\\s*:\\s*" +
                    "(?:" +
                        "\"((?:[^\"\\\\]|\\\\.)*)\"" +  // quoted string
                        "|" +
                        "([\\w.+-]+)" +                  // number, bool, null, enum
                    ")"
            );

    private static final Gson GSON = new Gson();

    private OperationExtractor() {}

    /**
     * Extract all operations from a request body string.
     * Returns empty list if no operations found.
     */
    public static List<ExtractedOperation> extract(String body) {
        if (body == null || body.isBlank()) {
            return Collections.emptyList();
        }

        body = body.strip();

        // Try JSON parse
        try {
            JsonElement element = JsonParser.parseString(body);

            if (element.isJsonArray()) {
                JsonArray array = element.getAsJsonArray();
                List<ExtractedOperation> results = new ArrayList<>();
                for (JsonElement item : array) {
                    if (item.isJsonObject()) {
                        ExtractedOperation op = fromJsonObject(item.getAsJsonObject());
                        if (op != null) {
                            results.add(op);
                        }
                    }
                }
                return results;
            }

            if (element.isJsonObject()) {
                ExtractedOperation op = fromJsonObject(element.getAsJsonObject());
                if (op != null) {
                    return List.of(op);
                }
            }
        } catch (JsonSyntaxException e) {
            // Fall through to regex
        }

        // Regex fallback for non-JSON bodies
        return extractFromRegex(body);
    }

    /**
     * Extract a single operation from a parsed JSON object.
     */
    private static ExtractedOperation fromJsonObject(JsonObject obj) {
        String query = "";
        if (obj.has("query") && obj.get("query").isJsonPrimitive()) {
            query = obj.get("query").getAsString();
        }

        String name = null;
        if (obj.has("operationName") && !obj.get("operationName").isJsonNull()) {
            name = obj.get("operationName").getAsString();
        }

        String opType = "query"; // default

        Matcher m = OP_PATTERN.matcher(query);
        if (m.find()) {
            opType = m.group(1);
            if (name == null || name.isEmpty()) {
                name = m.group(2);
            }
        }

        if (name == null || name.isEmpty()) {
            return null;
        }

        JsonObject variables = null;
        if (obj.has("variables") && !obj.get("variables").isJsonNull()) {
            JsonElement varElement = obj.get("variables");
            if (varElement.isJsonObject()) {
                variables = varElement.getAsJsonObject();
            } else if (varElement.isJsonPrimitive()
                    && varElement.getAsJsonPrimitive().isString()) {
                // Handle stringified JSON: "variables": "{\"key\": \"val\"}"
                try {
                    JsonElement parsed = JsonParser.parseString(
                            varElement.getAsString());
                    if (parsed.isJsonObject()) {
                        variables = parsed.getAsJsonObject();
                    }
                } catch (JsonSyntaxException ignored) {
                    // Not valid JSON string, skip
                }
            }
        }

        // If no variables object found, try to extract inline arguments
        // from the query string itself (e.g., createOrder(productId: "X", quantity: 10))
        if (variables == null && !query.isEmpty()) {
            variables = extractInlineArguments(query);
        }

        return new ExtractedOperation(name, opType, variables);
    }

    /**
     * Public accessor for inline argument extraction from a query string.
     * Used by IntruderSender to find position offsets for inline values.
     */
    public static JsonObject extractInlineVariables(String query) {
        return extractInlineArguments(query);
    }

    /**
     * Parse inline arguments from a GraphQL query string.
     * Handles: createOrder(productId: "PROD123", quantity: 10, metadata: "test")
     * Returns a JsonObject with the extracted key-value pairs, or null.
     */
    private static JsonObject extractInlineArguments(String query) {
        Matcher argBlockMatcher = INLINE_ARGS_PATTERN.matcher(query);
        JsonObject allVars = null;

        while (argBlockMatcher.find()) {
            String argsString = argBlockMatcher.group(1);
            Matcher pairMatcher = ARG_PAIR_PATTERN.matcher(argsString);

            while (pairMatcher.find()) {
                if (allVars == null) allVars = new JsonObject();

                String key = pairMatcher.group(1);
                String quotedVal = pairMatcher.group(2);  // string value
                String bareVal = pairMatcher.group(3);     // number/bool/null/enum

                if (quotedVal != null) {
                    // Unescape basic sequences
                    String unescaped = quotedVal
                            .replace("\\\"", "\"")
                            .replace("\\\\", "\\")
                            .replace("\\n", "\n");
                    allVars.addProperty(key, unescaped);
                } else if (bareVal != null) {
                    switch (bareVal.toLowerCase()) {
                        case "true" -> allVars.addProperty(key, true);
                        case "false" -> allVars.addProperty(key, false);
                        case "null" -> allVars.add(key, JsonNull.INSTANCE);
                        default -> {
                            // Try number, fall back to string (enum values etc.)
                            try {
                                if (bareVal.contains(".")) {
                                    allVars.addProperty(key,
                                            Double.parseDouble(bareVal));
                                } else {
                                    allVars.addProperty(key,
                                            Long.parseLong(bareVal));
                                }
                            } catch (NumberFormatException e) {
                                allVars.addProperty(key, bareVal);
                            }
                        }
                    }
                }
            }
        }

        return allVars;
    }

    /**
     * Regex fallback for non-JSON bodies. No variables available.
     */
    private static List<ExtractedOperation> extractFromRegex(String body) {
        Matcher m = OP_PATTERN.matcher(body);
        List<ExtractedOperation> results = new ArrayList<>();
        while (m.find()) {
            results.add(new ExtractedOperation(m.group(2), m.group(1), null));
        }
        return results;
    }

    /**
     * Extract a specific operation from a batched JSON array body.
     * Returns the JsonObject for the matching operation, or null.
     */
    public static JsonObject extractSingleFromBatch(String body, String opName) {
        try {
            JsonElement element = JsonParser.parseString(body);
            if (!element.isJsonArray()) {
                return element.isJsonObject() ? element.getAsJsonObject() : null;
            }

            for (JsonElement item : element.getAsJsonArray()) {
                if (!item.isJsonObject()) continue;
                JsonObject obj = item.getAsJsonObject();

                String itemName = null;
                if (obj.has("operationName") && !obj.get("operationName").isJsonNull()) {
                    itemName = obj.get("operationName").getAsString();
                }
                if (itemName == null && obj.has("query") && obj.get("query").isJsonPrimitive()) {
                    Matcher m = OP_PATTERN.matcher(obj.get("query").getAsString());
                    if (m.find()) {
                        itemName = m.group(2);
                    }
                }

                if (opName.equals(itemName)) {
                    return obj;
                }
            }
        } catch (JsonSyntaxException e) {
            // ignore
        }
        return null;
    }
}
