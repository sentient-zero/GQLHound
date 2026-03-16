package io.github.sentientzero.gqlhound.extraction;

import com.google.gson.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Converts GraphQL requests between inline and parameterized variable styles.
 *
 * Parameterized:
 *   query: "mutation createOrder($productId: String!, $quantity: Int!) {
 *            createOrder(productId: $productId, quantity: $quantity) { orderId } }"
 *   variables: {"productId": "PROD123", "quantity": 10}
 *
 * Inline:
 *   query: "mutation createOrder {
 *            createOrder(productId: \"PROD123\", quantity: 10) { orderId } }"
 *   (no variables object)
 */
public final class QueryStyleConverter {

    private QueryStyleConverter() {}

    // Matches the variable declaration block: ($var: Type!, $var2: Type)
    private static final Pattern VAR_DECL_BLOCK =
            Pattern.compile("(query|mutation|subscription)\\s+(\\w+)\\s*\\(([^)]+)\\)");

    // Matches individual variable declarations: $varName: TypeName!
    private static final Pattern VAR_DECL =
            Pattern.compile("\\$(\\w+)\\s*:\\s*([\\w!\\[\\]]+)");

    // Matches $varName references in the query body
    private static final Pattern VAR_REF =
            Pattern.compile("\\$(\\w+)");

    // Matches a field call with inline args: fieldName(arg: val, ...)
    private static final Pattern INLINE_ARGS_BLOCK =
            Pattern.compile("(\\w+)\\s*\\(([^)]+)\\)\\s*\\{");

    // Matches key: value pairs in inline arguments
    private static final Pattern INLINE_PAIR =
            Pattern.compile(
                    "(\\w+)\\s*:\\s*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(\\$\\w+)|([\\w.+-]+))");

    /**
     * Convert a parameterized request to inline style.
     * Takes the variables JSON and substitutes values directly into the query string.
     * Returns a new JsonObject with the modified query and no variables.
     */
    public static JsonObject toInline(JsonObject requestBody) {
        String query = requestBody.has("query")
                ? requestBody.get("query").getAsString() : "";
        JsonObject variables = requestBody.has("variables")
                && requestBody.get("variables").isJsonObject()
                ? requestBody.getAsJsonObject("variables") : null;

        if (variables == null || variables.isEmpty()) {
            // Already inline or no variables to convert
            return requestBody.deepCopy();
        }

        String converted = query;

        // Remove variable declaration block: mutation foo($id: ID!, $name: String!) -> mutation foo
        Matcher declBlock = VAR_DECL_BLOCK.matcher(converted);
        if (declBlock.find()) {
            String opType = declBlock.group(1);
            String opName = declBlock.group(2);
            converted = converted.substring(0, declBlock.start())
                    + opType + " " + opName
                    + converted.substring(declBlock.end());
        }

        // Replace each $varName reference with the actual value
        for (Map.Entry<String, JsonElement> entry : variables.entrySet()) {
            String varName = entry.getKey();
            String literal = toLiteral(entry.getValue());
            // Replace $varName with the literal, handling word boundaries
            converted = converted.replaceAll(
                    "\\$" + Pattern.quote(varName) + "(?!\\w)",
                    Matcher.quoteReplacement(literal));
        }

        // Build new request body without variables
        JsonObject result = new JsonObject();
        result.addProperty("query", converted);
        if (requestBody.has("operationName")) {
            result.add("operationName", requestBody.get("operationName"));
        }
        return result;
    }

    /**
     * Convert an inline request to parameterized style.
     * Extracts inline argument values, replaces them with $variable references,
     * and builds a variables object.
     * Returns a new JsonObject with parameterized query and variables.
     */
    public static JsonObject toParameterized(JsonObject requestBody) {
        String query = requestBody.has("query")
                ? requestBody.get("query").getAsString() : "";
        JsonObject existingVars = requestBody.has("variables")
                && requestBody.get("variables").isJsonObject()
                ? requestBody.getAsJsonObject("variables") : null;

        if (existingVars != null && !existingVars.isEmpty()) {
            // Already parameterized
            return requestBody.deepCopy();
        }

        // Extract inline arguments and their types
        Map<String, ArgInfo> args = extractInlineArgs(query);
        if (args.isEmpty()) {
            return requestBody.deepCopy();
        }

        // Build variables object and replacement query
        JsonObject variables = new JsonObject();
        String converted = query;

        // Replace inline values with $variable references in the field call
        for (Map.Entry<String, ArgInfo> entry : args.entrySet()) {
            String argName = entry.getKey();
            ArgInfo info = entry.getValue();
            variables.add(argName, info.value);

            // Replace "argName: <literal>" with "argName: $argName"
            String literalPattern = buildLiteralPattern(argName, info);
            converted = converted.replaceFirst(
                    literalPattern,
                    Matcher.quoteReplacement(argName + ": $" + argName));
        }

        // Add variable declarations to the operation signature
        // mutation createOrder { -> mutation createOrder($productId: String!, $quantity: Int!) {
        Pattern opSig = Pattern.compile(
                "(query|mutation|subscription)\\s+(\\w+)\\s*\\{");
        Matcher sigMatcher = opSig.matcher(converted);
        if (sigMatcher.find()) {
            StringBuilder decls = new StringBuilder("(");
            boolean first = true;
            for (Map.Entry<String, ArgInfo> entry : args.entrySet()) {
                if (!first) decls.append(", ");
                first = false;
                decls.append("$").append(entry.getKey())
                        .append(": ").append(entry.getValue().graphqlType);
            }
            decls.append(")");

            converted = converted.substring(0, sigMatcher.end() - 1)
                    + decls
                    + " {"
                    + converted.substring(sigMatcher.end());
        }

        // Build new request body
        JsonObject result = new JsonObject();
        result.addProperty("query", converted);
        result.add("variables", variables);
        if (requestBody.has("operationName")) {
            result.add("operationName", requestBody.get("operationName"));
        }
        return result;
    }

    /**
     * Extract inline arguments from a query string with type inference.
     */
    private static Map<String, ArgInfo> extractInlineArgs(String query) {
        Map<String, ArgInfo> args = new LinkedHashMap<>();

        Matcher blockMatcher = INLINE_ARGS_BLOCK.matcher(query);
        while (blockMatcher.find()) {
            String argsStr = blockMatcher.group(2);
            Matcher pairMatcher = INLINE_PAIR.matcher(argsStr);

            while (pairMatcher.find()) {
                String key = pairMatcher.group(1);
                String quotedVal = pairMatcher.group(2);
                String varRef = pairMatcher.group(3);
                String bareVal = pairMatcher.group(4);

                // Skip if it's already a $variable reference
                if (varRef != null) continue;

                if (quotedVal != null) {
                    String unescaped = quotedVal
                            .replace("\\\"", "\"")
                            .replace("\\\\", "\\");
                    args.put(key, new ArgInfo(
                            new JsonPrimitive(unescaped), "String!",
                            "\"" + quotedVal + "\""));
                } else if (bareVal != null) {
                    switch (bareVal.toLowerCase()) {
                        case "true" -> args.put(key, new ArgInfo(
                                new JsonPrimitive(true), "Boolean!", bareVal));
                        case "false" -> args.put(key, new ArgInfo(
                                new JsonPrimitive(false), "Boolean!", bareVal));
                        case "null" -> args.put(key, new ArgInfo(
                                JsonNull.INSTANCE, "String", bareVal));
                        default -> {
                            try {
                                if (bareVal.contains(".")) {
                                    double d = Double.parseDouble(bareVal);
                                    args.put(key, new ArgInfo(
                                            new JsonPrimitive(d), "Float!", bareVal));
                                } else {
                                    long l = Long.parseLong(bareVal);
                                    args.put(key, new ArgInfo(
                                            new JsonPrimitive(l), "Int!", bareVal));
                                }
                            } catch (NumberFormatException e) {
                                // Enum value
                                args.put(key, new ArgInfo(
                                        new JsonPrimitive(bareVal), "String!", bareVal));
                            }
                        }
                    }
                }
            }
        }
        return args;
    }

    /**
     * Build a regex pattern that matches "argName: <literal>" in the query.
     */
    private static String buildLiteralPattern(String argName, ArgInfo info) {
        return Pattern.quote(argName) + "\\s*:\\s*"
                + Pattern.quote(info.originalLiteral);
    }

    /**
     * Convert a JsonElement to a GraphQL inline literal string.
     */
    private static String toLiteral(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return "null";
        }
        if (element.isJsonPrimitive()) {
            JsonPrimitive prim = element.getAsJsonPrimitive();
            if (prim.isString()) {
                return "\"" + escapeGraphQL(prim.getAsString()) + "\"";
            }
            if (prim.isBoolean()) {
                return prim.getAsBoolean() ? "true" : "false";
            }
            Number num = prim.getAsNumber();
            if (num.doubleValue() == num.longValue()) {
                return String.valueOf(num.longValue());
            }
            return num.toString();
        }
        if (element.isJsonArray()) {
            StringBuilder sb = new StringBuilder("[");
            JsonArray arr = element.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(toLiteral(arr.get(i)));
            }
            sb.append("]");
            return sb.toString();
        }
        if (element.isJsonObject()) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, JsonElement> entry :
                    element.getAsJsonObject().entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append(entry.getKey()).append(": ")
                        .append(toLiteral(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        return element.toString();
    }

    private static String escapeGraphQL(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Holds extracted argument info for inline-to-parameterized conversion.
     */
    private record ArgInfo(
            JsonElement value,
            String graphqlType,
            String originalLiteral
    ) {}
}
