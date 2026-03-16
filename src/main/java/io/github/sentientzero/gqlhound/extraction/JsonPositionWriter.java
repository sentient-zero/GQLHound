package io.github.sentientzero.gqlhound.extraction;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.*;

/**
 * Serializes a JsonElement to a JSON string while recording byte offsets
 * of variable values for Intruder position marking.
 *
 * String values are marked inside quotes so Intruder replaces the value
 * content, keeping the surrounding quotes and JSON structure valid.
 *
 * Positions are recorded relative to the start of the serialized body.
 */
public class JsonPositionWriter {

    private final Set<String> markPaths; // null = mark ALL variable paths
    private final StringBuilder buffer = new StringBuilder();
    private final Map<String, int[]> positions = new LinkedHashMap<>(); // path -> [start, end]

    /**
     * @param markPaths specific variable paths to mark, or null to mark all
     */
    public JsonPositionWriter(Set<String> markPaths) {
        this.markPaths = markPaths;
    }

    public String getResult() {
        return buffer.toString();
    }

    /**
     * Return positions sorted by start offset (ascending), as required by Burp.
     */
    public List<Map.Entry<String, int[]>> getSortedPositions() {
        List<Map.Entry<String, int[]>> sorted = new ArrayList<>(positions.entrySet());
        sorted.sort(Comparator.comparingInt(e -> e.getValue()[0]));
        return sorted;
    }

    public int getPositionCount() {
        return positions.size();
    }

    public void serialize(JsonElement element) {
        writeElement(element, "");
    }

    private void writeElement(JsonElement element, String path) {
        if (element == null || element.isJsonNull()) {
            writeLeaf(element, path);
        } else if (element.isJsonObject()) {
            writeObject(element.getAsJsonObject(), path);
        } else if (element.isJsonArray()) {
            writeArray(element.getAsJsonArray(), path);
        } else {
            writeLeaf(element, path);
        }
    }

    private void writeObject(JsonObject obj, String path) {
        buffer.append('{');
        boolean first = true;
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            if (!first) buffer.append(", ");
            first = false;

            // Write key
            buffer.append('"');
            buffer.append(escapeString(entry.getKey()));
            buffer.append("\": ");

            // Build child path
            String childPath = path.isEmpty()
                    ? entry.getKey()
                    : path + "." + entry.getKey();

            writeElement(entry.getValue(), childPath);
        }
        buffer.append('}');
    }

    private void writeArray(JsonArray arr, String path) {
        buffer.append('[');
        for (int i = 0; i < arr.size(); i++) {
            if (i > 0) buffer.append(", ");
            String childPath = path + "[" + i + "]";
            writeElement(arr.get(i), childPath);
        }
        buffer.append(']');
    }

    private void writeLeaf(JsonElement element, String path) {
        // Determine if this is under "variables" and should be marked
        String varPath = null;
        if (path.startsWith("variables.")) {
            varPath = path.substring("variables.".length());
        }

        boolean shouldMark = false;
        if (varPath != null) {
            if (markPaths == null) {
                shouldMark = true;
            } else {
                shouldMark = markPaths.contains(varPath);
            }
        }

        String jsonValue = toJsonLiteral(element);
        boolean isString = jsonValue.startsWith("\"") && jsonValue.endsWith("\"")
                && jsonValue.length() > 2;

        if (shouldMark && isString) {
            // Mark inside quotes: write quote, mark start, content, mark end, quote
            buffer.append('"');
            int start = buffer.length();
            buffer.append(jsonValue, 1, jsonValue.length() - 1); // escaped content
            int end = buffer.length();
            buffer.append('"');
            positions.put(varPath, new int[]{start, end});
        } else if (shouldMark) {
            int start = buffer.length();
            buffer.append(jsonValue);
            int end = buffer.length();
            positions.put(varPath, new int[]{start, end});
        } else {
            buffer.append(jsonValue);
        }
    }

    private static String toJsonLiteral(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return "null";
        }
        JsonPrimitive prim = element.getAsJsonPrimitive();
        if (prim.isString()) {
            return "\"" + escapeString(prim.getAsString()) + "\"";
        }
        if (prim.isBoolean()) {
            return prim.getAsBoolean() ? "true" : "false";
        }
        // Number
        Number num = prim.getAsNumber();
        if (num.doubleValue() == num.longValue()) {
            return String.valueOf(num.longValue());
        }
        return num.toString();
    }

    private static String escapeString(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
