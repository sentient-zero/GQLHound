package io.github.sentientzero.gqlhound.extraction;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Flattens nested JSON structures into dot-notation paths with string values.
 * Example: {"input": {"user": {"name": "alice"}}} -> [("input.user.name", "alice")]
 */
public final class VariableFlattener {

    private VariableFlattener() {}

    /**
     * Flatten a JsonObject into a list of (path, value_string) pairs.
     */
    public static List<Map.Entry<String, String>> flatten(JsonObject obj) {
        List<Map.Entry<String, String>> results = new ArrayList<>();
        flattenElement(obj, "", results);
        return results;
    }

    /**
     * Return just the paths (no values) from a JsonObject.
     */
    public static List<String> flattenKeys(JsonObject obj) {
        List<Map.Entry<String, String>> flat = flatten(obj);
        return flat.stream().map(Map.Entry::getKey).toList();
    }

    private static void flattenElement(JsonElement element, String prefix,
                                       List<Map.Entry<String, String>> results) {
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = prefix.isEmpty()
                        ? entry.getKey()
                        : prefix + "." + entry.getKey();
                JsonElement val = entry.getValue();
                if (val.isJsonObject() || val.isJsonArray()) {
                    flattenElement(val, key, results);
                } else {
                    results.add(new AbstractMap.SimpleImmutableEntry<>(
                            key, valueToString(val)));
                }
            }
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                String key = prefix + "[" + i + "]";
                JsonElement val = arr.get(i);
                if (val.isJsonObject() || val.isJsonArray()) {
                    flattenElement(val, key, results);
                } else {
                    results.add(new AbstractMap.SimpleImmutableEntry<>(
                            key, valueToString(val)));
                }
            }
        }
    }

    private static String valueToString(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return "null";
        }
        if (element.isJsonPrimitive()) {
            JsonPrimitive prim = element.getAsJsonPrimitive();
            String s;
            if (prim.isString()) {
                s = prim.getAsString();
            } else if (prim.isBoolean()) {
                s = String.valueOf(prim.getAsBoolean());
            } else {
                s = prim.getAsNumber().toString();
            }
            if (s.length() > 60) {
                return s.substring(0, 57) + "...";
            }
            return s;
        }
        return element.toString();
    }
}
