package io.github.sentientzero.gqlhound.model;

import com.google.gson.JsonObject;

/**
 * Result of extracting a single GraphQL operation from a request body.
 */
public record ExtractedOperation(
        String name,
        String operationType,
        JsonObject variables
) {
}
