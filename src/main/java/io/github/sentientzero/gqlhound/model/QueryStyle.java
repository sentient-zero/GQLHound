package io.github.sentientzero.gqlhound.model;

/**
 * GraphQL variable passing style for send-to-tool operations.
 */
public enum QueryStyle {
    /** Send as-is, no conversion */
    ORIGINAL("Original"),
    /** Convert to inline arguments in the query string */
    INLINE("as Inline"),
    /** Convert to parameterized with $variables */
    PARAMETERIZED("as Parameterized");

    private final String label;

    QueryStyle(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
