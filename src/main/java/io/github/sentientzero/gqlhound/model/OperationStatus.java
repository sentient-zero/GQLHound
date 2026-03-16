package io.github.sentientzero.gqlhound.model;

public enum OperationStatus {
    NEW("New"),
    IN_PROGRESS("In Progress"),
    POSTPONED("Postponed"),
    DONE("Done"),
    IGNORED("Ignored");

    private final String label;

    OperationStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public static OperationStatus fromLabel(String label) {
        for (OperationStatus s : values()) {
            if (s.label.equalsIgnoreCase(label)) {
                return s;
            }
        }
        return NEW;
    }

    @Override
    public String toString() {
        return label;
    }
}
