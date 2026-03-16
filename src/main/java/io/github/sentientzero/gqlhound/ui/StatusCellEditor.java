package io.github.sentientzero.gqlhound.ui;

import io.github.sentientzero.gqlhound.model.OperationStatus;

import javax.swing.*;

/**
 * Provides a JComboBox cell editor for the Status column in the operations table.
 */
public final class StatusCellEditor {

    private StatusCellEditor() {}

    public static DefaultCellEditor create() {
        String[] labels = new String[OperationStatus.values().length];
        for (int i = 0; i < labels.length; i++) {
            labels[i] = OperationStatus.values()[i].getLabel();
        }
        JComboBox<String> combo = new JComboBox<>(labels);
        return new DefaultCellEditor(combo);
    }
}
