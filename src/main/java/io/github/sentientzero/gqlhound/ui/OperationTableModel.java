package io.github.sentientzero.gqlhound.ui;

import io.github.sentientzero.gqlhound.model.GraphQlOperation;
import io.github.sentientzero.gqlhound.model.OperationStatus;
import io.github.sentientzero.gqlhound.store.OperationStore;

import javax.swing.table.AbstractTableModel;

/**
 * Table model for the upper operations table.
 * Columns: #, Operation Name, Type, Status, Count, Var Shapes, Last Host
 */
public class OperationTableModel extends AbstractTableModel
        implements OperationStore.OperationStoreListener {

    private static final String[] COLUMNS = {
            "#", "Operation Name", "Type", "Status",
            "Count", "Var Shapes", "Last Host"
    };

    private final OperationStore store;

    public OperationTableModel(OperationStore store) {
        this.store = store;
        store.setListener(this);
    }

    @Override
    public int getRowCount() {
        return store.getOperationCount();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int col) {
        return COLUMNS[col];
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return switch (col) {
            case 0, 4, 5 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 3; // Status column
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col != 3) return;
        GraphQlOperation op = store.getOperation(row);
        if (op != null) {
            op.setStatus(OperationStatus.fromLabel(value.toString()));
            fireTableCellUpdated(row, col);
        }
    }

    @Override
    public Object getValueAt(int row, int col) {
        GraphQlOperation op = store.getOperation(row);
        if (op == null) return "";
        return switch (col) {
            case 0 -> row + 1;
            case 1 -> op.getName();
            case 2 -> op.getOperationType();
            case 3 -> op.getStatus().getLabel();
            case 4 -> op.getRequestCount();
            case 5 -> op.getShapeCount();
            case 6 -> op.getLastHost();
            default -> "";
        };
    }

    public String getOperationName(int row) {
        GraphQlOperation op = store.getOperation(row);
        return op != null ? op.getName() : null;
    }

    // OperationStoreListener callbacks (called from proxy thread)

    @Override
    public void operationAdded(int index) {
        javax.swing.SwingUtilities.invokeLater(
                () -> fireTableRowsInserted(index, index));
    }

    @Override
    public void operationUpdated(int index) {
        javax.swing.SwingUtilities.invokeLater(
                () -> fireTableRowsUpdated(index, index));
    }
}
