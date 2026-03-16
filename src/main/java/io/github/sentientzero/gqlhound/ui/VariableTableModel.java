package io.github.sentientzero.gqlhound.ui;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for the lower variables table.
 * Columns: Variable Path, Sample Values, Times Seen
 */
public class VariableTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "Variable Path", "Sample Values", "Times Seen"
    };

    private List<Object[]> rows = new ArrayList<>();

    @Override
    public int getRowCount() {
        return rows.size();
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
        return col == 2 ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int row, int col) {
        if (row >= rows.size()) return "";
        return rows.get(row)[col];
    }

    public String getPath(int row) {
        if (row >= 0 && row < rows.size()) {
            return (String) rows.get(row)[0];
        }
        return null;
    }

    public void load(List<Object[]> newRows) {
        this.rows = newRows != null ? newRows : new ArrayList<>();
        fireTableDataChanged();
    }
}
