package io.github.sentientzero.gqlhound.ui;

import io.github.sentientzero.gqlhound.store.ExportImporter;
import io.github.sentientzero.gqlhound.store.OperationStore;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.HashSet;
import java.util.Set;

/**
 * Main extension tab. Split pane with operations table (top) and
 * variables table (bottom), plus header buttons for Clear/Export/Import.
 */
public class GqlHoundTab {

    private final MontoyaApi api;
    private final OperationStore store;
    private final OperationTableModel opModel;
    private final VariableTableModel varModel;
    private final ContextMenuFactory contextMenu;

    private JPanel panel;
    private JTable opTable;
    private JTable varTable;
    private String selectedOpName;
    private JCheckBox captureProxy;
    private JCheckBox captureRepeater;

    public GqlHoundTab(MontoyaApi api, OperationStore store,
                       ContextMenuFactory contextMenu) {
        this.api = api;
        this.store = store;
        this.opModel = new OperationTableModel(store);
        this.varModel = new VariableTableModel();
        this.contextMenu = contextMenu;

        buildUi();
    }

    public Component getComponent() {
        return panel;
    }

    public OperationTableModel getOpModel() {
        return opModel;
    }

    public boolean isCaptureProxy() {
        return captureProxy.isSelected();
    }

    public boolean isCaptureRepeater() {
        return captureRepeater.isSelected();
    }

    private void buildUi() {
        panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel title = new JLabel("GQL Hound");
        title.setFont(new Font(Font.DIALOG, Font.BOLD, 14));
        header.add(title);

        header.add(Box.createHorizontalStrut(12));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> onClear());
        header.add(clearBtn);

        header.add(Box.createHorizontalStrut(8));
        JButton exportBtn = new JButton("Export");
        exportBtn.addActionListener(e -> onExport());
        header.add(exportBtn);

        header.add(Box.createHorizontalStrut(8));
        JButton importBtn = new JButton("Import");
        importBtn.addActionListener(e -> onImport());
        header.add(importBtn);

        header.add(Box.createHorizontalStrut(20));
        header.add(new JLabel("Capture from:"));
        header.add(Box.createHorizontalStrut(4));
        captureProxy = new JCheckBox("Proxy", true);
        header.add(captureProxy);
        header.add(Box.createHorizontalStrut(4));
        captureRepeater = new JCheckBox("Repeater", true);
        header.add(captureRepeater);

        panel.add(header, BorderLayout.NORTH);

        // Upper table: operations (sortable)
        opTable = new JTable(opModel);
        opTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        opTable.setAutoCreateRowSorter(true);

        TableColumnModel cm = opTable.getColumnModel();
        cm.getColumn(0).setMaxWidth(50);   // #
        cm.getColumn(2).setMaxWidth(100);  // Type
        cm.getColumn(3).setCellEditor(StatusCellEditor.create());
        cm.getColumn(3).setMaxWidth(110);  // Status
        cm.getColumn(4).setMaxWidth(80);   // Count
        cm.getColumn(5).setMaxWidth(90);   // Var Shapes

        opTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = opTable.getSelectedRow();
            if (viewRow < 0) {
                selectedOpName = null;
                varModel.load(null);
                return;
            }
            int modelRow = opTable.convertRowIndexToModel(viewRow);
            selectedOpName = opModel.getOperationName(modelRow);
            if (selectedOpName != null) {
                varModel.load(store.getVariableRows(selectedOpName));
            }
        });

        opTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handleOpPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handleOpPopup(e); }
        });

        JScrollPane opScroll = new JScrollPane(opTable);

        // Lower table: variables (sortable)
        JPanel varPanel = new JPanel(new BorderLayout(0, 4));
        JLabel varLabel = new JLabel("Variables for selected operation:");
        varLabel.setFont(new Font(Font.DIALOG, Font.BOLD, 12));
        varPanel.add(varLabel, BorderLayout.NORTH);

        varTable = new JTable(varModel);
        varTable.setAutoCreateRowSorter(true);
        varTable.getColumnModel().getColumn(2).setMaxWidth(100);

        varTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handleVarPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handleVarPopup(e); }
        });

        JScrollPane varScroll = new JScrollPane(varTable);
        varPanel.add(varScroll, BorderLayout.CENTER);

        // Split pane
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, opScroll, varPanel);
        split.setResizeWeight(0.5);
        split.setDividerLocation(250);
        panel.add(split, BorderLayout.CENTER);
    }

    private void handleOpPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int row = opTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        opTable.setRowSelectionInterval(row, row);
        int modelRow = opTable.convertRowIndexToModel(row);
        String opName = opModel.getOperationName(modelRow);
        if (opName != null) {
            contextMenu.showOperationMenu(opTable, e.getX(), e.getY(), opName);
        }
    }

    private void handleVarPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int[] selectedRows = varTable.getSelectedRows();
        if (selectedRows.length == 0 || selectedOpName == null) return;

        Set<String> paths = new HashSet<>();
        for (int viewRow : selectedRows) {
            int modelRow = varTable.convertRowIndexToModel(viewRow);
            String path = varModel.getPath(modelRow);
            if (path != null) paths.add(path);
        }

        if (!paths.isEmpty()) {
            contextMenu.showVariableMenu(
                    varTable, e.getX(), e.getY(), selectedOpName, paths);
        }
    }

    private void onClear() {
        store.clear();
        selectedOpName = null;
        varModel.load(null);
        opModel.fireTableDataChanged();
    }

    private void onExport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export GQL Hound Data");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        chooser.setSelectedFile(new File("gql_hound_export.json"));

        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        if (!file.getName().endsWith(".json")) {
            file = new File(file.getAbsolutePath() + ".json");
        }

        try {
            ExportImporter.exportToFile(store, file);
            int ops = store.getOperationCount();
            int shapes = 0;
            for (var shapeList : store.getRequestStoreSnapshot().values()) {
                shapes += shapeList.size();
            }
            api.logging().logToOutput(
                    "[GQL Hound] Exported %d operations, %d shapes to %s"
                            .formatted(ops, shapes, file.getAbsolutePath()));
        } catch (Exception ex) {
            api.logging().logToError(
                    "[GQL Hound] Export failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(panel,
                    "Export failed: " + ex.getMessage(),
                    "GQL Hound", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onImport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import GQL Hound Data");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));

        if (chooser.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        try {
            // Suppress per-row table events during bulk import
            store.setSuppressEvents(true);
            ExportImporter.ImportResult result =
                    ExportImporter.importFromFile(store, file);
            store.setSuppressEvents(false);

            // Single bulk refresh on EDT
            selectedOpName = null;
            varModel.load(null);
            SwingUtilities.invokeLater(() -> opModel.fireTableDataChanged());

            api.logging().logToOutput(
                    "[GQL Hound] Imported %d operations, %d shapes from %s"
                            .formatted(result.operationCount(),
                                    result.shapeCount(),
                                    file.getAbsolutePath()));
        } catch (Exception ex) {
            store.setSuppressEvents(false);
            api.logging().logToError(
                    "[GQL Hound] Import failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(panel,
                    "Import failed: " + ex.getMessage(),
                    "GQL Hound", JOptionPane.ERROR_MESSAGE);
        }
    }
}
