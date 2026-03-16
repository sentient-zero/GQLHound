package io.github.sentientzero.gqlhound.ui;

import io.github.sentientzero.gqlhound.intruder.IntruderSender;
import io.github.sentientzero.gqlhound.intruder.RepeaterSender;
import io.github.sentientzero.gqlhound.model.QueryStyle;
import io.github.sentientzero.gqlhound.model.VariableShape;
import io.github.sentientzero.gqlhound.store.OperationStore;

import javax.swing.*;
import java.awt.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds right-click popup menus for the operations and variables tables.
 * Each send option offers Original, as Inline, and as Parameterized styles.
 */
public class ContextMenuFactory {

    private final OperationStore store;
    private final IntruderSender intruderSender;
    private final RepeaterSender repeaterSender;

    public ContextMenuFactory(OperationStore store,
                              IntruderSender intruderSender,
                              RepeaterSender repeaterSender) {
        this.store = store;
        this.intruderSender = intruderSender;
        this.repeaterSender = repeaterSender;
    }

    /**
     * Build and show popup menu for a right-clicked operation row.
     */
    public void showOperationMenu(Component invoker, int x, int y,
                                  String opName) {
        List<VariableShape> shapes = store.getShapes(opName);
        if (shapes.isEmpty()) return;

        JPopupMenu menu = new JPopupMenu();

        // -- Send to Repeater
        JMenu repMenu = new JMenu("Send to Repeater");
        for (VariableShape shape : shapes) {
            JMenu shapeMenu = new JMenu(shape.getLabel());
            addStyleItems(shapeMenu, (style) ->
                    repeaterSender.send(shape, opName, style));
            repMenu.add(shapeMenu);
        }
        if (shapes.size() > 1) {
            repMenu.addSeparator();
            Set<String> allPaths = store.getAllVariablePaths(opName);
            JMenu mergeMenu = new JMenu(
                    "Merged (all %d observed vars)".formatted(allPaths.size()));
            addStyleItems(mergeMenu, (style) ->
                    repeaterSender.sendMerged(opName, style));
            repMenu.add(mergeMenu);
        }
        menu.add(repMenu);

        // -- Send to Intruder
        JMenu intMenu = new JMenu("Send to Intruder");
        for (VariableShape shape : shapes) {
            JMenu shapeMenu = new JMenu(shape.getLabel());
            addStyleItems(shapeMenu, (style) ->
                    intruderSender.sendShape(shape, opName, null, style));
            intMenu.add(shapeMenu);
        }

        // Merged option
        if (shapes.size() > 1) {
            intMenu.addSeparator();
            Set<String> allPaths = store.getAllVariablePaths(opName);
            JMenu mergeMenu = new JMenu(
                    "Merged (all %d observed vars)".formatted(allPaths.size()));
            addStyleItems(mergeMenu, (style) ->
                    intruderSender.sendMerged(opName, style));
            intMenu.add(mergeMenu);
        }
        menu.add(intMenu);

        menu.show(invoker, x, y);
    }

    /**
     * Build and show popup menu for selected variable rows.
     */
    public void showVariableMenu(Component invoker, int x, int y,
                                 String opName, Set<String> selectedPaths) {
        if (opName == null || selectedPaths.isEmpty()) return;

        VariableShape bestShape = store.getBestShapeForPaths(
                opName, selectedPaths);
        if (bestShape == null) return;

        Set<String> covered = new HashSet<>(selectedPaths);
        covered.retainAll(bestShape.getSignature());

        JPopupMenu menu = new JPopupMenu();

        // Intruder with selected vars
        String intLabel = "Send %d var(s) to Intruder"
                .formatted(selectedPaths.size());
        if (covered.size() < selectedPaths.size()) {
            intLabel += " (%d covered)".formatted(covered.size());
        }
        JMenu intMenu = new JMenu(intLabel);
        addStyleItems(intMenu, (style) ->
                intruderSender.sendShape(bestShape, opName,
                        selectedPaths, style));
        menu.add(intMenu);

        // Repeater
        JMenu repMenu = new JMenu(
                "Send to Repeater (%d var request)"
                        .formatted(covered.size()));
        addStyleItems(repMenu, (style) ->
                repeaterSender.send(bestShape, opName, style));
        menu.add(repMenu);

        menu.show(invoker, x, y);
    }

    /**
     * Add Original / as Inline / as Parameterized items to a menu.
     */
    private void addStyleItems(JMenu parent, StyleAction action) {
        for (QueryStyle style : QueryStyle.values()) {
            JMenuItem item = new JMenuItem(style.getLabel());
            item.addActionListener(e -> action.execute(style));
            parent.add(item);
        }
    }

    @FunctionalInterface
    private interface StyleAction {
        void execute(QueryStyle style);
    }
}
