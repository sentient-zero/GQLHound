package io.github.sentientzero.gqlhound.ui;

import io.github.sentientzero.gqlhound.extraction.OperationExtractor;
import com.google.gson.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Custom message editor tab that displays GraphQL requests in a
 * readable format: operation info, formatted query, and pretty-printed
 * variables in separate panes. Supports editing when in editable context.
 */
public class GqlRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private static final Pattern OP_PATTERN =
            Pattern.compile("(query|mutation|subscription)\\s+(\\w+)");

    private static final Gson PRETTY_GSON =
            new GsonBuilder().setPrettyPrinting().create();

    private final MontoyaApi api;
    private final boolean editable;

    // UI components
    private final JPanel panel;
    private final JLabel opInfoLabel;
    private final JTextArea queryArea;
    private final JTextArea variablesArea;

    // State
    private HttpRequestResponse currentReqRes;
    private String originalQuery;
    private String originalVariables;
    private boolean hasGraphql;

    public GqlRequestEditor(MontoyaApi api, EditorCreationContext context) {
        this.api = api;
        this.editable = context.editorMode() == EditorMode.DEFAULT;

        // Build UI
        panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // Operation info bar
        opInfoLabel = new JLabel(" ");
        opInfoLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 13));
        opInfoLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 6, 4));
        panel.add(opInfoLabel, BorderLayout.NORTH);

        // Query text area
        queryArea = new JTextArea();
        queryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        queryArea.setLineWrap(true);
        queryArea.setWrapStyleWord(true);
        queryArea.setEditable(editable);
        JScrollPane queryScroll = new JScrollPane(queryArea);
        queryScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Query",
                TitledBorder.LEFT, TitledBorder.TOP));

        // Variables text area
        variablesArea = new JTextArea();
        variablesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        variablesArea.setLineWrap(true);
        variablesArea.setWrapStyleWord(true);
        variablesArea.setEditable(editable);
        JScrollPane varsScroll = new JScrollPane(variablesArea);
        varsScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Variables",
                TitledBorder.LEFT, TitledBorder.TOP));

        // Split pane: query on top, variables on bottom
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, queryScroll, varsScroll);
        split.setResizeWeight(0.65);
        panel.add(split, BorderLayout.CENTER);
    }

    @Override
    public String caption() {
        return "GraphQL (GQL Hound)";
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        if (!editable || !hasGraphql) return false;
        return !queryArea.getText().equals(originalQuery)
                || !variablesArea.getText().equals(originalVariables);
    }

    /**
     * Determine if this tab should appear for the given request.
     * Checks for GraphQL indicators in the body.
     */
    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        try {
            String body = requestResponse.request().bodyToString();
            if (body == null || body.isBlank()) return false;

            // Quick checks before full parse
            body = body.strip();
            if (!body.startsWith("{") && !body.startsWith("[")) return false;

            // Check for GraphQL indicators
            JsonElement element = JsonParser.parseString(body);
            if (element.isJsonArray() && !element.getAsJsonArray().isEmpty()) {
                element = element.getAsJsonArray().get(0);
            }
            if (!element.isJsonObject()) return false;
            JsonObject obj = element.getAsJsonObject();
            return obj.has("query") || obj.has("operationName");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Called when Burp wants to display a request in this tab.
     * Parse the body and populate the formatted view.
     */
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentReqRes = requestResponse;
        this.hasGraphql = false;

        if (requestResponse == null || requestResponse.request() == null) {
            clearDisplay();
            return;
        }

        try {
            String body = requestResponse.request().bodyToString();
            if (body == null || body.isBlank()) {
                clearDisplay();
                return;
            }

            JsonElement element = JsonParser.parseString(body.strip());

            // Handle batched: show first operation
            JsonObject obj;
            boolean batched = false;
            int batchSize = 0;
            if (element.isJsonArray()) {
                JsonArray arr = element.getAsJsonArray();
                batchSize = arr.size();
                batched = true;
                if (arr.isEmpty() || !arr.get(0).isJsonObject()) {
                    clearDisplay();
                    return;
                }
                obj = arr.get(0).getAsJsonObject();
            } else if (element.isJsonObject()) {
                obj = element.getAsJsonObject();
            } else {
                clearDisplay();
                return;
            }

            if (!obj.has("query") && !obj.has("operationName")) {
                clearDisplay();
                return;
            }

            hasGraphql = true;

            // Extract query
            String query = obj.has("query") && obj.get("query").isJsonPrimitive()
                    ? obj.get("query").getAsString() : "";

            // Extract operation info
            String opName = obj.has("operationName")
                    && !obj.get("operationName").isJsonNull()
                    ? obj.get("operationName").getAsString() : null;
            String opType = "query";
            Matcher m = OP_PATTERN.matcher(query);
            if (m.find()) {
                opType = m.group(1);
                if (opName == null || opName.isEmpty()) {
                    opName = m.group(2);
                }
            }

            // Build info label (finalized after variable extraction below)
            StringBuilder info = new StringBuilder();
            info.append(opType.toUpperCase());
            if (opName != null && !opName.isEmpty()) {
                info.append("  ").append(opName);
            }
            if (batched) {
                info.append("    [batched: %d operations]".formatted(batchSize));
            }

            // Format query with basic indentation
            String formattedQuery = formatQuery(query);
            queryArea.setText(formattedQuery);
            queryArea.setCaretPosition(0);
            originalQuery = formattedQuery;

            // Format variables
            String formattedVars = "";
            boolean hasVarsObj = false;
            boolean hasInlineVars = false;

            if (obj.has("variables") && !obj.get("variables").isJsonNull()) {
                JsonElement varEl = obj.get("variables");
                if (varEl.isJsonObject()) {
                    formattedVars = PRETTY_GSON.toJson(varEl);
                    hasVarsObj = true;
                } else if (varEl.isJsonPrimitive()
                        && varEl.getAsJsonPrimitive().isString()) {
                    try {
                        JsonElement parsed = JsonParser.parseString(
                                varEl.getAsString());
                        formattedVars = PRETTY_GSON.toJson(parsed);
                        hasVarsObj = true;
                    } catch (JsonSyntaxException e) {
                        formattedVars = varEl.getAsString();
                    }
                }
            }

            // If no variables object, extract inline arguments from query
            if (formattedVars.isEmpty() && !query.isEmpty()) {
                JsonObject inlineVars =
                        OperationExtractor.extractInlineVariables(query);
                if (inlineVars != null && !inlineVars.isEmpty()) {
                    formattedVars = PRETTY_GSON.toJson(inlineVars)
                            + "\n\n// Extracted from inline arguments";
                    hasInlineVars = true;
                }
            }

            if (formattedVars.isEmpty()) {
                formattedVars = "(no variables detected)";
            }

            // Add style indicator to info label
            if (hasVarsObj) {
                info.append("    [parameterized]");
            } else if (hasInlineVars) {
                info.append("    [inline]");
            }
            opInfoLabel.setText(info.toString());
            variablesArea.setText(formattedVars);
            variablesArea.setCaretPosition(0);
            originalVariables = formattedVars;

        } catch (Exception e) {
            clearDisplay();
        }
    }

    /**
     * Called when Burp needs the (potentially modified) request back.
     * Reconstructs the JSON body from the editor fields.
     */
    @Override
    public HttpRequest getRequest() {
        if (currentReqRes == null || !hasGraphql || !isModified()) {
            return currentReqRes != null ? currentReqRes.request() : null;
        }

        try {
            HttpRequest original = currentReqRes.request();
            String body = original.bodyToString();
            JsonElement element = JsonParser.parseString(body.strip());

            JsonObject obj;
            boolean wasBatched = false;
            JsonArray batchArr = null;
            if (element.isJsonArray()) {
                batchArr = element.getAsJsonArray();
                wasBatched = true;
                obj = batchArr.get(0).getAsJsonObject();
            } else {
                obj = element.getAsJsonObject();
            }

            // Update query - collapse the formatted query back to single line
            String editedQuery = queryArea.getText().strip();
            obj.addProperty("query", editedQuery);

            // Update variables
            String editedVars = variablesArea.getText().strip();
            if (!editedVars.isEmpty()
                    && !editedVars.startsWith("(none")) {
                try {
                    JsonElement parsedVars = JsonParser.parseString(editedVars);
                    obj.add("variables", parsedVars);
                } catch (JsonSyntaxException e) {
                    // Keep original if parse fails
                }
            }

            String newBody;
            if (wasBatched) {
                batchArr.set(0, obj);
                newBody = PRETTY_GSON.toJson(batchArr);
            } else {
                newBody = PRETTY_GSON.toJson(obj);
            }

            return original.withBody(newBody);

        } catch (Exception e) {
            return currentReqRes.request();
        }
    }

    private void clearDisplay() {
        opInfoLabel.setText(" ");
        queryArea.setText("");
        variablesArea.setText("");
        originalQuery = "";
        originalVariables = "";
        hasGraphql = false;
    }

    /**
     * Basic GraphQL query formatter. Adds newlines and indentation
     * based on brace/paren nesting depth.
     */
    private static String formatQuery(String query) {
        if (query == null || query.isBlank()) return "";

        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        char prev = 0;

        for (int i = 0; i < query.length(); i++) {
            char c = query.charAt(i);

            if (c == '"' && prev != '\\') {
                inString = !inString;
                sb.append(c);
            } else if (inString) {
                sb.append(c);
            } else if (c == '{') {
                indent++;
                sb.append(" {\n");
                appendIndent(sb, indent);
            } else if (c == '}') {
                indent = Math.max(0, indent - 1);
                sb.append('\n');
                appendIndent(sb, indent);
                sb.append('}');
            } else if (c == '(') {
                sb.append('(');
            } else if (c == ')') {
                sb.append(')');
            } else if (c == '\n' || c == '\r') {
                // Skip existing newlines, we control formatting
            } else if (c == ' ' || c == '\t') {
                // Collapse whitespace
                if (sb.length() > 0
                        && sb.charAt(sb.length() - 1) != ' '
                        && sb.charAt(sb.length() - 1) != '\n') {
                    sb.append(' ');
                }
            } else {
                sb.append(c);
            }
            prev = c;
        }

        return sb.toString().strip();
    }

    private static void appendIndent(StringBuilder sb, int level) {
        sb.append("  ".repeat(level));
    }
}
