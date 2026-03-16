package io.github.sentientzero.gqlhound;

import io.github.sentientzero.gqlhound.extraction.OperationExtractor;
import io.github.sentientzero.gqlhound.intruder.IntruderSender;
import io.github.sentientzero.gqlhound.intruder.RepeaterSender;
import io.github.sentientzero.gqlhound.model.ExtractedOperation;
import io.github.sentientzero.gqlhound.store.OperationStore;
import io.github.sentientzero.gqlhound.ui.ContextMenuFactory;
import io.github.sentientzero.gqlhound.ui.GqlHoundTab;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

/**
 * GQL Hound - Burp Suite extension for passive GraphQL operation discovery,
 * triage, and fuzzing.
 *
 * Montoya API entry point. Registers:
 * - HTTP handler for proxy traffic monitoring
 * - Suite tab for the extension UI
 * - Unload handler for clean shutdown
 */
public class GqlHound implements BurpExtension {

    private static final String EXTENSION_NAME = "GQL Hound";

    private MontoyaApi api;
    private OperationStore store;
    private GqlHoundTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.store = new OperationStore();

        api.extension().setName(EXTENSION_NAME);

        // Build senders
        IntruderSender intruderSender = new IntruderSender(api, store);
        RepeaterSender repeaterSender = new RepeaterSender(api, store);
        ContextMenuFactory contextMenu = new ContextMenuFactory(
                store, intruderSender, repeaterSender);

        // Build UI
        tab = new GqlHoundTab(api, store, contextMenu);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab.getComponent());

        // Register proxy request handler
        api.http().registerHttpHandler(new GqlHttpHandler());

        // Register unload handler (bApp Store requirement)
        api.extension().registerUnloadingHandler(() -> {
            store.clear();
            api.logging().logToOutput("[GQL Hound] Extension unloaded.");
        });

        api.logging().logToOutput("[GQL Hound] v2.0.1 loaded.");
    }

    /**
     * HTTP handler that processes proxy requests to extract GraphQL operations.
     * Avoids slow operations per bApp Store requirements.
     */
    private class GqlHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(
                HttpRequestToBeSent request) {

            // Only process traffic from enabled capture sources
            boolean fromProxy = request.toolSource().isFromTool(
                    burp.api.montoya.core.ToolType.PROXY);
            boolean fromRepeater = request.toolSource().isFromTool(
                    burp.api.montoya.core.ToolType.REPEATER);

            if (!(fromProxy && tab.isCaptureProxy())
                    && !(fromRepeater && tab.isCaptureRepeater())) {
                return RequestToBeSentAction.continueWith(request);
            }

            try {
                String body = request.bodyToString();
                if (body == null || body.isBlank()) {
                    return RequestToBeSentAction.continueWith(request);
                }

                List<ExtractedOperation> operations =
                        OperationExtractor.extract(body);
                if (operations.isEmpty()) {
                    return RequestToBeSentAction.continueWith(request);
                }

                String host = request.httpService().host();
                boolean isBatched = operations.size() > 1;
                long mutationCount = operations.stream()
                        .filter(op -> "mutation".equals(op.operationType()))
                        .count();
                boolean hasBatchedMutations = isBatched && mutationCount > 1;

                // Build annotation tags
                Annotations annotations = request.annotations();
                String existingComment = annotations.notes() != null
                        ? annotations.notes() : "";
                StringBuilder newTags = new StringBuilder();
                boolean anyNew = false;

                for (ExtractedOperation op : operations) {
                    String tag = "GQL:" + op.name();
                    if (!existingComment.contains(tag)) {
                        if (newTags.length() > 0) newTags.append(" | ");
                        newTags.append(tag);
                    }

                    // Record variables
                    if (op.variables() != null) {
                        api.logging().logToOutput(
                                "[GQL Hound] %s: %d variable keys detected"
                                        .formatted(op.name(),
                                                op.variables().size()));
                    } else {
                        api.logging().logToOutput(
                                "[GQL Hound] %s: no variables object found"
                                        .formatted(op.name()));
                    }
                    store.recordVariables(op.name(), op.variables());

                    // Store original request by variable shape
                    store.storeRequest(op.name(), op.variables(),
                            request, request.httpService());
                    store.updateShapeCount(op.name());

                    // Track operation
                    boolean isNew = store.trackOperation(
                            op.name(), op.operationType(), host);
                    if (isNew) {
                        anyNew = true;
                        api.logging().logToOutput(
                                "[GQL Hound] New %s: %s (%s)"
                                        .formatted(op.operationType(),
                                                op.name(), host));
                    }
                }

                // Build updated comment
                String comment;
                if (newTags.length() > 0) {
                    comment = existingComment.isEmpty()
                            ? newTags.toString()
                            : existingComment + " | " + newTags;
                } else {
                    comment = existingComment;
                }

                // Determine highlight color
                HighlightColor highlight = annotations.highlightColor();
                if (hasBatchedMutations) {
                    highlight = HighlightColor.ORANGE;
                    api.logging().logToOutput(
                            "[GQL Hound] Batched mutations (%d): %s (%s)"
                                    .formatted(mutationCount,
                                            String.join(", ",
                                                    operations.stream()
                                                            .filter(op -> "mutation"
                                                                    .equals(op.operationType()))
                                                            .map(ExtractedOperation::name)
                                                            .toList()),
                                            host));
                } else if (anyNew) {
                    highlight = HighlightColor.CYAN;
                }

                Annotations updated = Annotations.annotations(comment, highlight);
                return RequestToBeSentAction.continueWith(request, updated);

            } catch (Exception e) {
                api.logging().logToError(
                        "[GQL Hound] Error processing request: " + e.getMessage());
                return RequestToBeSentAction.continueWith(request);
            }
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(
                HttpResponseReceived response) {
            return ResponseReceivedAction.continueWith(response);
        }
    }
}
