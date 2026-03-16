package io.github.sentientzero.gqlhound.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

/**
 * Provides a "GraphQL (GQL Hound)" tab in Burp's HTTP message editor
 * for any request containing a GraphQL body.
 */
public class GqlRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;

    public GqlRequestEditorProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(
            EditorCreationContext creationContext) {
        return new GqlRequestEditor(api, creationContext);
    }
}
