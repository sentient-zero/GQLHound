package io.github.sentientzero.gqlhound.model;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents a unique combination of operation name + variable key set.
 * Stores the most recent original request for replay to Intruder/Repeater.
 */
public class VariableShape {

    private final Set<String> signature; // frozenset of variable paths
    private final List<String> sortedKeys;
    private final AtomicInteger count;
    private final AtomicReference<HttpRequest> storedRequest;
    private final AtomicReference<HttpService> storedService;

    public VariableShape(Set<String> signature, List<String> sortedKeys,
                         HttpRequest request, HttpService service) {
        this.signature = Collections.unmodifiableSet(signature);
        this.sortedKeys = Collections.unmodifiableList(sortedKeys);
        this.count = new AtomicInteger(1);
        this.storedRequest = new AtomicReference<>(request);
        this.storedService = new AtomicReference<>(service);
    }

    public Set<String> getSignature() {
        return signature;
    }

    public List<String> getSortedKeys() {
        return sortedKeys;
    }

    public int getCount() {
        return count.get();
    }

    public int incrementCount() {
        return count.incrementAndGet();
    }

    public void setCount(int c) {
        count.set(c);
    }

    public HttpRequest getStoredRequest() {
        return storedRequest.get();
    }

    public HttpService getStoredService() {
        return storedService.get();
    }

    public void updateRequest(HttpRequest request, HttpService service) {
        storedRequest.set(request);
        storedService.set(service);
    }

    public String getLabel() {
        int n = sortedKeys.size();
        if (n == 0) {
            return String.format("no variables (%dx)", count.get());
        }
        StringBuilder sb = new StringBuilder();
        int preview = Math.min(n, 4);
        for (int i = 0; i < preview; i++) {
            if (i > 0) sb.append(", ");
            sb.append(sortedKeys.get(i));
        }
        if (n > 4) {
            sb.append(String.format(", ... +%d more", n - 4));
        }
        return String.format("%d vars: %s (%dx)", n, sb, count.get());
    }
}
