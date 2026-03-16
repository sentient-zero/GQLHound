package io.github.sentientzero.gqlhound.model;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents a unique GraphQL operation observed in proxy traffic.
 * Thread-safe via atomics for fields updated from the proxy listener.
 */
public class GraphQlOperation {

    private final String name;
    private final String operationType; // query, mutation, subscription
    private final AtomicReference<OperationStatus> status;
    private final AtomicInteger requestCount;
    private final AtomicInteger shapeCount;
    private final AtomicReference<String> lastHost;

    public GraphQlOperation(String name, String operationType, String host) {
        this.name = name;
        this.operationType = operationType;
        this.status = new AtomicReference<>(OperationStatus.NEW);
        this.requestCount = new AtomicInteger(1);
        this.shapeCount = new AtomicInteger(0);
        this.lastHost = new AtomicReference<>(host);
    }

    public String getName() {
        return name;
    }

    public String getOperationType() {
        return operationType;
    }

    public OperationStatus getStatus() {
        return status.get();
    }

    public void setStatus(OperationStatus status) {
        this.status.set(status);
    }

    public int getRequestCount() {
        return requestCount.get();
    }

    public int incrementRequestCount() {
        return requestCount.incrementAndGet();
    }

    public void setRequestCount(int count) {
        requestCount.set(count);
    }

    public int getShapeCount() {
        return shapeCount.get();
    }

    public void setShapeCount(int count) {
        shapeCount.set(count);
    }

    public String getLastHost() {
        return lastHost.get();
    }

    public void setLastHost(String host) {
        lastHost.set(host);
    }
}
