package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 用 {@code emailauth.dns.timeout-millis} 为每次底层解析限时的包装解析器。
 * 超时立即返回 TIMEOUT，取消仍在后台运行的查询（中断工作线程），
 * 慢查询既不会拖住调用方，也不会在后台持续累积并发压力。
 */
public class TimedDnsResolver implements VersionedDnsResolver, AutoCloseable {
    private final DnsResolver delegate;
    private final VersionedDnsResolver versionedDelegate;
    private final AuthProperties properties;
    private final ExecutorService executor;

    public TimedDnsResolver(DnsResolver delegate, AuthProperties properties) {
        this.delegate = delegate;
        this.properties = properties;
        this.versionedDelegate = delegate instanceof VersionedDnsResolver versioned
                ? versioned : null;
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "dns-resolve");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public DnsResult resolve(String domain, RecordType type) {
        return runWithTimeout(() -> delegate.resolve(domain, type));
    }

    @Override
    public long version() {
        return versionedDelegate != null ? versionedDelegate.version() : 0L;
    }

    @Override
    public DnsResult resolveAt(String domain, RecordType type, long version) {
        if (versionedDelegate == null) {
            return resolve(domain, type);
        }
        return runWithTimeout(() -> versionedDelegate.resolveAt(domain, type, version));
    }

    private DnsResult runWithTimeout(java.util.function.Supplier<DnsResult> query) {
        long timeoutMillis = properties.getDns().getTimeoutMillis();
        Future<DnsResult> future = executor.submit(query::get);
        try {
            if (timeoutMillis <= 0) {
                return future.get();
            }
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            // mayInterruptIfRunning=true：后台慢查询立即收到中断，不再累积资源。
            future.cancel(true);
            return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException(cause);
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
