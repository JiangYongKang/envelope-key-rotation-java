package com.github.highcumontoa.envelopekeyrotationjava.audit;

import java.util.ArrayList;
import java.util.List;

/**
 * 线程安全的进程内审计记录存储。
 * 仅保存元数据（操作类型、调用方、版本、结果、原因），
 * 任何调用方都不得在此放入明文密钥材料或明文数据。
 */
public class InMemoryAuditLog implements AuditLog {

    private final Object lock = new Object();
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void record(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("audit event is required");
        }
        synchronized (lock) {
            events.add(event);
        }
    }

    @Override
    public List<AuditEvent> events() {
        synchronized (lock) {
            return List.copyOf(events);
        }
    }
}
