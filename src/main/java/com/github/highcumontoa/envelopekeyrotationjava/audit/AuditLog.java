package com.github.highcumontoa.envelopekeyrotationjava.audit;

import java.util.List;

/**
 * 审计记录存储。
 */
public interface AuditLog {

    /**
     * 追加一条审计记录（实现需保证线程安全）。
     */
    void record(AuditEvent event);

    /**
     * 返回全部审计记录的只读快照，按时间先后排列。
     */
    List<AuditEvent> events();
}
