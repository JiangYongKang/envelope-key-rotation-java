package com.github.highcumontoa.envelopekeyrotationjava.envelope.audit;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditEvent;

import java.util.List;

/**
 * 敏感操作留痕。实现必须保证记录中不含明文密钥材料。
 */
public interface AuditLog {
    void record(Caller caller, AuditAction action, boolean success,
                Integer keyVersion, String reason, String detail);
    List<AuditEvent> events();
}
