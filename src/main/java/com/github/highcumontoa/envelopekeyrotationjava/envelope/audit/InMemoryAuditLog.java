package com.github.highcumontoa.envelopekeyrotationjava.envelope.audit;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditEvent;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 本地内存审计留痕：事件保存在 {@link CopyOnWriteArrayList}，并发安全；
 * 同时以 INFO 级别输出脱敏日志。
 *
 * 红线：本类只接收元数据（caller / action / version / reason / 长度类 detail），
 * 调用方绝不应把密钥材料或明文数据传入 detail。
 */
public class InMemoryAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditLog.class);

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void record(Caller caller, AuditAction action, boolean success,
                       Integer keyVersion, String reason, String detail) {
        AuditEvent event = new AuditEvent(
                Instant.now(),
                caller == null ? "anonymous" : caller.id(),
                action,
                success,
                keyVersion,
                reason,
                detail);
        events.add(event);
        // 留痕日志：仅元数据，保证可追溯且不含密钥材料
        log.info("[AUDIT] at={} caller={} action={} success={} keyVersion={} reason={} detail={}",
                event.timestamp(), event.caller(), event.action(), event.success(),
                event.keyVersion(), event.reason(), event.detail());
    }

    @Override
    public List<AuditEvent> events() {
        return List.copyOf(events);
    }

    /** 便于服务层统一记录失败事件。 */
    public static String reasonOf(EnvelopeException e) {
        RejectReason reason = e.getReason();
        return reason == null ? "UNKNOWN" : reason.name();
    }
}
