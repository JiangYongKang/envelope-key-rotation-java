package com.github.highcumontoa.envelopekeyrotationjava.audit;

import java.time.Instant;

/**
 * 审计记录。只保存版本号、结果与拒绝原因等元数据，
 * 严禁持有任何明文密钥材料或明文数据。
 */
public record AuditEvent(Instant time,
                         AuditAction action,
                         String callerId,
                         String keyVersion,
                         boolean success,
                         String reason) {
}
